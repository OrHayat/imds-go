package ibmimds

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// makeJWT returns a token string with the given payload. The header
// and signature are static placeholders since verify.go does not
// check the signature — IBM's verification model is "trust the TLS
// channel to iam.cloud.ibm.com".
func makeJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	p := base64.RawURLEncoding.EncodeToString(body)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	return header + "." + p + "." + sig
}

func TestVerifyIdentityToken(t *testing.T) {
	iat := time.Now().Unix()
	exp := iat + 3600
	iamJWT := makeJWT(t, map[string]any{
		"iam_id":   "crn-crn:v1:bluemix:public:iam-identity::a/acc123::profile:Profile-abc",
		"sub":      "Profile-abc",
		"sub_type": "Profile",
		"iss":      "https://iam.cloud.ibm.com/identity",
		"iat":      iat,
		"exp":      exp,
		"account":  map[string]any{"bss": "acc123"},
	})

	var gotGrant, gotCRToken, gotProfile string
	var gotContentType, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		gotContentType = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		form, err := parseForm(string(body))
		if err != nil {
			t.Fatalf("parse request form: %v", err)
		}
		gotGrant = form["grant_type"]
		gotCRToken = form["cr_token"]
		gotProfile = form["profile_id"]

		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": iamJWT,
			"token_type":   "Bearer",
			"scope":        "ibm openid",
		})
	}))
	defer srv.Close()

	claims, err := VerifyIdentityTokenWithIAMURL(
		t.Context(),
		"fake.cr.token",
		"Profile-abc",
		srv.URL,
		srv.Client(),
	)
	if err != nil {
		t.Fatalf("VerifyIdentityTokenWithIAMURL: %v", err)
	}

	if gotGrant != crTokenGrant {
		t.Errorf("grant_type = %q, want %q", gotGrant, crTokenGrant)
	}
	if gotCRToken != "fake.cr.token" {
		t.Errorf("cr_token = %q", gotCRToken)
	}
	if gotProfile != "Profile-abc" {
		t.Errorf("profile_id = %q", gotProfile)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", gotContentType)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q", gotAccept)
	}

	if claims.IAMID != "crn-crn:v1:bluemix:public:iam-identity::a/acc123::profile:Profile-abc" {
		t.Errorf("IAMID = %q", claims.IAMID)
	}
	if claims.Subject != "Profile-abc" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.SubjectType != "Profile" {
		t.Errorf("SubjectType = %q", claims.SubjectType)
	}
	if claims.Issuer != "https://iam.cloud.ibm.com/identity" {
		t.Errorf("Issuer = %q", claims.Issuer)
	}
	if claims.AccountID != "acc123" {
		t.Errorf("AccountID = %q", claims.AccountID)
	}
	if claims.Scope != "ibm openid" {
		t.Errorf("Scope = %q", claims.Scope)
	}
	if claims.IssuedAt.Unix() != iat {
		t.Errorf("IssuedAt = %v, want %v", claims.IssuedAt, time.Unix(iat, 0))
	}
	if claims.Expires.Unix() != exp {
		t.Errorf("Expires = %v, want %v", claims.Expires, time.Unix(exp, 0))
	}
	if claims.IAMToken != iamJWT {
		t.Errorf("IAMToken not surfaced")
	}
}

func TestVerifyIdentityTokenOmitsProfileWhenEmpty(t *testing.T) {
	var gotProfileIDSet bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		form, err := parseForm(string(body))
		if err != nil {
			t.Fatalf("parse request form: %v", err)
		}
		_, gotProfileIDSet = form["profile_id"]
		iat := time.Now().Unix()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": makeJWT(t, map[string]any{"iss": "x", "iat": iat, "exp": iat + 3600}),
		})
	}))
	defer srv.Close()

	_, err := VerifyIdentityTokenWithIAMURL(t.Context(), "cr", "", srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if gotProfileIDSet {
		t.Error("profile_id should be omitted when caller passes empty string")
	}
}

func TestVerifyIdentityTokenEmptyCRTokenRejected(t *testing.T) {
	_, err := VerifyIdentityTokenWithIAMURL(t.Context(), "", "Profile-x", "", nil)
	if err == nil {
		t.Fatal("expected error for empty crToken")
	}
}

func TestVerifyIdentityTokenWithIAMURLRejectsBadURL(t *testing.T) {
	cases := []struct {
		name   string
		iamURL string
	}{
		{"no-scheme", "iam.cloud.ibm.com/identity/token"},
		{"ftp-scheme", "ftp://iam.cloud.ibm.com/identity/token"},
		{"file-scheme", "file:///etc/passwd"},
		{"no-host", "https://"},
		// Port-only URL: url.Parse leaves u.Host == ":1234" (non-empty)
		// but u.Hostname() == "" — the check must use Hostname().
		{"port-only-no-hostname", "https://:1234/identity/token"},
		{"remote-http", "http://iam.cloud.ibm.com/identity/token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyIdentityTokenWithIAMURL(t.Context(), "cr", "", tc.iamURL, nil)
			if err == nil {
				t.Fatalf("expected rejection for iamURL=%q", tc.iamURL)
			}
		})
	}
}

func TestVerifyIdentityTokenWithIAMURLAllowsLoopbackHTTP(t *testing.T) {
	// Plain http:// URLs targeting a loopback address are allowed
	// for tests. The actual request will fail because the target
	// isn't a real IAM server, but the URL-shape check must not
	// reject loopback http up front.
	cases := []string{
		"http://127.0.0.1:12345/identity/token",
		"http://localhost:12345/identity/token",
		"http://[::1]:12345/identity/token",
	}
	for _, iamURL := range cases {
		t.Run(iamURL, func(t *testing.T) {
			_, err := VerifyIdentityTokenWithIAMURL(t.Context(), "cr", "", iamURL, nil)
			if err == nil {
				t.Fatal("expected downstream error from unreachable server, got nil")
			}
			if strings.Contains(err.Error(), "must use https unless host is loopback") {
				t.Errorf("loopback URL rejected by http-scheme check: %v", err)
			}
		})
	}
}

func TestVerifyIdentityTokenIAMFailureSurfacesStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "token revoked", http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := VerifyIdentityTokenWithIAMURL(t.Context(), "cr", "", srv.URL, srv.Client())
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention status code, got %v", err)
	}
}

func TestVerifyIdentityTokenEmptyIAMAccessTokenRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": ""})
	}))
	defer srv.Close()

	_, err := VerifyIdentityTokenWithIAMURL(t.Context(), "cr", "", srv.URL, srv.Client())
	if err == nil {
		t.Fatal("expected error on empty access_token")
	}
}

func TestVerifyIdentityTokenRejectsMissingIat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Omit iat entirely; exp present.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": makeJWT(t, map[string]any{"iss": "x", "exp": time.Now().Unix() + 3600}),
		})
	}))
	defer srv.Close()
	_, err := VerifyIdentityTokenWithIAMURL(t.Context(), "cr", "", srv.URL, srv.Client())
	if err == nil {
		t.Fatal("expected rejection for missing iat")
	}
	if !strings.Contains(err.Error(), "iat") {
		t.Errorf("err = %v, want iat-missing rejection", err)
	}
}

func TestVerifyIdentityTokenRejectsMissingExp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": makeJWT(t, map[string]any{"iss": "x", "iat": time.Now().Unix()}),
		})
	}))
	defer srv.Close()
	_, err := VerifyIdentityTokenWithIAMURL(t.Context(), "cr", "", srv.URL, srv.Client())
	if err == nil {
		t.Fatal("expected rejection for missing exp")
	}
	if !strings.Contains(err.Error(), "exp") {
		t.Errorf("err = %v, want exp-missing rejection", err)
	}
}

func TestVerifyIdentityTokenRejectsExpBeforeIat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iat := time.Now().Unix()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": makeJWT(t, map[string]any{"iss": "x", "iat": iat, "exp": iat - 1}),
		})
	}))
	defer srv.Close()
	_, err := VerifyIdentityTokenWithIAMURL(t.Context(), "cr", "", srv.URL, srv.Client())
	if err == nil {
		t.Fatal("expected rejection for exp <= iat")
	}
	if !strings.Contains(err.Error(), "not after iat") {
		t.Errorf("err = %v, want exp-not-after-iat rejection", err)
	}
}

func TestVerifyIdentityTokenMalformedJWT(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "not.a.jwt.at.all",
		})
	}))
	defer srv.Close()

	_, err := VerifyIdentityTokenWithIAMURL(t.Context(), "cr", "", srv.URL, srv.Client())
	if err == nil {
		t.Fatal("expected error on malformed JWT")
	}
}

func TestVerifyIdentityTokenDefaultsIAMURL(t *testing.T) {
	// Does not hit the real iam.cloud.ibm.com — we pass a cancelled
	// context to force the HTTP call to fail quickly. What we're
	// asserting is that passing "" for iamURL does not panic and
	// that the error originates from the HTTP attempt, not from
	// URL construction.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := VerifyIdentityTokenWithIAMURL(ctx, "cr", "", "", nil)
	if err == nil {
		t.Fatal("expected error from cancelled ctx")
	}
	if !strings.Contains(err.Error(), "IAM exchange") && !strings.Contains(err.Error(), "build IAM request") {
		t.Errorf("error should come from HTTP layer, got: %v", err)
	}
}

// parseForm is a tiny URL-encoded form parser used by the tests to
// inspect the IAM exchange request body without dragging in
// net/url's ParseQuery (which would also be fine, just noisier).
func parseForm(s string) (map[string]string, error) {
	m := make(map[string]string)
	for _, pair := range strings.Split(s, "&") {
		if pair == "" {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("bad pair %q", pair)
		}
		k, err := decodeFormValue(kv[0])
		if err != nil {
			return nil, err
		}
		v, err := decodeFormValue(kv[1])
		if err != nil {
			return nil, err
		}
		m[k] = v
	}
	return m, nil
}

func decodeFormValue(s string) (string, error) {
	// Tests only use ASCII values without % escapes for the pieces
	// we care about (grant_type, cr_token, profile_id), except for
	// the ':' in crTokenGrant, which the stdlib form encoder turns
	// into %3A. Decode that small subset.
	return strings.NewReplacer("%3A", ":", "+", " ", "%2F", "/").Replace(s), nil
}
