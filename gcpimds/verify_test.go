package gcpimds

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// --- GetIdentityToken client-side tests ---

func TestGetIdentityTokenSendsAudienceAndFormat(t *testing.T) {
	var gotQuery url.Values
	var gotFlavor string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/identity" {
			http.NotFound(w, r)
			return
		}
		gotQuery = r.URL.Query()
		gotFlavor = r.Header.Get("Metadata-Flavor")
		_, _ = w.Write([]byte("  fake.jwt.value  \n"))
	}))
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tok, err := c.GetIdentityToken(context.Background(), "https://example.com",
		WithFormat(FormatFull),
		WithIncludeLicenses(),
	)
	if err != nil {
		t.Fatalf("GetIdentityToken: %v", err)
	}
	if tok != "fake.jwt.value" {
		t.Errorf("token = %q, want trimmed %q", tok, "fake.jwt.value")
	}
	if gotFlavor != "Google" {
		t.Errorf("Metadata-Flavor = %q, want Google", gotFlavor)
	}
	if got := gotQuery.Get("audience"); got != "https://example.com" {
		t.Errorf("audience = %q", got)
	}
	if got := gotQuery.Get("format"); got != "full" {
		t.Errorf("format = %q", got)
	}
	if got := gotQuery.Get("licenses"); got != "TRUE" {
		t.Errorf("licenses = %q", got)
	}
}

func TestGetIdentityTokenOmitsFormatWhenUnset(t *testing.T) {
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		_, _ = w.Write([]byte("tok"))
	}))
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.GetIdentityToken(context.Background(), "aud"); err != nil {
		t.Fatalf("GetIdentityToken: %v", err)
	}
	// When the caller omits WithFormat, GetIdentityToken does not set
	// the format query param at all — GCE applies its documented
	// default (standard) server-side.
	if _, ok := gotQuery["format"]; ok {
		t.Errorf("format should be absent when WithFormat omitted, got %q", gotQuery.Get("format"))
	}
	if _, ok := gotQuery["licenses"]; ok {
		t.Errorf("licenses should be absent, got %v", gotQuery["licenses"])
	}
}

func TestGetIdentityTokenRequiresAudience(t *testing.T) {
	c, err := New(WithBaseURL("http://127.0.0.1:1"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.GetIdentityToken(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "audience is required") {
		t.Errorf("err = %v, want audience required", err)
	}
}

func TestGetIdentityTokenLicensesRequiresFull(t *testing.T) {
	c, err := New(WithBaseURL("http://127.0.0.1:1"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.GetIdentityToken(context.Background(), "aud",
		WithFormat(FormatStandard),
		WithIncludeLicenses(),
	)
	if err == nil || !strings.Contains(err.Error(), "FormatFull") {
		t.Errorf("err = %v, want FormatFull required", err)
	}
}

func TestGetIdentityTokenRejectsUnknownFormat(t *testing.T) {
	c, err := New(WithBaseURL("http://127.0.0.1:1"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.GetIdentityToken(context.Background(), "aud",
		WithFormat(Format("bogus")),
	)
	if err == nil || !strings.Contains(err.Error(), "invalid format") {
		t.Errorf("err = %v, want invalid-format rejection", err)
	}
}

// --- VerifyIdentityToken tests ---

type testSigner struct {
	key *rsa.PrivateKey
	kid string
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa GenerateKey: %v", err)
	}
	return &testSigner{key: key, kid: "test-key-1"}
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// stripLeadingZeros returns b without any leading 0x00 bytes.
func stripLeadingZeros(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

func (s *testSigner) jwksJSON() string {
	n := stripLeadingZeros(s.key.N.Bytes())
	e := stripLeadingZeros(big.NewInt(int64(s.key.E)).Bytes())
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": s.kid,
				"alg": "RS256",
				"use": "sig",
				"n":   b64url(n),
				"e":   b64url(e),
			},
		},
	}
	buf, _ := json.Marshal(jwks)
	return string(buf)
}

// sign produces a JWT with the supplied payload claims signed by the
// test key. If overrideKid is non-empty, it is used as the JWT header
// kid instead of the signer's real kid (to simulate mismatches).
func (s *testSigner) sign(t *testing.T, payload map[string]any, overrideKid string) string {
	t.Helper()
	kid := s.kid
	if overrideKid != "" {
		kid = overrideKid
	}
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}
	hBytes, _ := json.Marshal(header)
	pBytes, _ := json.Marshal(payload)
	signing := b64url(hBytes) + "." + b64url(pBytes)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}
	return signing + "." + b64url(sig)
}

func basePayload(aud string, iat, exp time.Time) map[string]any {
	return map[string]any{
		"iss":            "https://accounts.google.com",
		"aud":            aud,
		"sub":            "1234567890",
		"email":          "svc@example.iam.gserviceaccount.com",
		"email_verified": true,
		"iat":            iat.Unix(),
		"exp":            exp.Unix(),
	}
}

// ceClaim fishes the google.compute_engine subclaim out of a JWT
// payload built by fullPayload, failing the test if the shape is
// unexpected. Used by tests that need to mutate individual CE fields
// (license_id, project_number, …) without tripping errcheck on
// single-value type assertions.
func ceClaim(t *testing.T, p map[string]any) map[string]any {
	t.Helper()
	google, ok := p["google"].(map[string]any)
	if !ok {
		t.Fatalf("payload missing google claim")
	}
	ce, ok := google["compute_engine"].(map[string]any)
	if !ok {
		t.Fatalf("payload missing google.compute_engine claim")
	}
	return ce
}

func fullPayload(aud string, iat, exp time.Time) map[string]any {
	p := basePayload(aud, iat, exp)
	p["google"] = map[string]any{
		"compute_engine": map[string]any{
			"instance_id":    "111222333",
			"instance_name":  "my-vm",
			"project_id":     "my-project",
			"project_number": float64(987654321),
			"zone":           "us-central1-a",
		},
	}
	return p
}

func newJWKSServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=3600")
		_, _ = fmt.Fprint(w, body)
	}))
}

func TestVerifyIdentityTokenPositiveStandard(t *testing.T) {
	s := newTestSigner(t)
	jwks := newJWKSServer(t, s.jwksJSON())
	defer jwks.Close()

	iat := time.Now().Add(-1 * time.Minute)
	exp := time.Now().Add(1 * time.Hour)
	tok := s.sign(t, basePayload("https://svc.example.com", iat, exp), "")

	claims, err := VerifyIdentityTokenWithCertsURL(context.Background(), tok, "https://svc.example.com", jwks.URL)
	if err != nil {
		t.Fatalf("VerifyIdentityTokenWithCertsURL: %v", err)
	}
	if claims.Audience != "https://svc.example.com" {
		t.Errorf("Audience = %q", claims.Audience)
	}
	if claims.Issuer != "https://accounts.google.com" {
		t.Errorf("Issuer = %q", claims.Issuer)
	}
	if claims.Subject != "1234567890" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.Email != "svc@example.iam.gserviceaccount.com" {
		t.Errorf("Email = %q", claims.Email)
	}
	if !claims.EmailVerified {
		t.Errorf("EmailVerified = false, want true")
	}
	if claims.InstanceID != "" || claims.Zone != "" {
		t.Errorf("expected empty compute_engine claims, got %+v", claims)
	}
}

func TestVerifyIdentityTokenEmailNotVerified(t *testing.T) {
	s := newTestSigner(t)
	jwks := newJWKSServer(t, s.jwksJSON())
	defer jwks.Close()

	iat := time.Now().Add(-1 * time.Minute)
	exp := time.Now().Add(1 * time.Hour)
	payload := basePayload("https://svc.example.com", iat, exp)
	payload["email_verified"] = false
	tok := s.sign(t, payload, "")

	claims, err := VerifyIdentityTokenWithCertsURL(context.Background(), tok, "https://svc.example.com", jwks.URL)
	if err != nil {
		t.Fatalf("VerifyIdentityTokenWithCertsURL: %v", err)
	}
	if claims.EmailVerified {
		t.Errorf("EmailVerified = true, want false")
	}
}

func TestVerifyIdentityTokenPositiveFull(t *testing.T) {
	s := newTestSigner(t)
	jwks := newJWKSServer(t, s.jwksJSON())
	defer jwks.Close()

	iat := time.Now().Add(-1 * time.Minute)
	exp := time.Now().Add(1 * time.Hour)
	tok := s.sign(t, fullPayload("https://svc.example.com", iat, exp), "")

	claims, err := VerifyIdentityTokenWithCertsURL(context.Background(), tok, "https://svc.example.com", jwks.URL)
	if err != nil {
		t.Fatalf("VerifyIdentityTokenWithCertsURL: %v", err)
	}
	if claims.InstanceID != "111222333" {
		t.Errorf("InstanceID = %q", claims.InstanceID)
	}
	if claims.InstanceName != "my-vm" {
		t.Errorf("InstanceName = %q", claims.InstanceName)
	}
	if claims.ProjectID != "my-project" {
		t.Errorf("ProjectID = %q", claims.ProjectID)
	}
	if claims.ProjectNumber != 987654321 {
		t.Errorf("ProjectNumber = %d", claims.ProjectNumber)
	}
	if claims.Zone != "us-central1-a" {
		t.Errorf("Zone = %q", claims.Zone)
	}
}

func TestVerifyIdentityTokenWrongAudience(t *testing.T) {
	s := newTestSigner(t)
	jwks := newJWKSServer(t, s.jwksJSON())
	defer jwks.Close()

	iat := time.Now().Add(-1 * time.Minute)
	exp := time.Now().Add(1 * time.Hour)
	tok := s.sign(t, basePayload("https://svc-a.example.com", iat, exp), "")

	_, err := VerifyIdentityTokenWithCertsURL(context.Background(), tok, "https://svc-b.example.com", jwks.URL)
	if err == nil {
		t.Fatal("expected error for audience mismatch")
	}
}

func TestVerifyIdentityTokenExpired(t *testing.T) {
	s := newTestSigner(t)
	jwks := newJWKSServer(t, s.jwksJSON())
	defer jwks.Close()

	iat := time.Now().Add(-2 * time.Hour)
	exp := time.Now().Add(-1 * time.Hour)
	tok := s.sign(t, basePayload("https://svc.example.com", iat, exp), "")

	_, err := VerifyIdentityTokenWithCertsURL(context.Background(), tok, "https://svc.example.com", jwks.URL)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerifyIdentityTokenTamperedSignature(t *testing.T) {
	s := newTestSigner(t)
	jwks := newJWKSServer(t, s.jwksJSON())
	defer jwks.Close()

	iat := time.Now().Add(-1 * time.Minute)
	exp := time.Now().Add(1 * time.Hour)
	tok := s.sign(t, basePayload("https://svc.example.com", iat, exp), "")

	// Tamper by flipping a byte in the middle of the decoded signature,
	// then re-encode. Flipping a base64url character directly can touch
	// only padding bits at the tail and leave the decoded bytes
	// identical — not actually a tamper.
	parts := strings.Split(tok, ".")
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	sigBytes[len(sigBytes)/2] ^= 0xFF
	bad := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sigBytes)

	_, err = VerifyIdentityTokenWithCertsURL(context.Background(), bad, "https://svc.example.com", jwks.URL)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestVerifyIdentityTokenRejectsEmptyAudience(t *testing.T) {
	if _, err := VerifyIdentityToken(context.Background(), "any.token.here", ""); err == nil {
		t.Fatal("expected rejection for empty expectedAudience")
	}
	if _, err := VerifyIdentityTokenWithCertsURL(context.Background(), "any.token.here", "", "https://example.com/certs"); err == nil {
		t.Fatal("expected rejection for empty expectedAudience on WithCertsURL path")
	}
}

func TestVerifyIdentityTokenWithCertsURLRejectsBadURL(t *testing.T) {
	cases := []struct {
		name     string
		certsURL string
	}{
		{"empty", ""},
		{"no-scheme", "www.googleapis.com/oauth2/v3/certs"},
		{"ftp-scheme", "ftp://example.com/certs"},
		{"file-scheme", "file:///etc/passwd"},
		{"no-host", "https://"},
		// Port-only URL: url.Parse leaves u.Host == ":1234" (non-empty)
		// but u.Hostname() == "" — the check must use Hostname().
		{"port-only-no-hostname", "https://:1234/certs"},
		{"remote-http", "http://example.com/certs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyIdentityTokenWithCertsURL(context.Background(), "any", "aud", tc.certsURL)
			if err == nil {
				t.Fatalf("expected error for certsURL=%q", tc.certsURL)
			}
		})
	}
}

func TestVerifyIdentityTokenWithCertsURLAllowsLoopbackHTTP(t *testing.T) {
	// A plain http:// URL targeting a loopback address should not be
	// rejected at the URL-shape check — test JWKS servers commonly
	// serve on http://127.0.0.1:port. We only care that the shape
	// check passes; the eventual verify call will fail because the
	// target isn't a real JWKS server, but that's a separate branch.
	cases := []string{
		"http://127.0.0.1:12345/certs",
		"http://localhost:12345/certs",
		"http://[::1]:12345/certs",
	}
	for _, certsURL := range cases {
		t.Run(certsURL, func(t *testing.T) {
			_, err := VerifyIdentityTokenWithCertsURL(context.Background(), "any", "aud", certsURL)
			if err == nil {
				t.Fatal("expected downstream error, got nil")
			}
			// Must not be rejected by the http-scheme-requires-loopback check.
			if strings.Contains(err.Error(), "must use https unless host is loopback") {
				t.Errorf("loopback URL was rejected by http-scheme check: %v", err)
			}
		})
	}
}

func TestVerifyIdentityTokenFullLicenses(t *testing.T) {
	s := newTestSigner(t)
	jwks := newJWKSServer(t, s.jwksJSON())
	defer jwks.Close()

	iat := time.Now().Add(-1 * time.Minute)
	exp := time.Now().Add(1 * time.Hour)
	p := fullPayload("https://svc.example.com", iat, exp)
	// Append license_id array — GCP encodes this under google.compute_engine
	// when the token was requested with WithIncludeLicenses.
	ce := ceClaim(t, p)
	ce["license_id"] = []any{"lic-ubuntu-pro", "lic-sap"}
	tok := s.sign(t, p, "")

	claims, err := VerifyIdentityTokenWithCertsURL(context.Background(), tok, "https://svc.example.com", jwks.URL)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(claims.LicenseIDs) != 2 || claims.LicenseIDs[0] != "lic-ubuntu-pro" || claims.LicenseIDs[1] != "lic-sap" {
		t.Errorf("LicenseIDs = %v", claims.LicenseIDs)
	}
}

func TestParseProjectNumber(t *testing.T) {
	okCases := []struct {
		name string
		in   any
		want int64
	}{
		// Real GCE project numbers are 10-12 digits, per
		// https://docs.cloud.google.com/compute/docs/instances/verifying-instance-identity
		// (example payload uses 739419398126).
		{"float-realistic", float64(739419398126), 739419398126},
		{"float-small", float64(987654321), 987654321},
		{"float-zero", float64(0), 0},
		{"string-fallback", "987654321", 987654321},
	}
	for _, tc := range okCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseProjectNumber(tc.in)
			if err != nil {
				t.Fatalf("parseProjectNumber(%v): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseProjectNumber(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}

	errCases := []struct {
		name string
		in   any
	}{
		{"float-nan", math.NaN()},
		{"float-+inf", math.Inf(1)},
		{"float--inf", math.Inf(-1)},
		{"float-fractional", 12345.6},
		{"float-over-int64", math.MaxFloat64},
		{"float-under-int64", -math.MaxFloat64},
		{"string-invalid", "not-a-number"},
		{"bool-unsupported", true},
		{"nil", nil},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseProjectNumber(tc.in); err == nil {
				t.Errorf("parseProjectNumber(%v): expected error, got nil", tc.in)
			}
		})
	}
}

func TestVerifyIdentityTokenRejectsMalformedProjectNumber(t *testing.T) {
	s := newTestSigner(t)
	jwks := newJWKSServer(t, s.jwksJSON())
	defer jwks.Close()

	iat := time.Now().Add(-1 * time.Minute)
	exp := time.Now().Add(1 * time.Hour)
	p := fullPayload("https://svc.example.com", iat, exp)
	ce := ceClaim(t, p)
	ce["project_number"] = "not-a-number"
	tok := s.sign(t, p, "")

	_, err := VerifyIdentityTokenWithCertsURL(context.Background(), tok, "https://svc.example.com", jwks.URL)
	if err == nil {
		t.Fatal("expected rejection for malformed project_number")
	}
	if !strings.Contains(err.Error(), "invalid project_number") {
		t.Errorf("err = %v, want invalid project_number", err)
	}
}

func TestVerifyIdentityTokenProjectNumberAsString(t *testing.T) {
	s := newTestSigner(t)
	jwks := newJWKSServer(t, s.jwksJSON())
	defer jwks.Close()

	iat := time.Now().Add(-1 * time.Minute)
	exp := time.Now().Add(1 * time.Hour)
	p := fullPayload("https://svc.example.com", iat, exp)
	// Replace project_number with a string — this is the safe encoding
	// for numbers above 2^53 that would otherwise lose precision in
	// JSON float64. parseProjectNumber must handle both forms.
	ce := ceClaim(t, p)
	ce["project_number"] = "9223372036854775807"
	tok := s.sign(t, p, "")

	claims, err := VerifyIdentityTokenWithCertsURL(context.Background(), tok, "https://svc.example.com", jwks.URL)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.ProjectNumber != 9223372036854775807 {
		t.Errorf("ProjectNumber = %d, want int64 max", claims.ProjectNumber)
	}
}

func TestVerifyIdentityTokenKidMismatch(t *testing.T) {
	s := newTestSigner(t)
	jwks := newJWKSServer(t, s.jwksJSON())
	defer jwks.Close()

	iat := time.Now().Add(-1 * time.Minute)
	exp := time.Now().Add(1 * time.Hour)
	tok := s.sign(t, basePayload("https://svc.example.com", iat, exp), "other-kid")

	_, err := VerifyIdentityTokenWithCertsURL(context.Background(), tok, "https://svc.example.com", jwks.URL)
	if err == nil {
		t.Fatal("expected error for kid mismatch")
	}
}
