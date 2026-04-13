package ibmimds

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	imds "github.com/OrHayat/imds-go"
)

func TestGetIdentityToken(t *testing.T) {
	var gotExpires int
	var gotFlavor string
	var gotMethod string
	var gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/instance_identity/v1/token" {
			http.NotFound(w, r)
			return
		}
		gotMethod = r.Method
		gotFlavor = r.Header.Get("Metadata-Flavor")
		gotVersion = r.URL.Query().Get("version")
		var body struct {
			ExpiresIn int `json:"expires_in"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		gotExpires = body.ExpiresIn
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "raw.jwt.value"})
	}))
	defer srv.Close()

	c, err := New(imds.WithBaseURL(srv.URL), imds.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}

	tok, err := c.GetIdentityToken(t.Context())
	if err != nil {
		t.Fatalf("GetIdentityToken: %v", err)
	}
	if tok != "raw.jwt.value" {
		t.Errorf("token = %q, want %q (no Bearer prefix)", tok, "raw.jwt.value")
	}
	if strings.HasPrefix(tok, "Bearer ") {
		t.Errorf("token should not carry Bearer prefix, got %q", tok)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotFlavor != "ibm" {
		t.Errorf("Metadata-Flavor = %q, want ibm", gotFlavor)
	}
	if gotVersion != apiVersion {
		t.Errorf("version = %q, want %q", gotVersion, apiVersion)
	}
	if gotExpires != tokenTTL {
		t.Errorf("expires_in = %d, want %d (default tokenTTL)", gotExpires, tokenTTL)
	}
}

func TestGetIdentityTokenWithExpiresIn(t *testing.T) {
	var gotExpires int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ExpiresIn int `json:"expires_in"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		gotExpires = body.ExpiresIn
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "t"})
	}))
	defer srv.Close()

	c, err := New(imds.WithBaseURL(srv.URL), imds.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.GetIdentityToken(t.Context(), WithExpiresIn(600)); err != nil {
		t.Fatal(err)
	}
	if gotExpires != 600 {
		t.Errorf("expires_in = %d, want 600", gotExpires)
	}
}

func TestGetIdentityTokenRejectsNonPositiveExpiry(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetIdentityToken(t.Context(), WithExpiresIn(0)); err == nil {
		t.Fatal("expected error for expires_in=0")
	}
	if _, err := c.GetIdentityToken(t.Context(), WithExpiresIn(-5)); err == nil {
		t.Fatal("expected error for negative expires_in")
	}
}

func TestGetIdentityTokenEmptyAccessTokenRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: ""})
	}))
	defer srv.Close()

	c, err := New(imds.WithBaseURL(srv.URL), imds.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetIdentityToken(t.Context()); err == nil {
		t.Fatal("expected error on empty access_token")
	}
}
