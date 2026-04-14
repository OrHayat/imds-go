package azureimds

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
)

type testFixture struct {
	rootCert *x509.Certificate
	rootKey  *rsa.PrivateKey
	leafCert *x509.Certificate
	leafKey  *rsa.PrivateKey
}

func newTestFixture(t *testing.T) *testFixture {
	return newTestFixtureWithRootCN(t, "test-root")
}

func newTestFixtureWithRootCN(t *testing.T, rootCN string) *testFixture {
	t.Helper()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: rootCN},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return &testFixture{
		rootCert: rootCert,
		rootKey:  rootKey,
		leafCert: leafCert,
		leafKey:  leafKey,
	}
}

func (f *testFixture) rootPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(f.rootCert)
	return p
}

func (f *testFixture) signPayload(t *testing.T, payload []byte) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSignerChain(f.leafCert, f.leafKey, []*x509.Certificate{f.rootCert}, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func samplePayload(nonce string, created, expires time.Time) []byte {
	payload := map[string]any{
		"vmId":           "vm-abc",
		"subscriptionId": "sub-xyz",
		"sku":            "18.04-LTS",
		"licenseType":    "Windows_Server",
		"nonce":          nonce,
		"plan": map[string]string{
			"name":      "plan-name",
			"product":   "plan-product",
			"publisher": "plan-publisher",
		},
		"timeStamp": map[string]string{
			"createdOn": created.UTC().Format(attestedTimeLayout),
			"expiresOn": expires.UTC().Format(attestedTimeLayout),
		},
	}
	b, _ := json.Marshal(payload)
	return b
}

func TestVerifyAttestedDocumentPositive(t *testing.T) {
	f := newTestFixture(t)
	created := time.Now().Add(-time.Minute)
	expires := time.Now().Add(5 * time.Minute)
	payload := samplePayload("abc123", created, expires)
	sig := f.signPayload(t, payload)

	claims, err := VerifyAttestedDocumentWithRoots(sig, "abc123", f.rootPool())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.VMID != "vm-abc" {
		t.Errorf("VMID = %q", claims.VMID)
	}
	if claims.SubscriptionID != "sub-xyz" {
		t.Errorf("SubscriptionID = %q", claims.SubscriptionID)
	}
	if claims.SKU != "18.04-LTS" {
		t.Errorf("SKU = %q", claims.SKU)
	}
	if claims.LicenseType != "Windows_Server" {
		t.Errorf("LicenseType = %q", claims.LicenseType)
	}
	if claims.Nonce != "abc123" {
		t.Errorf("Nonce = %q", claims.Nonce)
	}
	if claims.Plan.Name != "plan-name" || claims.Plan.Product != "plan-product" || claims.Plan.Publisher != "plan-publisher" {
		t.Errorf("Plan = %+v", claims.Plan)
	}
	if claims.CreatedOn.IsZero() || claims.ExpiresOn.IsZero() {
		t.Errorf("timestamps not parsed: %v / %v", claims.CreatedOn, claims.ExpiresOn)
	}
}

func TestVerifyAttestedDocumentSkipsNonceWhenEmpty(t *testing.T) {
	f := newTestFixture(t)
	payload := samplePayload("ignored", time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute))
	sig := f.signPayload(t, payload)

	claims, err := VerifyAttestedDocumentWithRoots(sig, "", f.rootPool())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Nonce != "ignored" {
		t.Errorf("Nonce = %q", claims.Nonce)
	}
}

func TestVerifyAttestedDocumentNonceMismatch(t *testing.T) {
	f := newTestFixture(t)
	payload := samplePayload("server-nonce", time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute))
	sig := f.signPayload(t, payload)

	_, err := VerifyAttestedDocumentWithRoots(sig, "different-nonce", f.rootPool())
	if err == nil {
		t.Fatal("expected nonce mismatch error")
	}
}

func TestVerifyAttestedDocumentExpired(t *testing.T) {
	f := newTestFixture(t)
	payload := samplePayload("", time.Now().Add(-time.Hour), time.Now().Add(-time.Minute))
	sig := f.signPayload(t, payload)

	_, err := VerifyAttestedDocumentWithRoots(sig, "", f.rootPool())
	if err == nil {
		t.Fatal("expected expired error")
	}
}

func TestVerifyAttestedDocumentTampered(t *testing.T) {
	f := newTestFixture(t)
	payload := samplePayload("abc", time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute))
	sig := f.signPayload(t, payload)

	// Flip a byte in the middle of the DER structure — likely to corrupt
	// either the signature or the payload.
	sig[len(sig)/2] ^= 0xFF

	_, err := VerifyAttestedDocumentWithRoots(sig, "abc", f.rootPool())
	if err == nil {
		t.Fatal("expected verification error on tampered signature")
	}
}

func TestVerifyAttestedDocumentUntrustedRoot(t *testing.T) {
	f := newTestFixture(t)
	payload := samplePayload("", time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute))
	sig := f.signPayload(t, payload)

	// Build a fresh unrelated root pool — should fail chain verification.
	other := newTestFixture(t)
	_, err := VerifyAttestedDocumentWithRoots(sig, "", other.rootPool())
	if err == nil {
		t.Fatal("expected cert chain verification error")
	}
}

func TestVerifyAttestedDocumentBadPKCS7(t *testing.T) {
	f := newTestFixture(t)
	_, err := VerifyAttestedDocumentWithRoots([]byte("not-pkcs7"), "", f.rootPool())
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestVerifyAttestedDocumentBadTimestamp(t *testing.T) {
	f := newTestFixture(t)
	// Use RFC3339 instead of the expected MM/dd/yy layout.
	payload := map[string]any{
		"vmId":  "vm-abc",
		"nonce": "",
		"timeStamp": map[string]string{
			"createdOn": "2026-04-11T13:00:00Z",
			"expiresOn": "2026-04-11T13:05:00Z",
		},
	}
	b, _ := json.Marshal(payload)
	sig := f.signPayload(t, b)

	_, err := VerifyAttestedDocumentWithRoots(sig, "", f.rootPool())
	if err == nil {
		t.Fatal("expected timestamp parse error")
	}
}

func TestVerifyAttestedDocumentWithRootsNilPool(t *testing.T) {
	_, err := VerifyAttestedDocumentWithRoots([]byte("irrelevant"), "", nil)
	if err == nil {
		t.Fatal("expected error on nil roots pool")
	}
}

func TestVerifyAttestedDocumentAzureIssuerAccepted(t *testing.T) {
	f := newTestFixtureWithRootCN(t, "Microsoft Azure RSA TLS Issuing CA 03")
	payload := samplePayload("", time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute))
	sig := f.signPayload(t, payload)

	// Call the internal verifier with requireAzureIssuer=true to exercise
	// the issuer check without depending on the host system cert pool.
	claims, err := verifyAttestedDocument(sig, "", f.rootPool(), true)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.VMID != "vm-abc" {
		t.Errorf("VMID = %q", claims.VMID)
	}
}

func TestVerifyAttestedDocumentNonAzureIssuerRejected(t *testing.T) {
	f := newTestFixtureWithRootCN(t, "Some Other CA")
	payload := samplePayload("", time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute))
	sig := f.signPayload(t, payload)

	_, err := verifyAttestedDocument(sig, "", f.rootPool(), true)
	if err == nil {
		t.Fatal("expected rejection for non-Azure issuer")
	}
	if !strings.Contains(err.Error(), "not issued by Microsoft Azure") {
		t.Errorf("error = %v, want Azure issuer rejection", err)
	}
}

func TestGetAttestedDocument(t *testing.T) {
	f := newTestFixture(t)
	payload := samplePayload("nonce-42", time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute))
	sig := f.signPayload(t, payload)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			http.Error(w, "missing Metadata header", http.StatusBadRequest)
			return
		}
		if r.URL.Path != attestedPath {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("api-version") != attestedAPIVersion {
			http.Error(w, "wrong api-version", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("nonce") != "nonce-42" {
			http.Error(w, "wrong nonce", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"encoding":  "pkcs7",
			"signature": sigB64,
		})
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	doc, err := c.GetAttestedDocument(t.Context(), WithNonce("nonce-42"))
	if err != nil {
		t.Fatalf("GetAttestedDocument: %v", err)
	}
	if doc.Encoding != "pkcs7" {
		t.Errorf("Encoding = %q", doc.Encoding)
	}
	if doc.Nonce != "nonce-42" {
		t.Errorf("Nonce = %q", doc.Nonce)
	}

	// Round-trip: verify the signature we just fetched.
	claims, err := VerifyAttestedDocumentWithRoots(doc.Signature, "nonce-42", f.rootPool())
	if err != nil {
		t.Fatalf("verify round-trip: %v", err)
	}
	if claims.VMID != "vm-abc" {
		t.Errorf("VMID = %q", claims.VMID)
	}
}

func TestGetAttestedDocumentNoNonce(t *testing.T) {
	f := newTestFixture(t)
	payload := samplePayload("", time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute))
	sig := f.signPayload(t, payload)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("nonce") {
			http.Error(w, "unexpected nonce", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"encoding":  "pkcs7",
			"signature": sigB64,
		})
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	doc, err := c.GetAttestedDocument(t.Context())
	if err != nil {
		t.Fatalf("GetAttestedDocument: %v", err)
	}
	if doc.Nonce != "" {
		t.Errorf("Nonce = %q, want empty", doc.Nonce)
	}
}

func TestGetAttestedDocumentBadEncoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"encoding":  "pem",
			"signature": "Zm9v",
		})
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	_, err := c.GetAttestedDocument(t.Context())
	if err == nil {
		t.Fatal("expected bad encoding error")
	}
}

func TestGetAttestedDocumentBadBase64(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"encoding":  "pkcs7",
			"signature": "!!!not-base64!!!",
		})
	}))
	defer srv.Close()

	c := New(WithBaseURL(srv.URL), WithHTTPClient(srv.Client()))
	_, err := c.GetAttestedDocument(t.Context())
	if err == nil {
		t.Fatal("expected base64 decode error")
	}
}
