package ociimds

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// OCI embeds claims as custom string-valued attributes in the subject
// DN. For our tests we use a throwaway OID under the private enterprise
// arc. Any OID works — Go's x509 parser populates cert.Subject.Names
// with every attribute it finds in the RDN sequence, and our claim
// extractor matches on the value's string prefix, not on OID.
var testOPCAttrOID = []int{1, 3, 6, 1, 4, 1, 99999, 1}

type testPKI struct {
	rootCert   *x509.Certificate
	rootKey    *rsa.PrivateKey
	rootPEM    []byte
	intCert    *x509.Certificate
	intKey     *rsa.PrivateKey
	intPEM     []byte
	leafCert   *x509.Certificate
	leafKey    *rsa.PrivateKey
	leafPEM    []byte
	leafKeyPEM []byte
	rootPool   *x509.CertPool
}

// newTestPKI returns a cached shared testPKI for the common case —
// most tests in this file only need one stable RSA chain and pay no
// attention to its particular bytes, so regenerating ~3 RSA-2048 keys
// per test (there are ~28 tests) adds seconds of wall-clock time for
// no benefit. Tests that need a DISTINCT PKI (e.g. to prove cert chain
// verification fails across unrelated roots, or to exercise the
// per-override cache isolation) call newFreshTestPKI.
//
// The fixture is immutable after construction — all fields are read
// only from tests — so sharing across tests is safe.
var (
	sharedPKIMu sync.Mutex
	sharedPKI   *testPKI
)

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	sharedPKIMu.Lock()
	defer sharedPKIMu.Unlock()
	if sharedPKI != nil {
		return sharedPKI
	}
	sharedPKI = newFreshTestPKI(t)
	return sharedPKI
}

func newFreshTestPKI(t *testing.T) *testPKI {
	t.Helper()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	intKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		t.Fatal(err)
	}
	intPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intDER})

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "test-leaf",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: testOPCAttrOID, Value: "opc-tenant:tnc-111"},
				{Type: testOPCAttrOID, Value: "opc-instance:inst-222"},
				{Type: testOPCAttrOID, Value: "opc-compartment:comp-333"},
			},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(leafKey),
	})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	return &testPKI{
		rootCert:   rootCert,
		rootKey:    rootKey,
		rootPEM:    rootPEM,
		intCert:    intCert,
		intKey:     intKey,
		intPEM:     intPEM,
		leafCert:   leafCert,
		leafKey:    leafKey,
		leafPEM:    leafPEM,
		leafKeyPEM: leafKeyPEM,
		rootPool:   rootPool,
	}
}

func newIdentityServer(t *testing.T, pki *testPKI) (*httptest.Server, *Client) {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer Oracle" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case basePath + certPath:
			w.Write(pki.leafPEM)
		case basePath + intermediatePath:
			w.Write(pki.intPEM)
		case basePath + keyPath:
			w.Write(pki.leafKeyPEM)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(handler)
	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		srv.Close()
		t.Fatal(err)
	}
	return srv, c
}

func TestClaimsRoundTrip(t *testing.T) {
	// Sanity: make sure our test cert actually produces Subject.Names
	// entries that our prefix-matching extractor recognizes. If this
	// fails, the rest of the suite is meaningless.
	pki := newTestPKI(t)
	claims := claimsFromCert(pki.leafCert)
	if claims.TenancyID != "tnc-111" {
		t.Errorf("TenancyID: got %q, want %q", claims.TenancyID, "tnc-111")
	}
	if claims.InstanceID != "inst-222" {
		t.Errorf("InstanceID: got %q, want %q", claims.InstanceID, "inst-222")
	}
	if claims.CompartmentID != "comp-333" {
		t.Errorf("CompartmentID: got %q, want %q", claims.CompartmentID, "comp-333")
	}
}

func TestGetIdentityDocumentNoNonce(t *testing.T) {
	pki := newTestPKI(t)
	srv, c := newIdentityServer(t, pki)
	defer srv.Close()

	doc, err := c.GetIdentityDocument(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.LeafCert) == 0 || len(doc.Intermediate) == 0 {
		t.Fatal("expected leaf and intermediate to be populated")
	}
	if doc.Nonce != nil || doc.Signature != nil {
		t.Error("expected Nonce/Signature nil when WithNonce not supplied")
	}

	claims, err := VerifyIdentityDocumentWithRoots(doc, pki.rootPool, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.TenancyID != "tnc-111" {
		t.Errorf("TenancyID: got %q", claims.TenancyID)
	}
	if claims.InstanceID != "inst-222" {
		t.Errorf("InstanceID: got %q", claims.InstanceID)
	}
	if claims.CompartmentID != "comp-333" {
		t.Errorf("CompartmentID: got %q", claims.CompartmentID)
	}
}

func TestGetIdentityDocumentWithNonce(t *testing.T) {
	pki := newTestPKI(t)
	srv, c := newIdentityServer(t, pki)
	defer srv.Close()

	nonce := []byte("verifier-chosen-nonce-12345")
	doc, err := c.GetIdentityDocument(t.Context(), WithNonce(nonce))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Signature) == 0 {
		t.Fatal("expected signature to be populated")
	}
	if string(doc.Nonce) != string(nonce) {
		t.Errorf("nonce: got %q, want %q", doc.Nonce, nonce)
	}

	claims, err := VerifyIdentityDocumentWithRoots(doc, pki.rootPool, nonce)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.TenancyID != "tnc-111" {
		t.Errorf("TenancyID: got %q", claims.TenancyID)
	}
}

func TestVerifyRejectsMissingNonceWithEmptyExpected(t *testing.T) {
	// bytes.Equal(nil, []byte{}) returns true, so without the explicit
	// doc.Nonce == nil check, a verifier passing an empty-but-non-nil
	// expectedNonce would silently accept a document whose Nonce was
	// never populated. Guard against that trap.
	pki := newTestPKI(t)
	// Document has no Nonce/Signature (no WithNonce was used), but we
	// forge a Signature to satisfy the earlier "no signature" check
	// so the code reaches the nonce check.
	doc := &IdentityDocument{
		LeafCert:     pki.leafPEM,
		Intermediate: pki.intPEM,
		Signature:    []byte("anything"),
	}
	_, err := VerifyIdentityDocumentWithRoots(doc, pki.rootPool, []byte{})
	if err == nil {
		t.Fatal("expected rejection for empty expectedNonce with nil doc.Nonce")
	}
	if !strings.Contains(err.Error(), "document has no nonce") {
		t.Errorf("err = %v, want missing-nonce error", err)
	}
}

func TestSignNonceRejectsTrailingPEM(t *testing.T) {
	pki := newTestPKI(t)
	// Concatenate the test leaf key PEM with a spurious trailing PEM
	// block. signNonce must reject the whole blob rather than silently
	// signing with the first key.
	trailing := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pki.leafCert.Raw})
	poisoned := append(append([]byte{}, pki.leafKeyPEM...), trailing...)
	_, err := signNonce(poisoned, []byte("nonce"))
	if err == nil {
		t.Fatal("expected rejection for trailing PEM content in key.pem")
	}
	if !strings.Contains(err.Error(), "trailing content") {
		t.Errorf("err = %v, want trailing-content rejection", err)
	}
}

func TestSignNonceRejectsNonPEM(t *testing.T) {
	// Input that's not PEM at all hits the leading-content check,
	// which runs before pem.Decode — both are acceptable rejections
	// for "garbage in."
	_, err := signNonce([]byte("definitely not pem"), []byte("nonce"))
	if err == nil {
		t.Fatal("expected rejection for non-PEM key")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not PEM-encoded") && !strings.Contains(msg, "leading content") {
		t.Errorf("err = %v, want not-PEM or leading-content rejection", err)
	}
}

func TestSignNonceRejectsLeadingPEMContent(t *testing.T) {
	pki := newTestPKI(t)
	// Prepend attacker-chosen garbage before the real key PEM. The
	// leading-content check must reject this instead of pem.Decode
	// silently skipping the prefix bytes (polyglot input hole).
	poisoned := append([]byte("evil-prefix\n"), pki.leafKeyPEM...)
	_, err := signNonce(poisoned, []byte("nonce"))
	if err == nil {
		t.Fatal("expected rejection for leading content in key.pem")
	}
	if !strings.Contains(err.Error(), "leading content") {
		t.Errorf("err = %v, want leading-content rejection", err)
	}
}

func TestSignNonceAcceptsLeadingWhitespace(t *testing.T) {
	pki := newTestPKI(t)
	// Leading whitespace (newlines, tabs) is tolerated — real IMDS
	// responses may start with a newline.
	whitespaced := append([]byte("  \n\t"), pki.leafKeyPEM...)
	if _, err := signNonce(whitespaced, []byte("nonce")); err != nil {
		t.Fatalf("signNonce with leading whitespace: %v", err)
	}
}

func TestSignNonceRejectsWrongBlockType(t *testing.T) {
	// A PEM block with the wrong type (CERTIFICATE instead of a key
	// type) must be rejected up front, not passed to the parsers.
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("irrelevant")})
	_, err := signNonce(keyPEM, []byte("nonce"))
	if err == nil {
		t.Fatal("expected rejection for wrong PEM block type")
	}
	if !strings.Contains(err.Error(), "unexpected PEM type") {
		t.Errorf("err = %v, want unexpected-type rejection", err)
	}
}

func TestSignNonceRejectsMalformedPKCS1(t *testing.T) {
	// Well-formed PEM block wrapping garbage bytes — ParsePKCS1PrivateKey
	// fails, the error is wrapped.
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("not a valid pkcs1 der")})
	_, err := signNonce(keyPEM, []byte("nonce"))
	if err == nil {
		t.Fatal("expected rejection for malformed PKCS1")
	}
	if !strings.Contains(err.Error(), "parse PKCS1") {
		t.Errorf("err = %v, want parse-PKCS1 error", err)
	}
}

func TestSignNonceRejectsNonRSAPKCS8(t *testing.T) {
	// Generate an ECDSA key and wrap it in PKCS8 — signNonce should
	// parse the PKCS8 block successfully but refuse the key because
	// it's not RSA.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	_, err = signNonce(keyPEM, []byte("nonce"))
	if err == nil {
		t.Fatal("expected rejection for non-RSA PKCS8 key")
	}
	if !strings.Contains(err.Error(), "not an RSA") {
		t.Errorf("err = %v, want not-RSA rejection", err)
	}
}

func TestVerifyRejectsLeadingPEMContent(t *testing.T) {
	// parsePEMCert must reject leading non-PEM content, matching the
	// alibabaimds hardening and closing the polyglot-input hole.
	pki := newTestPKI(t)
	poisoned := append([]byte("evil-prefix\n"), pki.leafPEM...)
	doc := &IdentityDocument{LeafCert: poisoned, Intermediate: pki.intPEM}
	_, err := VerifyIdentityDocumentWithRoots(doc, pki.rootPool, nil)
	if err == nil {
		t.Fatal("expected rejection for leading content")
	}
	if !strings.Contains(err.Error(), "leading content") {
		t.Errorf("err = %v, want leading-content rejection", err)
	}
}

func TestVerifyAcceptsLeadingWhitespace(t *testing.T) {
	// Leading whitespace (newlines, tabs) is tolerated — real IMDS
	// responses may start with a newline and we don't want to fail
	// on whitespace.
	pki := newTestPKI(t)
	doc := &IdentityDocument{
		LeafCert:     append([]byte("  \n\t"), pki.leafPEM...),
		Intermediate: pki.intPEM,
	}
	if _, err := VerifyIdentityDocumentWithRoots(doc, pki.rootPool, nil); err != nil {
		t.Fatalf("verify with leading whitespace: %v", err)
	}
}

func TestGetIdentityDocumentFetchFailures(t *testing.T) {
	pki := newTestPKI(t)

	// Server that 404s for a specific path, serves real content for
	// the others. Drives each branch of GetIdentityDocument's fetch
	// chain: leaf, intermediate, key.
	for _, failPath := range []string{
		basePath + certPath,
		basePath + intermediatePath,
		basePath + keyPath,
	} {
		t.Run(failPath, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == failPath {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if r.Header.Get("Authorization") != "Bearer Oracle" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				switch r.URL.Path {
				case basePath + certPath:
					_, _ = w.Write(pki.leafPEM)
				case basePath + intermediatePath:
					_, _ = w.Write(pki.intPEM)
				case basePath + keyPath:
					_, _ = w.Write(pki.leafKeyPEM)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()

			c, err := New(WithBaseURL(srv.URL))
			if err != nil {
				t.Fatal(err)
			}
			// Pass WithNonce to force all three fetches (leaf,
			// intermediate, key) so each failPath case exercises a
			// distinct branch.
			_, err = c.GetIdentityDocument(t.Context(), WithNonce([]byte("nonce")))
			if err == nil {
				t.Fatal("expected error when fetch failed")
			}
		})
	}
}

func TestFetchRegionalRootsCacheIsolatesByOverride(t *testing.T) {
	// Two different baseURLOverride values for the same region must
	// not collide in the cache: each override should get its own
	// cached pool. The previous region-only cache key would hand out
	// the wrong pool (or poison the production cache).
	//
	// Use newFreshTestPKI for both so the two roots are distinct —
	// if cache isolation fails, verification of docB would return
	// pkiA's pool, which is signed by an unrelated chain, and the
	// test would fail.
	ClearRootCache()
	pkiA := newFreshTestPKI(t)
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pkiA.rootPEM)
	}))
	defer srvA.Close()

	pkiB := newFreshTestPKI(t)
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pkiB.rootPEM)
	}))
	defer srvB.Close()

	docA := &IdentityDocument{LeafCert: pkiA.leafPEM, Intermediate: pkiA.intPEM}
	docB := &IdentityDocument{LeafCert: pkiB.leafPEM, Intermediate: pkiB.intPEM}

	// Prime the cache via srvA.
	if _, err := VerifyIdentityDocument(t.Context(), docA, "us-ashburn-1", nil,
		WithFetchHTTPClient(srvA.Client()),
		withRootBaseURL(srvA.URL),
	); err != nil {
		t.Fatalf("verify via srvA: %v", err)
	}
	// Verify via srvB for the SAME region. If the cache were keyed by
	// region alone, this would reuse pkiA's pool and fail to verify
	// docB (different root). Keyed by (region+override) it fetches
	// from srvB and succeeds.
	if _, err := VerifyIdentityDocument(t.Context(), docB, "us-ashburn-1", nil,
		WithFetchHTTPClient(srvB.Client()),
		withRootBaseURL(srvB.URL),
	); err != nil {
		t.Fatalf("verify via srvB: %v", err)
	}
}

func TestGetIdentityDocumentWithEmptyNonce(t *testing.T) {
	pki := newTestPKI(t)
	srv, c := newIdentityServer(t, pki)
	defer srv.Close()

	nonce := []byte{}
	doc, err := c.GetIdentityDocument(t.Context(), WithNonce(nonce))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(doc.Signature) == 0 {
		t.Fatal("expected signature to be populated for empty-but-present nonce")
	}
	if doc.Nonce == nil {
		t.Fatal("expected nonce to be present as an empty slice, not nil")
	}
	if len(doc.Nonce) != 0 {
		t.Errorf("nonce length: got %d, want 0", len(doc.Nonce))
	}

	claims, err := VerifyIdentityDocumentWithRoots(doc, pki.rootPool, nonce)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.TenancyID != "tnc-111" {
		t.Errorf("TenancyID: got %q", claims.TenancyID)
	}
}

func TestVerifyWrongNonce(t *testing.T) {
	pki := newTestPKI(t)
	srv, c := newIdentityServer(t, pki)
	defer srv.Close()

	doc, err := c.GetIdentityDocument(t.Context(), WithNonce([]byte("real-nonce")))
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyIdentityDocumentWithRoots(doc, pki.rootPool, []byte("different-nonce"))
	if err == nil {
		t.Fatal("expected error for mismatched nonce")
	}
}

func TestVerifyMissingSignature(t *testing.T) {
	pki := newTestPKI(t)
	srv, c := newIdentityServer(t, pki)
	defer srv.Close()

	doc, err := c.GetIdentityDocument(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyIdentityDocumentWithRoots(doc, pki.rootPool, []byte("some-nonce"))
	if err == nil {
		t.Fatal("expected error when expectedNonce set but doc has no signature")
	}
}

func TestVerifyEmptySignatureRejected(t *testing.T) {
	// An empty-but-non-nil signature slice should hit the same
	// explicit "no signature" path as a nil slice, not fall through
	// to rsa.VerifyPKCS1v15 with a cryptic verification error.
	pki := newTestPKI(t)
	doc := &IdentityDocument{
		LeafCert:     pki.leafPEM,
		Intermediate: pki.intPEM,
		Nonce:        []byte("n"),
		Signature:    []byte{},
	}
	_, err := VerifyIdentityDocumentWithRoots(doc, pki.rootPool, []byte("n"))
	if err == nil {
		t.Fatal("expected rejection for empty signature")
	}
	if !strings.Contains(err.Error(), "has no signature") {
		t.Errorf("err = %v, want explicit no-signature rejection", err)
	}
}

func TestVerifyUntrustedRoot(t *testing.T) {
	pki := newTestPKI(t)
	srv, c := newIdentityServer(t, pki)
	defer srv.Close()

	doc, err := c.GetIdentityDocument(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	// Use newFreshTestPKI so otherPKI has a distinct root. If we used
	// the cached shared PKI, it would match pki and the test would
	// pass for the wrong reason (chain would verify cleanly).
	otherPKI := newFreshTestPKI(t)
	_, err = VerifyIdentityDocumentWithRoots(doc, otherPKI.rootPool, nil)
	if err == nil {
		t.Fatal("expected chain verification to fail with untrusted root")
	}
}

func TestVerifyTamperedSignature(t *testing.T) {
	pki := newTestPKI(t)
	srv, c := newIdentityServer(t, pki)
	defer srv.Close()

	nonce := []byte("nonce")
	doc, err := c.GetIdentityDocument(t.Context(), WithNonce(nonce))
	if err != nil {
		t.Fatal(err)
	}
	doc.Signature[0] ^= 0xFF
	_, err = VerifyIdentityDocumentWithRoots(doc, pki.rootPool, nonce)
	if err == nil {
		t.Fatal("expected signature verification to fail after tamper")
	}
}

func TestVerifyWrongEKURejected(t *testing.T) {
	// Mint a PKI where the leaf's ExtKeyUsage is ServerAuth (TLS server
	// certs) instead of ClientAuth. verifyParsed should refuse to
	// accept it because OCI instance-principal leaves are specifically
	// client-auth certs.
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "test-leaf",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: testOPCAttrOID, Value: "opc-tenant:tnc-111"},
				{Type: testOPCAttrOID, Value: "opc-instance:inst-222"},
			},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	doc := &IdentityDocument{LeafCert: leafPEM, Intermediate: rootPEM}
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)

	_, err = VerifyIdentityDocumentWithRoots(doc, pool, nil)
	if err == nil {
		t.Fatal("expected rejection for leaf with ServerAuth EKU")
	}
	if !strings.Contains(err.Error(), "verify cert chain") {
		t.Errorf("error = %v, want cert-chain rejection", err)
	}
}

func TestVerifyMultiBlockPEMRejected(t *testing.T) {
	pki := newTestPKI(t)
	// Concatenate two CERTIFICATE blocks. parsePEMCert must reject
	// the second one so a crafted bundle can't smuggle a hostile
	// extra cert alongside the expected leaf.
	doubleLeaf := append(append([]byte{}, pki.leafPEM...), pki.leafPEM...)
	doc := &IdentityDocument{LeafCert: doubleLeaf, Intermediate: pki.intPEM}
	_, err := VerifyIdentityDocumentWithRoots(doc, pki.rootPool, nil)
	if err == nil {
		t.Fatal("expected rejection for multi-block PEM")
	}
	if !strings.Contains(err.Error(), "trailing PEM content") {
		t.Errorf("error = %v, want trailing-content rejection", err)
	}
}

func TestFetchRegionalRootsSingleflightDedupes(t *testing.T) {
	ClearRootCache()
	pki := newTestPKI(t)

	// allReady is Done()'d once per goroutine right before it enters
	// VerifyIdentityDocument. The server handler, on the first
	// request, waits for all N Done calls before serving. This gives
	// a deterministic barrier instead of a flaky time.Sleep: by the
	// time the handler responds, all N goroutines have released the
	// wait group and are a few instructions away from (or already
	// inside) singleflight.Do, so they piggyback on the first
	// in-flight call instead of firing their own.
	const N = 20
	var allReady sync.WaitGroup
	allReady.Add(N)

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			allReady.Wait()
		}
		_, _ = w.Write(pki.rootPEM)
	}))
	defer srv.Close()

	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	errs := make(chan error, N)
	for range N {
		go func() {
			allReady.Done()
			_, err := VerifyIdentityDocument(context.Background(), doc, "us-ashburn-1", nil,
				WithFetchHTTPClient(srv.Client()),
				withRootBaseURL(srv.URL),
			)
			errs <- err
		}()
	}

	for range N {
		if err := <-errs; err != nil {
			t.Fatalf("verify: %v", err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected 1 upstream fetch (singleflight dedup), got %d", got)
	}
}

func TestVerifyNilDocumentRejected(t *testing.T) {
	pki := newTestPKI(t)
	_, err := VerifyIdentityDocumentWithRoots(nil, pki.rootPool, nil)
	if err == nil {
		t.Fatal("expected error on nil document")
	}
}

func TestVerifyNilRootsRejected(t *testing.T) {
	pki := newTestPKI(t)
	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	_, err := VerifyIdentityDocumentWithRoots(doc, nil, nil)
	if err == nil {
		t.Fatal("expected error on nil roots pool")
	}
}

func TestVerifyIdentityDocumentRequiresRegion(t *testing.T) {
	pki := newTestPKI(t)
	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	_, err := VerifyIdentityDocument(t.Context(), doc, "", nil)
	if err == nil {
		t.Fatal("expected error on empty region")
	}
}

func TestVerifyIdentityDocumentRejectsInjectedRegion(t *testing.T) {
	pki := newTestPKI(t)
	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	cases := []string{
		"evil.com/x",
		"us-ashburn-1/../attacker",
		"us-ashburn-1 ",
		"US-ASHBURN-1",
		"us_ashburn_1",
		"-leading",
		"trailing-",
	}
	for _, region := range cases {
		_, err := VerifyIdentityDocument(t.Context(), doc, region, nil)
		if err == nil {
			t.Errorf("expected rejection for region %q", region)
			continue
		}
		if !strings.Contains(err.Error(), "invalid region") {
			t.Errorf("region %q: error = %v, want invalid-region", region, err)
		}
	}
}

func TestVerifyMissingIdentityClaimsRejected(t *testing.T) {
	// Mint a fresh PKI where the leaf has no opc-tenant/opc-instance
	// subject attributes. verifyParsed should reject it after chain
	// verification succeeds.
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "bare-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	doc := &IdentityDocument{LeafCert: leafPEM, Intermediate: rootPEM}
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)

	_, err = VerifyIdentityDocumentWithRoots(doc, pool, nil)
	if err == nil {
		t.Fatal("expected rejection for cert with no identity claims")
	}
	if !strings.Contains(err.Error(), "missing required identity claims") {
		t.Errorf("error = %v, want missing-claims", err)
	}
}

func TestFetchRegionalRootsWrapperShape(t *testing.T) {
	ClearRootCache()
	pki := newTestPKI(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"certificates":[%q]}`, string(pki.rootPEM))
	}))
	defer srv.Close()

	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	_, err := VerifyIdentityDocument(t.Context(), doc, "us-ashburn-1", nil,
		WithFetchHTTPClient(srv.Client()),
		withRootBaseURL(srv.URL),
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestFetchRegionalRootsArrayShape(t *testing.T) {
	ClearRootCache()
	pki := newTestPKI(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `[%q]`, string(pki.rootPEM))
	}))
	defer srv.Close()

	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	_, err := VerifyIdentityDocument(t.Context(), doc, "us-ashburn-1", nil,
		WithFetchHTTPClient(srv.Client()),
		withRootBaseURL(srv.URL),
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestFetchRegionalRootsRawPEMShape(t *testing.T) {
	ClearRootCache()
	pki := newTestPKI(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pki.rootPEM)
	}))
	defer srv.Close()

	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	_, err := VerifyIdentityDocument(t.Context(), doc, "us-ashburn-1", nil,
		WithFetchHTTPClient(srv.Client()),
		withRootBaseURL(srv.URL),
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestFetchRegionalRootsNon200(t *testing.T) {
	ClearRootCache()
	pki := newTestPKI(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	_, err := VerifyIdentityDocument(t.Context(), doc, "us-ashburn-1", nil,
		WithFetchHTTPClient(srv.Client()),
		withRootBaseURL(srv.URL),
	)
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

func TestFetchRegionalRootsNon200IncludesBodySnippet(t *testing.T) {
	ClearRootCache()
	pki := newTestPKI(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("oracle is sad today"))
	}))
	defer srv.Close()

	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	_, err := VerifyIdentityDocument(t.Context(), doc, "us-ashburn-1", nil,
		WithFetchHTTPClient(srv.Client()),
		withRootBaseURL(srv.URL),
	)
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
	if !strings.Contains(err.Error(), "oracle is sad today") {
		t.Fatalf("expected error to contain body snippet, got: %v", err)
	}
}

func TestFetchRegionalRootsRejectsOversizedBody(t *testing.T) {
	ClearRootCache()
	pki := newTestPKI(t)
	// Stream more than maxRootCABodyBytes (1 MiB) of garbage.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 64*1024)
		// 1 MiB + 64 KiB to definitively exceed the cap.
		for i := 0; i < 17; i++ {
			_, _ = w.Write(buf)
		}
	}))
	defer srv.Close()

	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	_, err := VerifyIdentityDocument(t.Context(), doc, "us-ashburn-1", nil,
		WithFetchHTTPClient(srv.Client()),
		withRootBaseURL(srv.URL),
	)
	if err == nil {
		t.Fatal("expected error for oversized response")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("expected size-cap error, got: %v", err)
	}
}

func TestFetchRegionalRootsMalformed(t *testing.T) {
	ClearRootCache()
	pki := newTestPKI(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not a pem or json"))
	}))
	defer srv.Close()

	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	_, err := VerifyIdentityDocument(t.Context(), doc, "us-ashburn-1", nil,
		WithFetchHTTPClient(srv.Client()),
		withRootBaseURL(srv.URL),
	)
	if err == nil {
		t.Fatal("expected parse error for malformed response")
	}
}

func TestClearRootCache(t *testing.T) {
	ClearRootCache()
	pki := newTestPKI(t)
	// atomic: the handler goroutine increments, the test goroutine
	// reads. A plain int would race under `go test -race`.
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = w.Write(pki.rootPEM)
	}))
	defer srv.Close()

	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	for range 3 {
		if _, err := VerifyIdentityDocument(t.Context(), doc, "us-ashburn-1", nil,
			WithFetchHTTPClient(srv.Client()),
			withRootBaseURL(srv.URL),
		); err != nil {
			t.Fatal(err)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected 1 fetch (cached), got %d", got)
	}

	ClearRegionRootCache("us-ashburn-1")
	if _, err := VerifyIdentityDocument(t.Context(), doc, "us-ashburn-1", nil,
		WithFetchHTTPClient(srv.Client()),
		withRootBaseURL(srv.URL),
	); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected 2 fetches after ClearRegionRootCache, got %d", got)
	}

	ClearRootCache()
	if _, err := VerifyIdentityDocument(t.Context(), doc, "us-ashburn-1", nil,
		WithFetchHTTPClient(srv.Client()),
		withRootBaseURL(srv.URL),
	); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("expected 3 fetches after ClearRootCache, got %d", got)
	}
}

func TestClearRootCacheDuringInFlightFetch(t *testing.T) {
	// Race to defend against: goroutine A is in the middle of
	// fetching Oracle's regional roots for region R. Before A's HTTP
	// call completes, some other code calls ClearRootCache. When A's
	// fetch lands, it must NOT write the fetched pool back into the
	// cache — otherwise the Clear is silently undone and stale roots
	// linger forever.
	ClearRootCache()
	pki := newTestPKI(t)

	// reqSeen is closed by the handler as soon as the first request
	// lands so the main test goroutine knows the fetch is in flight.
	// release unblocks the handler once Clear has been called.
	reqSeen := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			close(reqSeen)
			<-release
		}
		_, _ = w.Write(pki.rootPEM)
	}))
	defer srv.Close()

	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	done := make(chan error, 1)
	go func() {
		_, err := VerifyIdentityDocument(context.Background(), doc, "us-ashburn-1", nil,
			WithFetchHTTPClient(srv.Client()),
			withRootBaseURL(srv.URL),
		)
		done <- err
	}()

	// Wait for the fetch to be in flight, then clear, then let the
	// fetch complete.
	<-reqSeen
	ClearRootCache()
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("verify during clear: %v", err)
	}

	// The fetch completed but must NOT have written back, because
	// the gen counter moved under it. The next verify must miss the
	// cache and hit the server again, so calls == 2.
	if _, err := VerifyIdentityDocument(context.Background(), doc, "us-ashburn-1", nil,
		WithFetchHTTPClient(srv.Client()),
		withRootBaseURL(srv.URL),
	); err != nil {
		t.Fatalf("post-clear verify: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected 2 upstream fetches (1 pre-clear + 1 post-clear miss), got %d — Clear was silently undone", got)
	}
}

func TestFetchRegionalRootsWaiterContextIsHonored(t *testing.T) {
	// With singleflight.Group.Do, a waiter piggybacking on another
	// goroutine's in-flight fetch would block synchronously until the
	// flight completed — even if the waiter's own ctx had already
	// cancelled. Using DoChan + per-caller select on ctx.Done lets
	// each caller honor its own deadline while still sharing the
	// underlying fetch.
	ClearRootCache()
	pki := newTestPKI(t)

	reqSeen := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(reqSeen)
			<-release
		}
		_, _ = w.Write(pki.rootPEM)
	}))
	defer srv.Close()

	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}

	// Primary caller with a generous ctx; its fetch will be held by
	// the server until we close(release).
	primaryDone := make(chan error, 1)
	go func() {
		_, err := VerifyIdentityDocument(context.Background(), doc, "us-ashburn-1", nil,
			WithFetchHTTPClient(srv.Client()),
			withRootBaseURL(srv.URL),
		)
		primaryDone <- err
	}()

	// Wait for the primary fetch to be in flight so we know the next
	// caller will piggyback on it.
	<-reqSeen

	// Waiter with a very short deadline. It should bail out on its
	// OWN ctx within ~50ms, NOT wait for the primary fetch to
	// finish. Without the DoChan fix this would block until
	// release is closed.
	waiterCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := VerifyIdentityDocument(waiterCtx, doc, "us-ashburn-1", nil,
		WithFetchHTTPClient(srv.Client()),
		withRootBaseURL(srv.URL),
	)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected waiter to return ctx error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("waiter err = %v, want context.DeadlineExceeded", err)
	}
	// Should complete around 50ms, definitely not near the 15s
	// default root-fetch timeout. Give generous headroom for slow
	// CI: anything under 1s proves the waiter didn't block on the
	// primary's completion.
	if elapsed > time.Second {
		t.Errorf("waiter took %v, want <1s (blocked on in-flight fetch instead of its own ctx)", elapsed)
	}

	// Let the primary complete.
	close(release)
	if err := <-primaryDone; err != nil {
		t.Fatalf("primary verify: %v", err)
	}
	// Only one upstream fetch happened despite two VerifyIdentityDocument
	// calls — singleflight still dedupes.
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected 1 upstream fetch, got %d", got)
	}
}

func TestFetchRegionalRootsHardTimeoutBoundsNoTimeoutClient(t *testing.T) {
	// Defense against a caller injecting an *http.Client whose Timeout
	// is 0 (a common pattern when relying purely on ctx for cancellation).
	// Inside the singleflight callback we use context.WithoutCancel so
	// one caller's cancellation can't kill the shared fetch — but that
	// means the http request would otherwise be unbounded if both the
	// client Timeout AND the original ctx are infinite. The
	// rootFetchHardTimeout cap must guarantee a wall-clock bound.
	ClearRootCache()
	pki := newTestPKI(t)

	// Shrink the hard cap so the test runs in ms instead of 15s.
	prev := rootFetchHardTimeout
	rootFetchHardTimeout = 100 * time.Millisecond
	defer func() { rootFetchHardTimeout = prev }()

	// Server hangs until either the test cleans up OR the client
	// cancels the request via ctx (which is what the hard cap does).
	// Selecting on r.Context().Done() lets the handler exit once the
	// hard cap fires, so srv.Close() doesn't deadlock waiting on a
	// stuck handler goroutine.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	// Caller-injected client with NO Timeout — only the hard cap can
	// bound this fetch. Background ctx, also no deadline.
	noTimeoutClient := &http.Client{}

	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	start := time.Now()
	_, err := VerifyIdentityDocument(context.Background(), doc, "us-ashburn-1", nil,
		WithFetchHTTPClient(noTimeoutClient),
		withRootBaseURL(srv.URL),
	)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	// Generous upper bound for slow CI: anything under 5s proves the
	// hard cap fired (vs blocking forever on the no-timeout client).
	if elapsed > 5*time.Second {
		t.Errorf("fetch took %v, want bounded by hard cap (~100ms)", elapsed)
	}
}

func TestClearRegionRootCacheDoesNotAffectOtherRegions(t *testing.T) {
	// Per-region isolation: while an in-flight fetch for region B is
	// pending, a ClearRegionRootCache("A") call must NOT invalidate
	// B's pending writeback. With a single global generation
	// counter, the clear for A would bump the counter and cause B's
	// fetch result to be dropped — turning ClearRegionRootCache into
	// an unintentional global invalidation.
	ClearRootCache()
	pki := newTestPKI(t)

	reqSeen := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			close(reqSeen)
			<-release
		}
		_, _ = w.Write(pki.rootPEM)
	}))
	defer srv.Close()

	doc := &IdentityDocument{LeafCert: pki.leafPEM, Intermediate: pki.intPEM}
	done := make(chan error, 1)
	go func() {
		_, err := VerifyIdentityDocument(context.Background(), doc, "us-phoenix-1", nil,
			WithFetchHTTPClient(srv.Client()),
			withRootBaseURL(srv.URL),
		)
		done <- err
	}()

	<-reqSeen
	// Clear a DIFFERENT region while the fetch for us-phoenix-1 is
	// still in flight. This must NOT invalidate the pending write.
	ClearRegionRootCache("us-ashburn-1")
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("verify during unrelated clear: %v", err)
	}

	// The pending fetch for us-phoenix-1 should have written its
	// pool back (unrelated clear was for us-ashburn-1). The next
	// verify should hit the cache and NOT touch the server.
	if _, err := VerifyIdentityDocument(context.Background(), doc, "us-phoenix-1", nil,
		WithFetchHTTPClient(srv.Client()),
		withRootBaseURL(srv.URL),
	); err != nil {
		t.Fatalf("post-clear verify: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("expected 1 upstream fetch (cached after first), got %d — unrelated ClearRegion invalidated us-phoenix-1", got)
	}
}

func TestRootCacheKeyNoCollisionOnSeparator(t *testing.T) {
	// Even if baseURLOverride contains arbitrary bytes, two different
	// (region, override) pairs must produce distinct cache entries.
	// The struct-keyed cache enforces this by type; this test pins
	// the property so a future refactor to string concatenation
	// doesn't silently reintroduce a collision.
	a := rootCacheKey{region: "us-ashburn-1", override: "http://a|http://b"}
	b := rootCacheKey{region: "us-ashburn-1|http://a", override: "http://b"}
	if a == b {
		t.Fatalf("distinct (region, override) pairs collided: %+v == %+v", a, b)
	}
	m := map[rootCacheKey]int{a: 1, b: 2}
	if len(m) != 2 {
		t.Errorf("expected 2 map entries, got %d", len(m))
	}
	if m[a] != 1 || m[b] != 2 {
		t.Errorf("map lookup mismatch: a=%d b=%d", m[a], m[b])
	}
}

func TestVerifyBadPEM(t *testing.T) {
	pki := newTestPKI(t)
	doc := &IdentityDocument{
		LeafCert:     []byte("not a pem"),
		Intermediate: pki.intPEM,
	}
	_, err := VerifyIdentityDocumentWithRoots(doc, pki.rootPool, nil)
	if err == nil {
		t.Fatal("expected parse error")
	}
}
