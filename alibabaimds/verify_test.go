package alibabaimds

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
)

// testFixture bundles a throwaway CA + leaf certificate and a signing
// helper that produces detached PKCS7 blobs like Alibaba's IMDS does.
type testFixture struct {
	root     *x509.Certificate
	rootKey  *rsa.PrivateKey
	leaf     *x509.Certificate
	leafKey  *rsa.PrivateKey
	leafCert *x509.Certificate // alias for convenience in assertions
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root", Organization: []string{"alibabaimds-test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-leaf", Organization: []string{"alibabaimds-test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return &testFixture{
		root:     root,
		rootKey:  rootKey,
		leaf:     leaf,
		leafKey:  leafKey,
		leafCert: leaf,
	}
}

// signDetached produces a PEM-encoded detached PKCS7 signature over
// content, signed by the fixture's leaf cert. Mirrors Alibaba's IMDS
// output format.
func (f *testFixture) signDetached(t *testing.T, content []byte) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.AddSignerChain(f.leaf, f.leafKey, []*x509.Certificate{f.root}, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	sd.Detach()
	der, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: der})
}

const testDocument = `{"owner-account-id":"1234567890","instance-id":"i-abc123","mac":"00:11:22:33:44:55","region-id":"cn-hangzhou","serial-number":"sn-xyz","zone-id":"cn-hangzhou-a","instance-type":"ecs.g6.large","image-id":"img-42","private-ipv4":"10.0.0.42","audience":"test-aud"}`

func TestVerifyIdentityWithCertsPositive(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)
	sig := f.signDetached(t, doc)

	claims, err := VerifyIdentityWithCerts(doc, sig, "test-aud", []*x509.Certificate{f.leaf})
	if err != nil {
		t.Fatal(err)
	}
	if claims.InstanceID != "i-abc123" {
		t.Errorf("InstanceID = %q", claims.InstanceID)
	}
	if claims.OwnerAccountID != "1234567890" {
		t.Errorf("OwnerAccountID = %q", claims.OwnerAccountID)
	}
	if claims.MAC != "00:11:22:33:44:55" {
		t.Errorf("MAC = %q", claims.MAC)
	}
	if claims.RegionID != "cn-hangzhou" {
		t.Errorf("RegionID = %q", claims.RegionID)
	}
	if claims.SerialNumber != "sn-xyz" {
		t.Errorf("SerialNumber = %q", claims.SerialNumber)
	}
	if claims.ZoneID != "cn-hangzhou-a" {
		t.Errorf("ZoneID = %q", claims.ZoneID)
	}
	if claims.InstanceType != "ecs.g6.large" {
		t.Errorf("InstanceType = %q", claims.InstanceType)
	}
	if claims.ImageID != "img-42" {
		t.Errorf("ImageID = %q", claims.ImageID)
	}
	if claims.PrivateIPv4 != "10.0.0.42" {
		t.Errorf("PrivateIPv4 = %q", claims.PrivateIPv4)
	}
	if claims.Audience != "test-aud" {
		t.Errorf("Audience = %q", claims.Audience)
	}
}

func TestVerifyIdentityWithCertsNoAudienceCheck(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)
	sig := f.signDetached(t, doc)

	// Empty expectedAudience must skip the audience comparison but
	// still return the signed Audience value in Claims.
	claims, err := VerifyIdentityWithCerts(doc, sig, "", []*x509.Certificate{f.leaf})
	if err != nil {
		t.Fatal(err)
	}
	if claims.Audience != "test-aud" {
		t.Errorf("Audience = %q", claims.Audience)
	}
}

func TestVerifyIdentityAudienceMismatch(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)
	sig := f.signDetached(t, doc)

	_, err := VerifyIdentityWithCerts(doc, sig, "wrong-aud", []*x509.Certificate{f.leaf})
	if err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestVerifyIdentityTamperedDocument(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)
	sig := f.signDetached(t, doc)

	tampered := append([]byte{}, doc...)
	tampered[len(tampered)-3] = 'Z' // flip a byte inside the JSON

	_, err := VerifyIdentityWithCerts(tampered, sig, "", []*x509.Certificate{f.leaf})
	if err == nil {
		t.Fatal("expected signature verification to fail on tampered document")
	}
}

func TestVerifyIdentityWrongTrustedCerts(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)
	sig := f.signDetached(t, doc)

	// A fresh fixture whose leaf will not match the signer.
	other := newTestFixture(t)

	_, err := VerifyIdentityWithCerts(doc, sig, "", []*x509.Certificate{other.leaf})
	if err == nil {
		t.Fatal("expected verification failure with wrong trusted certs")
	}
}

func TestVerifyIdentityMalformedPKCS7(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)

	// Garbage bytes wrapped in a PKCS7 PEM block.
	bad := pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: []byte("not-a-pkcs7-blob")})
	_, err := VerifyIdentityWithCerts(doc, bad, "", []*x509.Certificate{f.leaf})
	if err == nil {
		t.Fatal("expected error parsing malformed PKCS7")
	}
}

func TestVerifyIdentityNotPEM(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)
	_, err := VerifyIdentityWithCerts(doc, []byte("definitely not pem"), "", []*x509.Certificate{f.leaf})
	if err == nil {
		t.Fatal("expected error for non-PEM signature")
	}
}

func TestVerifyIdentityRejectsEmptyCerts(t *testing.T) {
	doc := []byte(testDocument)
	_, err := VerifyIdentityWithCerts(doc, []byte("irrelevant"), "", nil)
	if err == nil {
		t.Fatal("expected rejection for nil certs slice")
	}
	if !strings.Contains(err.Error(), "certs slice is empty") {
		t.Errorf("err = %v, want empty-slice rejection", err)
	}
	_, err = VerifyIdentityWithCerts(doc, []byte("irrelevant"), "", []*x509.Certificate{})
	if err == nil {
		t.Fatal("expected rejection for empty certs slice")
	}
}

func TestVerifyIdentityRejectsNilCertEntry(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)
	// Sparse slice: a valid cert followed by a nil entry. Without
	// the upfront guard this would panic when the signer-match loop
	// dereferences the nil entry's Raw field.
	certs := []*x509.Certificate{f.leaf, nil}
	_, err := VerifyIdentityWithCerts(doc, []byte("irrelevant"), "", certs)
	if err == nil {
		t.Fatal("expected rejection for nil cert entry")
	}
	if !strings.Contains(err.Error(), "certs[1] is nil") {
		t.Errorf("err = %v, want certs[1]-is-nil rejection", err)
	}
}

func TestVerifyIdentityRejectsWrongPEMType(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)
	// A well-formed CERTIFICATE PEM block instead of a PKCS7 block.
	// Must be rejected up front with a clear error, not passed to
	// pkcs7.Parse which would surface a cryptic asn1 error.
	wrongType := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.leaf.Raw})
	_, err := VerifyIdentityWithCerts(doc, wrongType, "", []*x509.Certificate{f.leaf})
	if err == nil {
		t.Fatal("expected rejection for wrong PEM block type")
	}
	if !strings.Contains(err.Error(), `want "PKCS7"`) {
		t.Errorf("err = %v, want PKCS7 block-type rejection", err)
	}
}

func TestVerifyIdentityRejectsTrailingPEMContent(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)
	sig := f.signDetached(t, doc)
	// Append a second, unrelated PEM block to the signature. A well-
	// formed PKCS7 block up front followed by attacker-chosen trailing
	// content must be rejected rather than silently ignored.
	trailing := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.leaf.Raw})
	bundle := append(append([]byte{}, sig...), trailing...)
	_, err := VerifyIdentityWithCerts(doc, bundle, "", []*x509.Certificate{f.leaf})
	if err == nil {
		t.Fatal("expected rejection for trailing content")
	}
	if !strings.Contains(err.Error(), "trailing content") {
		t.Errorf("err = %v, want trailing-content rejection", err)
	}
}

func TestVerifyIdentityRejectsLeadingContent(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)
	sig := f.signDetached(t, doc)
	// Prepend attacker-chosen garbage before the PEM block. pem.Decode
	// would silently skip this; the strict check rejects it.
	bundle := append([]byte("evil-prefix\n"), sig...)
	_, err := VerifyIdentityWithCerts(doc, bundle, "", []*x509.Certificate{f.leaf})
	if err == nil {
		t.Fatal("expected rejection for leading non-PEM content")
	}
	if !strings.Contains(err.Error(), "leading content") {
		t.Errorf("err = %v, want leading-content rejection", err)
	}
}

func TestVerifyIdentityAcceptsLeadingWhitespace(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)
	sig := f.signDetached(t, doc)
	// Leading whitespace (newlines, tabs) is tolerated — real
	// servers may prepend whitespace and we don't want to fail on it.
	bundle := append([]byte("  \n\t"), sig...)
	if _, err := VerifyIdentityWithCerts(doc, bundle, "", []*x509.Certificate{f.leaf}); err != nil {
		t.Fatalf("verify with leading whitespace: %v", err)
	}
}

func TestVerifyIdentityAcceptsTrailingWhitespace(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)
	// Trailing newline after the PEM block is tolerated — real
	// Alibaba responses may end with one and we don't want to fail
	// on whitespace.
	sig := append(f.signDetached(t, doc), '\n')
	if _, err := VerifyIdentityWithCerts(doc, sig, "", []*x509.Certificate{f.leaf}); err != nil {
		t.Fatalf("verify with trailing newline: %v", err)
	}
}

func TestLoadAlibabaCertBakedIn(t *testing.T) {
	certs, err := loadAlibabaCert()
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
	c := certs[0]
	// Pin the exact serial, validity window, and key size. This is a
	// sanity check against accidental cert replacement/corruption in
	// future edits to certs.go — any change to those values should
	// force an intentional test update rather than silently passing.
	const (
		wantSerial    = "1718014343"
		wantNotBefore = "2018-02-23T01:29:38Z"
		wantNotAfter  = "2038-02-18T01:29:38Z"
	)
	if got := c.SerialNumber.String(); got != wantSerial {
		t.Errorf("SerialNumber = %s, want %s", got, wantSerial)
	}
	if got := c.NotBefore.UTC().Format(time.RFC3339); got != wantNotBefore {
		t.Errorf("NotBefore = %s, want %s", got, wantNotBefore)
	}
	if got := c.NotAfter.UTC().Format(time.RFC3339); got != wantNotAfter {
		t.Errorf("NotAfter = %s, want %s", got, wantNotAfter)
	}
	// And a sanity warning if the NotAfter ever slips into the past,
	// to catch long-lived cert expiry.
	if c.NotAfter.Before(time.Now()) {
		t.Errorf("baked-in cert is expired: NotAfter=%s", c.NotAfter)
	}
	pub, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Errorf("baked-in cert public key is not RSA: %T", c.PublicKey)
	} else if bits := pub.N.BitLen(); bits != 2048 {
		t.Errorf("baked-in cert public key size = %d bits, want 2048", bits)
	}
}

// TestGetIdentityEndToEnd exercises both endpoints and asserts the
// query-passthrough behavior of WithAudience.
func TestGetIdentityEndToEnd(t *testing.T) {
	f := newTestFixture(t)
	doc := []byte(testDocument)
	sig := f.signDetached(t, doc)

	// gotAudience is written by the httptest server goroutine and
	// read by the main test goroutine; guard with a mutex so
	// `go test -race` stays clean.
	var (
		audienceMu  sync.Mutex
		gotAudience string
	)
	setAudience := func(s string) {
		audienceMu.Lock()
		defer audienceMu.Unlock()
		gotAudience = s
	}
	readAudience := func() string {
		audienceMu.Lock()
		defer audienceMu.Unlock()
		return gotAudience
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case identityDocumentPath:
			_, _ = w.Write(doc)
		case identitySignaturePath:
			setAudience(r.URL.Query().Get("audience"))
			_, _ = w.Write(sig)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	// Document-only fetch.
	gotDoc, err := c.GetIdentityDocument(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if string(gotDoc) != string(doc) {
		t.Fatalf("document mismatch: got %q", string(gotDoc))
	}

	// Signature fetch without audience — query param absent.
	if _, err := c.GetIdentitySignature(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := readAudience(); got != "" {
		t.Errorf("unexpected audience %q on plain signature fetch", got)
	}

	// Signature fetch with audience — query passthrough.
	if _, err := c.GetIdentitySignature(t.Context(), WithAudience("abc123")); err != nil {
		t.Fatal(err)
	}
	if got := readAudience(); got != "abc123" {
		t.Errorf("audience query = %q, want %q", got, "abc123")
	}

	// GetAttestedIdentity convenience wraps both fetches.
	att, err := c.GetAttestedIdentity(t.Context(), WithAudience("abc123"))
	if err != nil {
		t.Fatal(err)
	}
	if att.Audience != "abc123" {
		t.Errorf("attested audience = %q", att.Audience)
	}
	if string(att.Document) != string(doc) {
		t.Error("attested document mismatch")
	}
	if string(att.Signature) != string(sig) {
		t.Error("attested signature mismatch")
	}
}

// TestVerifyIdentityEnforcesRequestedAudience covers the security
// property the fake-server test can't reach by itself: when the fake
// signature endpoint actually signs a document whose audience field
// equals the caller-supplied query parameter, VerifyIdentity must
// accept the bundle iff the verifier's expectedAudience matches, and
// reject it otherwise. This is the end-to-end "what you asked to be
// signed is what gets enforced" check.
func TestVerifyIdentityEnforcesRequestedAudience(t *testing.T) {
	f := newTestFixture(t)
	// docFor returns a JSON document whose embedded audience field
	// equals the requested value — mimics Alibaba's real behavior where
	// the audience query on the signature endpoint makes its way into
	// the signed payload.
	docFor := func(audience string) []byte {
		return fmt.Appendf(nil, `{"owner-account-id":"1234567890","instance-id":"i-abc123","mac":"00:11:22:33:44:55","region-id":"cn-hangzhou","serial-number":"sn-xyz","zone-id":"cn-hangzhou-a","instance-type":"ecs.g6.large","image-id":"img-42","private-ipv4":"10.0.0.42","audience":%q}`, audience)
	}

	requested := "verifier-nonce-42"
	requestedDoc := docFor(requested)
	requestedSig := f.signDetached(t, requestedDoc)

	// Match: verifier's expectedAudience == what was signed.
	claims, err := VerifyIdentityWithCerts(requestedDoc, requestedSig, requested, []*x509.Certificate{f.leaf})
	if err != nil {
		t.Fatalf("verify with matching audience: %v", err)
	}
	if claims.Audience != requested {
		t.Errorf("claims.Audience = %q, want %q", claims.Audience, requested)
	}
	if claims.InstanceID != "i-abc123" {
		t.Errorf("claims.InstanceID = %q", claims.InstanceID)
	}

	// Mismatch: verifier expected something else, must fail.
	if _, err := VerifyIdentityWithCerts(requestedDoc, requestedSig, "someone-else", []*x509.Certificate{f.leaf}); err == nil {
		t.Error("expected audience mismatch error")
	}
}

func TestGetIdentityDocumentError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetIdentityDocument(t.Context())
	if err == nil {
		t.Fatal("expected error on 500")
	}
}

// Ensure we exercise the "signature fetch errors after document
// succeeds" branch in GetAttestedIdentity.
func TestGetAttestedIdentitySignatureError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == identityDocumentPath {
			_, _ = fmt.Fprint(w, testDocument)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetAttestedIdentity(t.Context())
	if err == nil {
		t.Fatal("expected signature fetch error")
	}
}
