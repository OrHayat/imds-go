package awsimds

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

func TestGetPKCS7Signature(t *testing.T) {
	routes := fullRoutes()
	routes["/latest/dynamic/instance-identity/pkcs7"] = "dGVzdC1wa2NzNy1zaWduYXR1cmU="
	c := newTestClient(t, routes)

	sig, err := c.GetPKCS7Signature(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if string(sig) != "dGVzdC1wa2NzNy1zaWduYXR1cmU=" {
		t.Fatalf("got %q", string(sig))
	}
}

func TestGetRSA2048Signature(t *testing.T) {
	routes := fullRoutes()
	routes["/latest/dynamic/instance-identity/rsa2048"] = "dGVzdC1yc2EyMDQ4LXNpZw=="
	c := newTestClient(t, routes)

	sig, err := c.GetRSA2048Signature(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if string(sig) != "dGVzdC1yc2EyMDQ4LXNpZw==" {
		t.Fatalf("got %q", string(sig))
	}
}

func TestGetSignature(t *testing.T) {
	routes := fullRoutes()
	routes["/latest/dynamic/instance-identity/signature"] = "dGVzdC1zaWduYXR1cmU="
	c := newTestClient(t, routes)

	sig, err := c.GetSignature(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if string(sig) != "dGVzdC1zaWduYXR1cmU=" {
		t.Fatalf("got %q", string(sig))
	}
}

func TestGetRawIdentityDocument(t *testing.T) {
	routes := fullRoutes()
	routes["/latest/dynamic/instance-identity/document"] = `{"instanceId":"i-abc123","region":"us-east-1"}`
	c := newTestClient(t, routes)

	doc, err := c.GetRawIdentityDocument(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if string(doc) != `{"instanceId":"i-abc123","region":"us-east-1"}` {
		t.Fatalf("got %q", string(doc))
	}
}

func TestGetDynamicDataTrimsWhitespace(t *testing.T) {
	routes := fullRoutes()
	routes["/latest/dynamic/instance-identity/pkcs7"] = "  some-data\n\n"
	c := newTestClient(t, routes)

	data, err := c.GetPKCS7Signature(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "some-data" {
		t.Fatalf("expected trimmed, got %q", string(data))
	}
}

func TestGetDynamicData404(t *testing.T) {
	c := newTestClient(t, fullRoutes())
	_, err := c.GetPKCS7Signature(t.Context())
	if err == nil {
		t.Fatal("expected error for missing dynamic data")
	}
}

func TestVerifyPKCS7InvalidInput(t *testing.T) {
	_, err := VerifyPKCS7([]byte("not-valid-pkcs7"))
	if err == nil {
		t.Fatal("expected error for invalid PKCS7")
	}
}

func TestVerifyRSAUnexpectedSignatureLength(t *testing.T) {
	doc := []byte(`{"instanceId":"i-123"}`)
	_, err := VerifyRSA(doc, []byte("AQID")) // 3 bytes decoded
	if err == nil {
		t.Fatal("expected error for unexpected signature length")
	}
}

func TestVerifyRSANoMatchingCert(t *testing.T) {
	doc := []byte(`{"instanceId":"i-123"}`)
	// 256 bytes decoded = RSA-2048 size, but won't match any cert
	fakeSig := make([]byte, 256)
	sigB64 := base64.StdEncoding.EncodeToString(fakeSig)
	_, err := VerifyRSA(doc, []byte(sigB64))
	if err == nil {
		t.Fatal("expected error for no matching certificate")
	}
}

func TestVerifyRSAWithCertsPositive(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Test"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	doc, _ := json.Marshal(Claims{
		InstanceID: "i-test123",
		AccountID:  "999999999999",
		Region:     "us-test-1",
	})

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sha256Hash(doc))
	if err != nil {
		t.Fatal(err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	claims, err := VerifyRSAWithCerts(doc, []byte(sigB64), []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	if claims.InstanceID != "i-test123" {
		t.Fatalf("instance id = %q", claims.InstanceID)
	}
	if claims.AccountID != "999999999999" {
		t.Fatalf("account id = %q", claims.AccountID)
	}
	if claims.Region != "us-test-1" {
		t.Fatalf("region = %q", claims.Region)
	}
}

func sha256Hash(data []byte) []byte {
	h := crypto.SHA256.New()
	h.Write(data)
	return h.Sum(nil)
}

func TestCertPoolLoaded(t *testing.T) {
	pool := certPool()
	if len(pool) == 0 {
		t.Fatal("expected certs to be loaded")
	}
}

func TestCertMapsHaveAllRegions(t *testing.T) {
	for region := range dsaCerts {
		if _, ok := rsaCerts[region]; !ok {
			t.Fatalf("region %s missing from rsaCerts", region)
		}
		if _, ok := rsa2048Certs[region]; !ok {
			t.Fatalf("region %s missing from rsa2048Certs", region)
		}
	}
	for region := range rsaCerts {
		if _, ok := dsaCerts[region]; !ok {
			t.Fatalf("region %s missing from dsaCerts", region)
		}
	}
	for region := range rsa2048Certs {
		if _, ok := dsaCerts[region]; !ok {
			t.Fatalf("region %s missing from dsaCerts", region)
		}
	}
}

func TestImdsHandlerDynamicData(t *testing.T) {
	routes := fullRoutes()
	routes["/latest/dynamic/instance-identity/pkcs7"] = "test-sig"

	ts := fakeIMDS(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
			w.Write([]byte(testToken))
			return
		}
		if v, ok := routes[r.URL.Path]; ok {
			w.Write([]byte(v))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	c := New(imds.Options{}, func(o *imds.Options) {
		o.Endpoint = ts.URL
	})
	sig, err := c.GetPKCS7Signature(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if string(sig) != "test-sig" {
		t.Fatalf("got %q", string(sig))
	}
}
