package awsimds

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"go.mozilla.org/pkcs7"
)

type Claims struct {
	InstanceID       string    `json:"instanceId"`
	AccountID        string    `json:"accountId"`
	Region           string    `json:"region"`
	AvailabilityZone string    `json:"availabilityZone"`
	InstanceType     string    `json:"instanceType"`
	ImageID          string    `json:"imageId"`
	Architecture     string    `json:"architecture"`
	PrivateIP        string    `json:"privateIp"`
	PendingTime      time.Time `json:"pendingTime"`
}

func (c *Client) GetPKCS7Signature(ctx context.Context) ([]byte, error) {
	b, err := c.getDynamicData(ctx, "instance-identity/pkcs7")
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(b), nil
}

func (c *Client) GetRSA2048Signature(ctx context.Context) ([]byte, error) {
	b, err := c.getDynamicData(ctx, "instance-identity/rsa2048")
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(b), nil
}

func (c *Client) GetSignature(ctx context.Context) ([]byte, error) {
	b, err := c.getDynamicData(ctx, "instance-identity/signature")
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(b), nil
}

// GetRawIdentityDocument returns the raw JSON bytes of the identity document
// exactly as returned by IMDS. These bytes must not be modified — RSA
// verification requires byte-for-byte equality with the signed payload.
func (c *Client) GetRawIdentityDocument(ctx context.Context) ([]byte, error) {
	return c.getDynamicData(ctx, "instance-identity/document")
}

func (c *Client) getDynamicData(ctx context.Context, path string) ([]byte, error) {
	out, err := c.sdk.GetDynamicData(ctx, &imds.GetDynamicDataInput{Path: path})
	if err != nil {
		return nil, err
	}
	defer out.Content.Close()
	return io.ReadAll(out.Content)
}

// VerifyPKCS7 verifies a PKCS7-signed identity document using baked-in DSA certificates.
// The document is embedded in the PKCS7 envelope.
func VerifyPKCS7(pkcs7B64 []byte) (*Claims, error) {
	certPool()
	return VerifyPKCS7WithCerts(pkcs7B64, dsaCertPool)
}

func VerifyPKCS7WithCerts(pkcs7B64 []byte, certs []*x509.Certificate) (*Claims, error) {
	raw := fmt.Sprintf("-----BEGIN PKCS7-----\n%s\n-----END PKCS7-----", pkcs7B64)
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("awsimds: failed to decode PKCS7 PEM")
	}

	p7, err := pkcs7.Parse(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("awsimds: failed to parse PKCS7: %w", err)
	}

	p7.Certificates = certs
	if err := p7.Verify(); err != nil {
		return nil, fmt.Errorf("awsimds: PKCS7 verification failed: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(p7.Content, &claims); err != nil {
		return nil, fmt.Errorf("awsimds: failed to parse identity document: %w", err)
	}
	return &claims, nil
}

// VerifyRSA verifies a detached RSA signature against the identity document.
// docBytes must be the raw JSON bytes from IMDS (use GetRawIdentityDocument).
// sigB64 is the base64-encoded signature from IMDS.
// Auto-detects RSA-1024 vs RSA-2048 from decoded signature size and selects
// the matching certificate pool.
func VerifyRSA(docBytes, sigB64 []byte) (*Claims, error) {
	sig, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(sigB64)))
	if err != nil {
		return nil, fmt.Errorf("awsimds: failed to base64 decode signature: %w", err)
	}
	certPool()
	var pool []*x509.Certificate
	switch len(sig) {
	case 256:
		pool = rsa2048CertPool
	case 128:
		pool = rsaCertPool
	default:
		return nil, fmt.Errorf("awsimds: unexpected signature length %d bytes", len(sig))
	}
	return verifyRSAraw(docBytes, sig, pool)
}

func VerifyRSAWithCerts(docBytes, sigB64 []byte, certs []*x509.Certificate) (*Claims, error) {
	sig, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(sigB64)))
	if err != nil {
		return nil, fmt.Errorf("awsimds: failed to base64 decode signature: %w", err)
	}
	return verifyRSAraw(docBytes, sig, certs)
}

func verifyRSAraw(docBytes, sig []byte, certs []*x509.Certificate) (*Claims, error) {
	var verified bool
	for _, cert := range certs {
		if cert.CheckSignature(x509.SHA256WithRSA, docBytes, sig) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("awsimds: RSA signature verification failed: no matching certificate")
	}

	var claims Claims
	if err := json.Unmarshal(docBytes, &claims); err != nil {
		return nil, fmt.Errorf("awsimds: failed to parse identity document: %w", err)
	}
	return &claims, nil
}
