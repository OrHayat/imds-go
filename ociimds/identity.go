package ociimds

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	certPath         = "identity/cert.pem"
	intermediatePath = "identity/intermediate.pem"
	keyPath          = "identity/key.pem"
)

// IdentityDocument is the bundle of material fetched from OCI IMDS that
// identifies this instance to a remote verifier.
//
// LeafCert and Intermediate are PEM-encoded X.509 certs. The leaf is
// issued by Oracle with tenancy/instance OCIDs embedded in the subject
// as custom attributes. The intermediate chains the leaf to a regional
// Oracle root CA (see Oracle's instance principal root CA endpoint).
//
// Nonce and Signature are populated only when GetIdentityDocument was
// called with WithNonce. Signature is an RSA PKCS1v15 SHA256 signature
// over Nonce, produced locally inside GetIdentityDocument using the
// key.pem fetched from IMDS. The private key is never retained on the
// Client; it's used transiently during GetIdentityDocument and
// discarded before the function returns.
type IdentityDocument struct {
	LeafCert     []byte
	Intermediate []byte
	Nonce        []byte
	Signature    []byte
}

type identityOptions struct {
	nonce []byte
}

// IdentityOption configures optional behavior on GetIdentityDocument.
type IdentityOption func(*identityOptions)

// WithNonce asks GetIdentityDocument to sign the given nonce bytes with
// the instance's IMDS-provided private key. The signature is returned
// in IdentityDocument.Signature and can be verified by a remote
// verifier via VerifyIdentityDocument with the same expectedNonce.
//
// The nonce MUST be chosen by the remote verifier and shipped to this
// instance out-of-band. If the instance picks its own nonce, the
// verifier has nothing to check against and replay protection is lost.
//
// The caller's slice is copied so that later mutation of the caller's
// buffer cannot change what gets signed or what ends up in
// IdentityDocument.Nonce.
func WithNonce(n []byte) IdentityOption {
	// Preserve the nil/empty distinction: append([]byte(nil), []byte{}...)
	// would collapse a non-nil empty input back to nil, which would then
	// skip signing in GetIdentityDocument's "o.nonce != nil" check.
	// make+copy keeps a non-nil zero-length slice non-nil.
	var copied []byte
	if n != nil {
		copied = make([]byte, len(n))
		copy(copied, n)
	}
	return func(o *identityOptions) { o.nonce = copied }
}

// GetIdentityDocument fetches the instance's leaf cert and intermediate
// from OCI IMDS. If WithNonce is supplied, it additionally fetches the
// private key and signs the nonce with it. The private key is NOT
// retained after this call returns.
func (c *Client) GetIdentityDocument(ctx context.Context, opts ...IdentityOption) (*IdentityDocument, error) {
	o := identityOptions{}
	for _, fn := range opts {
		fn(&o)
	}

	leaf, err := c.http.Get(ctx, certPath)
	if err != nil {
		return nil, fmt.Errorf("ociimds: fetch leaf cert: %w", err)
	}
	intermediate, err := c.http.Get(ctx, intermediatePath)
	if err != nil {
		return nil, fmt.Errorf("ociimds: fetch intermediate cert: %w", err)
	}

	doc := &IdentityDocument{
		LeafCert:     leaf,
		Intermediate: intermediate,
	}

	// Treat a non-nil nonce as a request to sign, even if it's empty.
	// An empty-but-present nonce is still a well-defined signature input
	// (SHA256 of zero bytes), and using "o.nonce != nil" keeps the
	// client-side "is a signature being produced" check aligned with
	// the verifier-side "is expectedNonce non-nil" check.
	if o.nonce != nil {
		keyPEM, err := c.http.Get(ctx, keyPath)
		if err != nil {
			return nil, fmt.Errorf("ociimds: fetch private key: %w", err)
		}
		sig, err := signNonce(keyPEM, o.nonce)
		if err != nil {
			return nil, err
		}
		// Same preserve-empty trick as WithNonce: an empty-but-present
		// nonce must round-trip as doc.Nonce == []byte{} (len 0, non-nil),
		// not doc.Nonce == nil, so downstream code can distinguish "a
		// signature was produced" from "no nonce was ever passed."
		doc.Nonce = make([]byte, len(o.nonce))
		copy(doc.Nonce, o.nonce)
		doc.Signature = sig
	}

	return doc, nil
}

func signNonce(keyPEM, nonce []byte) ([]byte, error) {
	// Reject leading non-PEM content, matching parsePEMCert's stance
	// in verify.go. pem.Decode silently skips bytes before the first
	// "-----BEGIN" marker, so without this check a crafted IMDS
	// response could smuggle attacker-chosen prefix bytes past the
	// parser. Leading whitespace is tolerated.
	trimmed := bytes.TrimLeft(keyPEM, " \t\r\n")
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		return nil, fmt.Errorf("ociimds: key.pem has unexpected leading content before PEM block")
	}
	block, rest := pem.Decode(trimmed)
	if block == nil {
		return nil, fmt.Errorf("ociimds: key.pem is not PEM-encoded")
	}
	// Reject any trailing PEM content, matching parsePEMCert's stance
	// in verify.go. A crafted IMDS response with a benign-looking
	// first private key block followed by attacker-chosen trailing
	// content should fail closed. Trailing whitespace is tolerated.
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, fmt.Errorf("ociimds: unexpected trailing content after private key PEM block")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ociimds: parse PKCS1 key: %w", err)
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ociimds: parse PKCS8 key: %w", err)
		}
		var ok bool
		key, ok = k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ociimds: key is not an RSA private key")
		}
	default:
		return nil, fmt.Errorf("ociimds: unexpected PEM type %q", block.Type)
	}

	hash := sha256.Sum256(nonce)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ociimds: sign nonce: %w", err)
	}
	return sig, nil
}
