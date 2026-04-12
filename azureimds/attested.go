package azureimds

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
)

const attestedPath = "/metadata/attested/document"
const attestedAPIVersion = "2025-04-07"

// AttestedDocument is the raw attested document fetched from Azure IMDS.
type AttestedDocument struct {
	Encoding  string // always "pkcs7"
	Signature []byte // decoded DER PKCS7 bytes
	Nonce     string // the nonce that was sent in the request (may be empty)
}

type attestedOptions struct {
	nonce string
}

type AttestedOption func(*attestedOptions)

// WithNonce supplies a nonce that Azure echoes back inside the signed
// attested document.
//
// The nonce field is ONLY useful in a challenge-response flow where a
// remote verifier picks the nonce, ships it to this instance out-of-band,
// the instance passes it here via WithNonce, and the verifier then
// asserts the same value on VerifyAttestedDocument.
//
// In a pure push flow (instance fetches a doc and sends it to a verifier
// that had no prior say in the exchange) the nonce provides no replay
// protection — the verifier has no pre-committed value to compare
// against. For push flows prefer one of:
//
//  1. Rely on Azure's built-in ~5 minute expiresOn window.
//  2. One-time-use enforcement on the verifier (TOFU by signed-doc hash,
//     the pattern HashiCorp Vault uses for AWS instance identity).
//  3. Bind the signed doc to a transport-layer secret (mTLS).
//
// Microsoft documents the nonce as a "10-digit string" but their own
// sample values exceed that (e.g. "20201130-211924"). This library does
// not validate the nonce format; pass through whatever the verifier
// handed you and let Azure accept or reject it.
func WithNonce(n string) AttestedOption {
	return func(o *attestedOptions) { o.nonce = n }
}

// GetAttestedDocument fetches and base64-decodes the signed attestation blob.
// The returned Signature is the raw DER PKCS7; pass it to VerifyAttestedDocument.
func (c *Client) GetAttestedDocument(ctx context.Context, opts ...AttestedOption) (*AttestedDocument, error) {
	o := attestedOptions{}
	for _, fn := range opts {
		fn(&o)
	}

	q := url.Values{"api-version": {attestedAPIVersion}}
	if o.nonce != "" {
		q.Set("nonce", o.nonce)
	}
	body, err := c.http.GetWithQuery(ctx, attestedPath, q)
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Encoding  string `json:"encoding"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("azureimds: parse attested envelope: %w", err)
	}
	if envelope.Encoding != "pkcs7" {
		return nil, fmt.Errorf("azureimds: unexpected attested encoding %q, want pkcs7", envelope.Encoding)
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return nil, fmt.Errorf("azureimds: decode attested signature: %w", err)
	}
	return &AttestedDocument{
		Encoding:  envelope.Encoding,
		Signature: sig,
		Nonce:     o.nonce,
	}, nil
}
