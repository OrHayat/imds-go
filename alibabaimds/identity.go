package alibabaimds

import (
	"context"
	"net/url"
)

const (
	identityDocumentPath  = "/latest/dynamic/instance-identity/document"
	identitySignaturePath = "/latest/dynamic/instance-identity/pkcs7"
)

type identityOptions struct {
	audience string
}

type IdentityOption func(*identityOptions)

// WithAudience supplies an audience string that Alibaba echoes back
// inside the signed PKCS7 payload. Functionally equivalent to Azure's
// attested-document nonce: the verifier picks a fresh random value,
// ships it to the instance out-of-band, the instance passes it here,
// and the verifier asserts the same value via VerifyIdentity's
// expectedAudience parameter.
//
// Only provides replay protection in a challenge-response flow where
// the verifier is the one choosing the value. In a push flow (the
// instance fetches the doc and sends it unsolicited to a verifier),
// the audience field is cosmetic — the verifier has no pre-committed
// value to compare against.
func WithAudience(a string) IdentityOption {
	return func(o *identityOptions) { o.audience = a }
}

// AttestedIdentity bundles the raw JSON document and its detached
// PKCS7 signature. Callers ship both to a remote verifier.
type AttestedIdentity struct {
	Document  []byte // raw bytes — DO NOT modify, PKCS7 verification is byte-for-byte
	Signature []byte // PEM-encoded PKCS7
	Audience  string // what was passed to WithAudience, may be empty
}

// GetIdentityDocument fetches the JSON instance-identity document.
// Returns the raw bytes exactly as served by IMDS; these must not be
// trimmed or re-encoded because the PKCS7 signature is byte-for-byte
// over this exact content.
func (c *Client) GetIdentityDocument(ctx context.Context) ([]byte, error) {
	return c.http.Get(ctx, identityDocumentPath)
}

// GetIdentitySignature fetches the PEM-encoded PKCS7 signature over
// the identity document. If WithAudience was supplied, the signature
// is bound to that audience (Alibaba includes it inside the signed
// content).
func (c *Client) GetIdentitySignature(ctx context.Context, opts ...IdentityOption) ([]byte, error) {
	o := identityOptions{}
	for _, fn := range opts {
		fn(&o)
	}
	if o.audience == "" {
		return c.http.Get(ctx, identitySignaturePath)
	}
	return c.http.GetWithQuery(ctx, identitySignaturePath, url.Values{"audience": {o.audience}})
}

// GetAttestedIdentity is a convenience that fetches both the document
// and the signature in one call and returns them paired. The document
// is fetched first, then the signature — both must succeed.
func (c *Client) GetAttestedIdentity(ctx context.Context, opts ...IdentityOption) (*AttestedIdentity, error) {
	o := identityOptions{}
	for _, fn := range opts {
		fn(&o)
	}
	doc, err := c.GetIdentityDocument(ctx)
	if err != nil {
		return nil, err
	}
	sig, err := c.GetIdentitySignature(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &AttestedIdentity{
		Document:  doc,
		Signature: sig,
		Audience:  o.audience,
	}, nil
}
