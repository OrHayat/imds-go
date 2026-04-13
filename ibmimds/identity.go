package ibmimds

import (
	"context"
	"fmt"
)

type identityOptions struct {
	expiresIn int
}

// IdentityOption configures GetIdentityToken.
type IdentityOption func(*identityOptions)

// WithExpiresIn sets how long the instance identity token should be
// valid, in seconds. Defaults to tokenTTL (3600). IBM caps the value
// at 3600; anything higher is silently clamped by the metadata
// service. Values ≤ 0 are rejected.
func WithExpiresIn(seconds int) IdentityOption {
	return func(o *identityOptions) { o.expiresIn = seconds }
}

// GetIdentityToken fetches a signed instance identity token from the
// IBM Cloud VPC metadata service. The returned value is a raw JWT
// (also called a "CR-token" in IBM docs — compute resource token),
// not the internal "Bearer " wrapped form the client uses for
// metadata API calls.
//
// The CR-token is NOT an IBM IAM access token. It is a short-lived
// credential issued by the VPC metadata service that must be
// exchanged at https://iam.cloud.ibm.com/identity/token for an IAM
// token bound to a trusted profile. VerifyIdentityToken handles the
// exchange and surfaces the resulting IAM claims.
//
// Unlike GCP identity tokens, IBM's CR-token has no caller-supplied
// audience parameter — it identifies the instance, and scoping is
// done at exchange time via the trusted profile binding. Layer
// replay protection at the application level if required.
func (c *Client) GetIdentityToken(ctx context.Context, opts ...IdentityOption) (string, error) {
	o := identityOptions{expiresIn: tokenTTL}
	for _, fn := range opts {
		fn(&o)
	}
	if o.expiresIn <= 0 {
		return "", fmt.Errorf("ibmimds: WithExpiresIn must be positive, got %d", o.expiresIn)
	}
	return c.tokenSrc.fetchToken(ctx, o.expiresIn)
}
