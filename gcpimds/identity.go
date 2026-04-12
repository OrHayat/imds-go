package gcpimds

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

const identityPath = "/computeMetadata/v1/instance/service-accounts/default/identity"

// Format controls how much detail GCP includes in the identity token payload.
type Format string

const (
	// FormatStandard returns only the minimal OIDC-compliant claims
	// (iss, sub, aud, exp, iat, email, email_verified, azp).
	FormatStandard Format = "standard"
	// FormatFull adds google.compute_engine.{instance_id, instance_name,
	// project_id, project_number, zone} and related claims.
	FormatFull Format = "full"
)

type identityOptions struct {
	format          Format
	includeLicenses bool
}

type IdentityOption func(*identityOptions)

// WithFormat selects the JWT payload verbosity. Defaults to FormatStandard
// if not set.
func WithFormat(f Format) IdentityOption {
	return func(o *identityOptions) { o.format = f }
}

// WithIncludeLicenses asks GCP to include image license codes in the JWT
// payload. Requires WithFormat(FormatFull); GetIdentityToken returns an
// error if this option is used under any other format. This is a
// marker option — it takes no arguments, and the verbose claims ride
// along on the returned Claims.LicenseIDs field.
func WithIncludeLicenses() IdentityOption {
	return func(o *identityOptions) { o.includeLicenses = true }
}

// GetIdentityToken fetches a signed JWT identifying this GCE instance.
//
// audience is REQUIRED and identifies the service the token is intended
// for. It becomes the "aud" claim in the JWT. Verifiers MUST reject
// tokens whose audience does not match their own expected value; this
// prevents a token issued for service A from being used against
// service B.
//
// audience is NOT a nonce. It does not provide replay protection within
// a single audience — a stolen token can be replayed against the
// intended service until it expires (~1 hour). Layer additional replay
// protection (application nonces, mTLS binding, one-time-use tracking)
// if that's a concern.
//
// Returns the raw JWT string ready to send to a verifier.
func (c *Client) GetIdentityToken(ctx context.Context, audience string, opts ...IdentityOption) (string, error) {
	if audience == "" {
		return "", fmt.Errorf("gcpimds: audience is required")
	}
	var o identityOptions
	for _, fn := range opts {
		fn(&o)
	}

	q := url.Values{"audience": {audience}}
	switch o.format {
	case "":
		// Caller omitted WithFormat. Leave the query param unset so GCE
		// applies its documented default (standard).
	case FormatStandard, FormatFull:
		q.Set("format", string(o.format))
	default:
		return "", fmt.Errorf("gcpimds: invalid format %q; allowed values are %q or %q",
			o.format, FormatStandard, FormatFull)
	}
	if o.includeLicenses {
		if o.format != FormatFull {
			return "", fmt.Errorf("gcpimds: WithIncludeLicenses requires WithFormat(FormatFull)")
		}
		q.Set("licenses", "TRUE")
	}

	body, err := c.http.GetWithQuery(ctx, identityPath, q)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}
