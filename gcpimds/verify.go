// Package gcpimds is the Google Cloud GCE Instance Metadata Service
// provider for github.com/OrHayat/imds-go. It offers a client for
// fetching instance metadata, retrieving signed OIDC-style identity
// tokens, and standalone verification helpers that validate those
// tokens against Google's public keys.
//
// The identity workflow is: GetIdentityToken fetches a JWT bound to a
// caller-supplied audience from the GCE metadata server;
// VerifyIdentityToken (or VerifyIdentityTokenWithCertsURL for hermetic
// tests pointing at a fake JWKS endpoint) delegates signature, issuer,
// and expiry validation to google.golang.org/api/idtoken and returns
// typed Claims describing the VM.
package gcpimds

import (
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
)

// certsFetchTimeout bounds a single JWKS fetch in VerifyIdentityTokenWithCertsURL.
// Callers should still propagate their own ctx deadline for end-to-end budgeting;
// this Timeout is a safety net against stalled endpoints for callers that don't.
const certsFetchTimeout = 30 * time.Second

// googleSACertsURL is the production JWKS endpoint that
// google.golang.org/api/idtoken hardcodes. certsRewriteTransport
// matches against this URL (by scheme+host+path, not by exact string)
// and rewrites matching requests to a caller-supplied target when
// VerifyIdentityTokenWithCertsURL is used.
const googleSACertsURL = "https://www.googleapis.com/oauth2/v3/certs"

// googleSACertsParsed is the pre-parsed form of googleSACertsURL.
// certsRewriteTransport compares req.URL.Scheme, Host, and Path
// against these components rather than doing an exact string compare,
// so trailing-slash or normalization differences in how idtoken builds
// the request don't accidentally skip the rewrite.
var googleSACertsParsed = mustParseURL(googleSACertsURL)

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(fmt.Sprintf("gcpimds: parse %q: %v", s, err))
	}
	return u
}

// Claims holds the verified fields from a GCP identity token.
type Claims struct {
	// Standard OIDC claims
	Audience string
	Issuer   string
	Subject  string
	// Email is the email claim from the JWT. Its authenticity is
	// meaningful ONLY if EmailVerified is true — callers must not treat
	// Email as an authenticated identifier unless they've checked
	// EmailVerified as well.
	Email         string
	EmailVerified bool
	IssuedAt      time.Time
	Expires       time.Time

	// google.compute_engine claims (only populated when FormatFull was
	// requested when the token was issued).
	InstanceID    string
	InstanceName  string
	ProjectID     string
	ProjectNumber int64
	Zone          string
	// LicenseIDs is the list of image license codes, populated only when
	// the token was fetched with WithFormat(FormatFull) AND
	// WithIncludeLicenses().
	LicenseIDs []string
}

// VerifyIdentityToken validates a GCP identity token against Google's
// public keys using google.golang.org/api/idtoken and the provided
// expectedAudience. Returns the parsed claims on success.
//
// expectedAudience is the URI this verifier is willing to accept tokens
// for, and MUST be non-empty — an empty string would bypass audience
// enforcement in idtoken and effectively accept any token from any
// GCE service account for any service. It is NOT a nonce — the same
// value is used for every verification. Signature verification, issuer
// checks, and expiry enforcement are all delegated to
// google.golang.org/api/idtoken, which also handles JWKS fetching and
// caching from https://www.googleapis.com/oauth2/v3/certs. idtoken
// accepts tokens issued by "https://accounts.google.com" (and its
// "accounts.google.com" variant) — if you need a stricter issuer
// policy, enforce it on the returned Claims.Issuer.
//
// For replay protection within a single audience, layer application-
// level nonces, mTLS binding, or one-time-use tracking on top.
func VerifyIdentityToken(ctx context.Context, token, expectedAudience string) (*Claims, error) {
	if expectedAudience == "" {
		return nil, fmt.Errorf("gcpimds: expectedAudience is required")
	}
	return verify(ctx, token, expectedAudience, "")
}

// VerifyIdentityTokenWithCertsURL is like VerifyIdentityToken but lets
// the caller point at a specific JWKS endpoint instead of Google's
// production one. certsURL must be non-empty, have an http or https
// scheme, and include a host component. Plain http is only allowed
// when the host is a loopback address (localhost, 127.0.0.0/8, ::1),
// so a test JWKS server over http://127.0.0.1:port works, but passing
// a remote plaintext URL is rejected as a MITM footgun.
//
// expectedAudience has the same contract as VerifyIdentityToken: it
// must be non-empty.
//
// This is intended for tests and development setups that use a fake or
// otherwise tightly controlled JWKS server. Do NOT pass an untrusted or
// user-controlled certsURL value in production: the verifier fetches
// from that URL during validation, and also trusts whatever keys it
// returns, which is both an SSRF vector and a trust bypass for token
// verification.
func VerifyIdentityTokenWithCertsURL(ctx context.Context, token, expectedAudience, certsURL string) (*Claims, error) {
	if expectedAudience == "" {
		return nil, fmt.Errorf("gcpimds: expectedAudience is required")
	}
	if certsURL == "" {
		return nil, fmt.Errorf("gcpimds: certsURL is required; use VerifyIdentityToken for the production JWKS flow")
	}
	u, err := url.Parse(certsURL)
	if err != nil {
		return nil, fmt.Errorf("gcpimds: parse certsURL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("gcpimds: certsURL must be http or https, got %q", u.Scheme)
	}
	// Hostname() strips the port, so `https://:1234/certs` (which has
	// u.Host == ":1234" but u.Hostname() == "") is correctly rejected.
	// u.Host != "" would wrongly let that through.
	if u.Hostname() == "" {
		return nil, fmt.Errorf("gcpimds: certsURL must include a host, got %q", certsURL)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("gcpimds: certsURL must use https unless host is loopback, got http://%s", u.Host)
	}
	return verify(ctx, token, expectedAudience, certsURL)
}

// isLoopbackHost reports whether the given hostname resolves literally
// to a loopback address. It accepts "localhost" (case-insensitive, with
// an optional trailing dot), any IPv4 in 127.0.0.0/8, and the IPv6
// loopback. No DNS lookup is performed.
func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func verify(ctx context.Context, token, expectedAudience, certsURL string) (*Claims, error) {
	var payload *idtoken.Payload
	var err error
	if certsURL == "" {
		payload, err = idtoken.Validate(ctx, token, expectedAudience)
	} else {
		transport, terr := newCertsRewriteTransport(certsURL)
		if terr != nil {
			return nil, terr
		}
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   certsFetchTimeout,
			// The JWKS endpoint should never redirect; block redirects so
			// a misconfigured or hostile certsURL can't redirect the fetch
			// to an attacker-controlled host.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		var v *idtoken.Validator
		v, err = idtoken.NewValidator(ctx, option.WithHTTPClient(httpClient))
		if err != nil {
			return nil, fmt.Errorf("gcpimds: build validator: %w", err)
		}
		payload, err = v.Validate(ctx, token, expectedAudience)
	}
	if err != nil {
		return nil, fmt.Errorf("gcpimds: validate identity token: %w", err)
	}
	return claimsFromPayload(payload)
}

// certsRewriteTransport redirects requests for Google's hardcoded JWKS
// endpoint to a caller-supplied URL. Used by
// VerifyIdentityTokenWithCertsURL so tests can serve test keys without
// monkey-patching the idtoken package.
//
// targetURL is parsed once at transport construction so every RoundTrip
// call reuses the same *url.URL (cheap and avoids hiding parse errors
// inside the hot path).
type certsRewriteTransport struct {
	targetURL *url.URL
}

func newCertsRewriteTransport(target string) (*certsRewriteTransport, error) {
	// target is intentionally caller-supplied via
	// VerifyIdentityTokenWithCertsURL; SSRF is the explicit contract and
	// VerifyIdentityTokenWithCertsURL already validated the URL shape.
	u, err := url.Parse(target) //nolint:gosec // G704: caller-supplied JWKS URL is the feature
	if err != nil {
		return nil, fmt.Errorf("gcpimds: parse certsURL: %w", err)
	}
	return &certsRewriteTransport{targetURL: u}, nil
}

func (t *certsRewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !matchesGoogleCertsURL(req.URL) {
		return http.DefaultTransport.RoundTrip(req)
	}
	// Clone the request so transport/middleware-relevant fields
	// (ContentLength, GetBody, TransferEncoding, Trailer, Host, and any
	// upstream-added fields) are preserved. Only the URL + Host get
	// rewritten to point at the caller-supplied target.
	newReq := req.Clone(req.Context())
	newURL := *t.targetURL
	newReq.URL = &newURL
	newReq.Host = t.targetURL.Host
	return http.DefaultTransport.RoundTrip(newReq)
}

// matchesGoogleCertsURL compares a request URL against the production
// JWKS endpoint by scheme + host + path, ignoring trailing slashes,
// query, and fragment. Exact string compare would be fragile across
// idtoken library updates that might normalize the URL differently.
func matchesGoogleCertsURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	return u.Scheme == googleSACertsParsed.Scheme &&
		u.Host == googleSACertsParsed.Host &&
		trimTrailingSlash(u.Path) == trimTrailingSlash(googleSACertsParsed.Path)
}

func trimTrailingSlash(s string) string {
	for len(s) > 1 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func claimsFromPayload(p *idtoken.Payload) (*Claims, error) {
	c := &Claims{
		Audience: p.Audience,
		Issuer:   p.Issuer,
		Subject:  p.Subject,
		IssuedAt: time.Unix(p.IssuedAt, 0),
		Expires:  time.Unix(p.Expires, 0),
	}
	if v, ok := p.Claims["email"].(string); ok {
		c.Email = v
	}
	if v, ok := p.Claims["email_verified"].(bool); ok {
		c.EmailVerified = v
	}
	if gmap, ok := p.Claims["google"].(map[string]any); ok {
		if ce, ok := gmap["compute_engine"].(map[string]any); ok {
			if v, ok := ce["instance_id"].(string); ok {
				c.InstanceID = v
			}
			if v, ok := ce["instance_name"].(string); ok {
				c.InstanceName = v
			}
			if v, ok := ce["project_id"].(string); ok {
				c.ProjectID = v
			}
			if raw, ok := ce["project_number"]; ok {
				n, err := parseProjectNumber(raw)
				if err != nil {
					return nil, fmt.Errorf("gcpimds: invalid project_number claim: %w", err)
				}
				c.ProjectNumber = n
			}
			if v, ok := ce["zone"].(string); ok {
				c.Zone = v
			}
			if licenses, ok := ce["license_id"].([]any); ok {
				for _, l := range licenses {
					if s, ok := l.(string); ok {
						c.LicenseIDs = append(c.LicenseIDs, s)
					}
				}
			}
		}
	}
	return c, nil
}

// parseProjectNumber extracts a GCP project number from the raw JWT
// claims value. GCE identity tokens encode project_number as a JSON
// number, which encoding/json decodes to float64. Real GCP project
// numbers are 10-12 digit integers (~10^11 to ~10^12), orders of
// magnitude below float64's 2^53 safe-integer limit, so float64
// round-trip precision is not an issue in practice. See the example
// payload at
// https://docs.cloud.google.com/compute/docs/instances/verifying-instance-identity
//
// A string fallback is also accepted in case a future GCE api-version
// switches to string encoding for forward compat. Malformed values
// (NaN, ±Inf, non-integer, out-of-range for int64, unparseable string,
// unsupported JSON type) return an error so callers see a loud
// malformed-token failure rather than silently accepting a wrong
// number.
func parseProjectNumber(v any) (int64, error) {
	switch n := v.(type) {
	case float64:
		if math.IsNaN(n) {
			return 0, fmt.Errorf("NaN")
		}
		if math.IsInf(n, 0) {
			return 0, fmt.Errorf("infinite")
		}
		if n != math.Trunc(n) {
			return 0, fmt.Errorf("non-integer %v", n)
		}
		if n < math.MinInt64 || n > math.MaxInt64 {
			return 0, fmt.Errorf("out of int64 range: %v", n)
		}
		return int64(n), nil
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse string %q: %w", n, err)
		}
		return i, nil
	default:
		return 0, fmt.Errorf("unsupported type %T", v)
	}
}
