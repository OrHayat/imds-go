package ibmimds

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultIAMURL is the production IBM Cloud IAM token endpoint used
// for exchanging instance identity tokens (CR-tokens) for IAM access
// tokens.
const DefaultIAMURL = "https://iam.cloud.ibm.com/identity/token"

// defaultIAMExchangeTimeout bounds an IAM exchange round-trip. IBM IAM
// typically responds in under a second; 15s leaves headroom for slow
// networks without letting a lost response hang the caller forever.
const defaultIAMExchangeTimeout = 15 * time.Second

var (
	defaultIAMClientOnce sync.Once
	defaultIAMClient     *http.Client
)

// newDefaultIAMClient returns an *http.Client suitable for the IAM
// exchange when the caller did not supply one. It enforces:
//
//   - a hard request timeout, so a stuck IBM IAM call can't hang the
//     caller indefinitely (http.DefaultClient has no Timeout);
//   - redirect blocking, so a hostile or misconfigured IAM endpoint
//     cannot 307/308 the POST body (which contains the CR-token) to
//     an attacker-controlled URL.
func newDefaultIAMClient() *http.Client {
	defaultIAMClientOnce.Do(func() {
		defaultIAMClient = &http.Client{
			Timeout: defaultIAMExchangeTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	})
	return defaultIAMClient
}

// crTokenGrant is the OAuth2 grant-type URN IBM IAM expects when
// exchanging an instance identity token for an IAM access token.
// Documented at https://cloud.ibm.com/apidocs/iam-identity-token-api.
const crTokenGrant = "urn:ibm:params:oauth:grant-type:cr-token" //nolint:gosec // G101: URN constant, not a credential

// isLoopbackHost reports whether the given hostname resolves literally
// to a loopback address. It accepts "localhost" (case-insensitive,
// with an optional trailing dot), any IPv4 in 127.0.0.0/8, and the
// IPv6 loopback. No DNS lookup is performed.
func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Claims holds the fields extracted from the IAM access token that
// IBM Cloud IAM returns after exchanging an instance identity
// (CR-token) at the IAM token endpoint.
type Claims struct {
	IAMID       string    // iam_id — e.g. "iam-ServiceId-..." or "crn-crn:v1:..."
	Subject     string    // sub
	SubjectType string    // sub_type — e.g. "Profile"
	Issuer      string    // iss — e.g. "https://iam.cloud.ibm.com/identity"
	AccountID   string    // account.bss — BSS account id
	Scope       string    // space-separated scope from the IAM response envelope
	IssuedAt    time.Time // iat
	Expires     time.Time // exp
	// IAMToken is the raw IAM access token returned by IBM IAM.
	// Callers that need to make subsequent IBM Cloud API calls on
	// behalf of the instance can pass this on Authorization headers;
	// callers that only need the claims can ignore it.
	IAMToken string
}

// VerifyIdentityToken exchanges an IBM instance identity token
// (CR-token) for an IAM access token at DefaultIAMURL and returns
// the claims extracted from the resulting IAM JWT. profileID
// selects the trusted profile to bind the IAM token to; pass empty
// to use the instance's default trusted profile linked at
// provisioning time.
//
// Verification model: IBM does not publish a JWKS for the raw
// instance identity token, so local signature verification is not
// possible. Instead, the exchange at iam.cloud.ibm.com IS the
// proof of validity — IBM IAM rejects any CR-token that is
// tampered, expired, or revoked, so a successful HTTP 200 from the
// IAM endpoint means IBM has authenticated the instance. Claims
// are then decoded from the IAM token payload; TLS to
// iam.cloud.ibm.com is the integrity boundary for those claims.
//
// For remote verification from a machine that isn't the instance
// itself, the CR-token is transmitted out of band (the instance
// obtains it via GetIdentityToken, ships it to the verifier, and
// the verifier calls VerifyIdentityToken to exchange it).
func VerifyIdentityToken(ctx context.Context, crToken, profileID string) (*Claims, error) {
	return VerifyIdentityTokenWithIAMURL(ctx, crToken, profileID, DefaultIAMURL, nil)
}

// VerifyIdentityTokenWithIAMURL is like VerifyIdentityToken but lets
// the caller point at a specific IAM endpoint URL (used by tests
// with a fake IAM server) and inject a custom *http.Client (e.g. to
// configure a custom root CA pool, proxies, or timeouts).
//
// iamURL is validated up front: it must parse, have an http or https
// scheme, and include a host component. Plain http is only allowed
// when the host is a loopback address (localhost, 127.0.0.0/8, ::1),
// so a test IAM server over http://127.0.0.1:port works, but passing
// any remote plaintext URL is rejected — the CR-token is posted in
// the request body and a plaintext remote URL is both a token
// disclosure risk (MITM) and a trust bypass (claims come from the
// response body, so a hostile endpoint can forge whatever it wants).
// Do NOT pass untrusted or user-controlled iamURL values in
// production.
//
// If iamURL is empty, DefaultIAMURL is used. If httpClient is nil, a
// hardened default is used: 15s timeout and redirect blocking, so a
// stuck or hostile IAM endpoint can't hang the caller or 3xx-redirect
// the CR-token-bearing POST body to an attacker-controlled URL. That
// default honors system root CAs and environment proxies. If you need
// custom transport-level behavior (proxies, non-default roots, longer
// timeout), build your own client and pass it here.
func VerifyIdentityTokenWithIAMURL(ctx context.Context, crToken, profileID, iamURL string, httpClient *http.Client) (*Claims, error) {
	if crToken == "" {
		return nil, fmt.Errorf("ibmimds: crToken is required")
	}
	if iamURL == "" {
		iamURL = DefaultIAMURL
	}
	u, err := url.Parse(iamURL)
	if err != nil {
		return nil, fmt.Errorf("ibmimds: parse iamURL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("ibmimds: iamURL must be http or https, got %q", u.Scheme)
	}
	// Hostname() strips the port, so "https://:1234/identity/token" is
	// correctly rejected (u.Host == ":1234" but Hostname() == "").
	if u.Hostname() == "" {
		return nil, fmt.Errorf("ibmimds: iamURL must include a host, got %q", iamURL)
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("ibmimds: iamURL must use https unless host is loopback, got http://%s", u.Host)
	}
	if httpClient == nil {
		httpClient = newDefaultIAMClient()
	}

	form := url.Values{
		"grant_type": {crTokenGrant},
		"cr_token":   {crToken},
	}
	if profileID != "" {
		form.Set("profile_id", profileID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, iamURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("ibmimds: build IAM request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ibmimds: IAM exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		// Drain the remainder so http.DefaultTransport can reuse the
		// connection on repeated failures. Ignore the error — we're
		// already returning one.
		_, _ = io.Copy(io.Discard, resp.Body)
		// %q on the raw snippet bytes keeps multi-line/non-UTF8 error
		// bodies as a single quoted, escaped string in the log line.
		return nil, fmt.Errorf("ibmimds: IAM exchange failed: %d %s: %q", resp.StatusCode, http.StatusText(resp.StatusCode), snippet)
	}

	var iamResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&iamResp); err != nil {
		return nil, fmt.Errorf("ibmimds: decode IAM response: %w", err)
	}
	if iamResp.AccessToken == "" {
		return nil, fmt.Errorf("ibmimds: IAM response has empty access_token")
	}

	claims, err := decodeJWTClaims(iamResp.AccessToken)
	if err != nil {
		return nil, err
	}
	claims.Scope = iamResp.Scope
	claims.IAMToken = iamResp.AccessToken
	return claims, nil
}

// decodeJWTClaims base64-decodes the payload segment of a JWT and
// extracts the fields we surface on Claims. Does NOT verify the
// signature — we rely on the TLS channel to iam.cloud.ibm.com for
// integrity. The IAM token's signature is anchored by IBM IAM's
// private key and could be independently verified against IBM's
// JWKS, but that would duplicate trust in the same TLS chain and
// add a dependency on a JWT library; the simpler "trust what IBM
// just handed us" model matches IBM's own documented flow.
func decodeJWTClaims(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("ibmimds: malformed JWT: expected 3 segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("ibmimds: decode JWT payload: %w", err)
	}

	var raw struct {
		IAMID   string `json:"iam_id"`
		Sub     string `json:"sub"`
		SubType string `json:"sub_type"`
		Iss     string `json:"iss"`
		Iat     int64  `json:"iat"`
		Exp     int64  `json:"exp"`
		Account struct {
			BSS string `json:"bss"`
		} `json:"account"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("ibmimds: parse JWT claims: %w", err)
	}
	// IBM IAM JWTs always include iat and exp. A missing or zero
	// value would decode to time.Unix(0, 0) == 1970-01-01, which is
	// both misleading and a silent acceptance of a malformed token.
	// Require both present and exp strictly after iat.
	if raw.Iat <= 0 {
		return nil, fmt.Errorf("ibmimds: JWT missing or invalid iat claim")
	}
	if raw.Exp <= 0 {
		return nil, fmt.Errorf("ibmimds: JWT missing or invalid exp claim")
	}
	if raw.Exp <= raw.Iat {
		return nil, fmt.Errorf("ibmimds: JWT exp (%d) is not after iat (%d)", raw.Exp, raw.Iat)
	}

	return &Claims{
		IAMID:       raw.IAMID,
		Subject:     raw.Sub,
		SubjectType: raw.SubType,
		Issuer:      raw.Iss,
		AccountID:   raw.Account.BSS,
		IssuedAt:    time.Unix(raw.Iat, 0),
		Expires:     time.Unix(raw.Exp, 0),
	}, nil
}
