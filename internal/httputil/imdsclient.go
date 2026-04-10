package httputil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	imds "github.com/OrHayat/imds-go"
)

// ErrMissingBaseURL is returned by NewClient when no base URL was configured.
var ErrMissingBaseURL = errors.New("httputil: Client requires WithBaseURL")

// ErrMissingProviderID is returned by NewClient when the provider ID is empty.
var ErrMissingProviderID = errors.New("httputil: Client requires a non-empty provider ID")

// ErrInvalidTokenSource is returned by NewClient when WithTokenSource was
// called with an empty header name or a nil TokenSource.
var ErrInvalidTokenSource = errors.New("httputil: WithTokenSource requires a non-empty header name and non-nil TokenSource")

// maxErrBodySnippet caps the bytes of an error response body captured into
// MetadataError.Err for diagnostics. Remaining bytes are drained.
const maxErrBodySnippet = 2 << 10 // 2 KiB

// Response is a read-to-completion HTTP response. The body has already been
// consumed and the underlying connection returned to the pool.
type Response struct {
	Body       []byte
	Header     http.Header
	StatusCode int
}

// TokenSource supplies a header value for authenticated requests. Implementations
// own the details of how the token is fetched — typically via a separate HTTP
// client that doesn't go through the token-injecting wrapper, mirroring the
// oauth2.TokenSource / aws credentials.Provider / azcore.TokenCredential pattern.
//
// Token returns the complete header value to inject (for example
// "Bearer eyJ..." or a raw token string). The wrapper caches the result until
// it invalidates on a 401 or 403 response and calls Token again.
type TokenSource interface {
	Token(ctx context.Context) (headerValue string, err error)
}

// Client is an application-level HTTP client for IMDS endpoints. It owns a
// base URL, default headers, default query parameters, and an optional
// token source, and handles the full request-response lifecycle (build,
// send, drain, close, retry, error wrap) so provider clients never touch
// *http.Response directly.
//
// A Client is safe for concurrent use by multiple goroutines.
type Client struct {
	http           *http.Client
	providerID     imds.ID
	baseURL        string
	defaultHeaders http.Header
	defaultQuery   url.Values

	// defaultQueryEncoded is the pre-encoded form of defaultQuery, computed
	// once in NewClient. When no per-request query override and no inline
	// path query are present, buildRequest uses it as-is to avoid a round
	// trip through url.Values / q.Encode() on the hot path.
	defaultQueryEncoded string

	// pendingTimeout is set by WithTimeout and applied by NewClient after
	// all options have run, so the option order does not matter.
	pendingTimeout time.Duration

	// token state: cached header value, refreshed on demand from tokenSource.
	tokenMu     sync.Mutex
	tokenHeader string
	tokenValue  string
	tokenSource TokenSource
}

// ClientOption configures a Client at construction time.
type ClientOption func(*Client)

// WithHTTPClient overrides the underlying *http.Client. NewClient clones the
// supplied client before applying any pending timeout, so callers can safely
// share a *http.Client across providers. The clone's CheckRedirect is always
// overridden to block redirects for IMDS safety.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(cl *Client) { cl.http = c }
}

// WithBaseURL sets the base URL prepended to every request path. Trailing
// slashes are trimmed.
func WithBaseURL(u string) ClientOption {
	return func(cl *Client) { cl.baseURL = strings.TrimRight(u, "/") }
}

// WithTimeout records a request timeout applied to the underlying
// *http.Client. The timeout is applied by NewClient after all options run, so
// WithTimeout and WithHTTPClient may appear in any order.
func WithTimeout(d time.Duration) ClientOption {
	return func(cl *Client) { cl.pendingTimeout = d }
}

// WithDefaultHeader registers a header applied to every request. Calling it
// multiple times with the same name replaces the previous value.
func WithDefaultHeader(name, value string) ClientOption {
	return func(cl *Client) {
		if cl.defaultHeaders == nil {
			cl.defaultHeaders = make(http.Header)
		}
		cl.defaultHeaders.Set(name, value)
	}
}

// WithDefaultQuery registers a query parameter applied to every request.
// Per-request overrides via GetWithQuery or WithQueryParam replace the
// default for that request.
func WithDefaultQuery(name, value string) ClientOption {
	return func(cl *Client) {
		if cl.defaultQuery == nil {
			cl.defaultQuery = make(url.Values)
		}
		cl.defaultQuery.Set(name, value)
	}
}

// WithTokenSource enables automatic token management. Before every request,
// the client injects the cached token into headerName, fetching a fresh one
// from src if the cache is empty. On a 401 or 403 response, the client
// invalidates the cache, fetches a new token, and retries the request once.
// Token errors and second failures propagate to the caller.
//
// The TokenSource is responsible for its own HTTP plumbing — typically it
// holds a separate *Client (or raw *http.Client) that does not itself have
// a WithTokenSource option set, so the token-fetch path does not recurse
// through the token-injecting layer. This mirrors the oauth2.Transport /
// azcore BearerTokenPolicy / aws ec2rolecreds.Provider pattern: two clients,
// structurally separated, one wrapping the other's fetch path.
func WithTokenSource(headerName string, src TokenSource) ClientOption {
	return func(cl *Client) {
		cl.tokenHeader = headerName
		cl.tokenSource = src
	}
}

// NewClient builds a Client for the given provider. WithBaseURL is required;
// NewClient returns ErrMissingBaseURL if it is not supplied. Defaults (link-
// local IMDS transport, 2s timeout, no headers, no query params) apply only
// when WithHTTPClient is not used; a supplied client keeps its own timeout
// and transport, though its CheckRedirect is always overridden to block
// redirects for IMDS safety. Use WithTimeout to enforce a timeout regardless
// of which underlying client is active.
func NewClient(providerID imds.ID, opts ...ClientOption) (*Client, error) {
	if providerID == "" {
		return nil, ErrMissingProviderID
	}
	c := &Client{providerID: providerID}
	for _, opt := range opts {
		opt(c)
	}
	if c.baseURL == "" {
		return nil, ErrMissingBaseURL
	}
	// If the caller touched either token field via WithTokenSource, both
	// must be valid. Rejecting early avoids silent "token fetched but never
	// injected" or nil-dereference-at-runtime footguns.
	if c.tokenHeader != "" || c.tokenSource != nil {
		if c.tokenHeader == "" || c.tokenSource == nil {
			return nil, ErrInvalidTokenSource
		}
	}

	if c.http == nil {
		c.http = DefaultHTTPClient()
	} else {
		clone := *c.http
		c.http = &clone
		c.http.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	if c.pendingTimeout > 0 {
		c.http.Timeout = c.pendingTimeout
	}
	if len(c.defaultQuery) > 0 {
		c.defaultQueryEncoded = c.defaultQuery.Encode()
	}
	return c, nil
}

// requestConfig accumulates per-request overrides applied by RequestOptions.
// body (an io.Reader) is collected by RequestOptions; Do reads it once into
// bodyBytes so retries can replay the same bytes without re-consuming a
// stream that's already been drained.
type requestConfig struct {
	method    string
	body      io.Reader
	bodyBytes []byte
	header    http.Header
	query     url.Values
}

// RequestOption customizes a single request issued via Do.
type RequestOption func(*requestConfig)

// WithMethod sets the HTTP method. Default is GET.
func WithMethod(method string) RequestOption {
	return func(rc *requestConfig) { rc.method = method }
}

// WithBody sets the request body.
func WithBody(body io.Reader) RequestOption {
	return func(rc *requestConfig) { rc.body = body }
}

// WithHeader sets a per-request header, replacing any default of the same name.
func WithHeader(name, value string) RequestOption {
	return func(rc *requestConfig) {
		if rc.header == nil {
			rc.header = make(http.Header)
		}
		rc.header.Set(name, value)
	}
}

// WithQueryParam sets a per-request query parameter, replacing any default
// of the same name.
func WithQueryParam(name, value string) RequestOption {
	return func(rc *requestConfig) {
		if rc.query == nil {
			rc.query = make(url.Values)
		}
		rc.query.Set(name, value)
	}
}

// WithQueryValues sets a per-request query parameter to the given slice of
// values, replacing any default of the same name. Use this when a single key
// needs multiple values; WithQueryParam is the single-value shortcut.
func WithQueryValues(name string, values ...string) RequestOption {
	return func(rc *requestConfig) {
		if rc.query == nil {
			rc.query = make(url.Values)
		}
		rc.query[name] = values
	}
}

// Get fetches the given path and returns the body. Non-200 responses are
// returned as a *imds.MetadataError.
//
// Get skips Do's variadic RequestOption path so no address is taken of the
// local requestConfig, letting escape analysis keep it on the stack.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	rc := requestConfig{method: http.MethodGet}
	resp, err := c.doWithRefresh(ctx, path, rc)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// GetWithQuery fetches the given path, overriding the client's default query
// parameters with extra on a key-by-key basis. Keys present in extra replace
// the default for this request only; keys absent in extra keep the default.
// Multi-value entries in extra are preserved.
//
// GetWithQuery builds the requestConfig directly instead of going through
// RequestOptions, avoiding one closure allocation per query key.
func (c *Client) GetWithQuery(ctx context.Context, path string, extra url.Values) ([]byte, error) {
	if len(extra) == 0 {
		return c.Get(ctx, path)
	}
	rc := requestConfig{method: http.MethodGet, query: extra}
	resp, err := c.doWithRefresh(ctx, path, rc)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// Do issues a request against path with the given per-request overrides,
// applying defaults, token injection, and 401/403 token refresh retry.
// Non-200 responses are returned as a *imds.MetadataError with up to 2 KiB
// of response body captured in Err.
//
// If the request has a body, Do reads it into memory once so a 401/403
// token-refresh retry can replay the same bytes. Request bodies are
// expected to be non-closing readers (bytes.Reader, strings.Reader); the
// caller is responsible for any resource lifecycle.
func (c *Client) Do(ctx context.Context, path string, opts ...RequestOption) (*Response, error) {
	rc := requestConfig{method: http.MethodGet}
	for _, opt := range opts {
		opt(&rc)
	}

	if rc.body != nil {
		b, err := io.ReadAll(rc.body)
		if err != nil {
			return nil, fmt.Errorf("httputil: read request body: %w", err)
		}
		rc.bodyBytes = b
		rc.body = nil
	}

	return c.doWithRefresh(ctx, path, rc)
}

// doWithRefresh handles token injection and a single 401/403 retry.
func (c *Client) doWithRefresh(ctx context.Context, path string, rc requestConfig) (*Response, error) {
	if c.tokenSource == nil {
		return c.doOnce(ctx, path, rc, "")
	}

	tok, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := c.doOnce(ctx, path, rc, tok)
	if err == nil {
		return resp, nil
	}
	if !isTokenRejected(err) {
		return nil, err
	}

	// Token was rejected: invalidate, fetch a new one, retry once.
	c.invalidateToken()
	tok, err2 := c.getToken(ctx)
	if err2 != nil {
		return nil, err2
	}
	return c.doOnce(ctx, path, rc, tok)
}

func isTokenRejected(err error) bool {
	var me *imds.MetadataError
	if !errors.As(err, &me) {
		return false
	}
	return me.StatusCode == http.StatusUnauthorized || me.StatusCode == http.StatusForbidden
}

// doOnce builds and sends a single request. tokenValue is injected into
// c.tokenHeader if non-empty.
func (c *Client) doOnce(ctx context.Context, path string, rc requestConfig, tokenValue string) (*Response, error) {
	req, err := c.buildRequest(ctx, path, rc, tokenValue)
	if err != nil {
		return nil, err
	}
	return c.send(req, path)
}

func (c *Client) buildRequest(ctx context.Context, path string, rc requestConfig, tokenValue string) (*http.Request, error) {
	urlStr, err := c.buildURL(path, rc)
	if err != nil {
		return nil, err
	}

	method := rc.method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if rc.bodyBytes != nil {
		body = bytes.NewReader(rc.bodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}
	// Direct map assignment skips per-Add canonicalization; default header
	// keys are already canonical (Set() was used in WithDefaultHeader). The
	// slices are shared, not copied: the stdlib transport reads req.Header
	// but does not mutate it, and this Client never mutates defaultHeaders
	// after NewClient returns. If this ever changes we must copy.
	for k, vs := range c.defaultHeaders {
		req.Header[k] = vs
	}
	for k, vs := range rc.header {
		req.Header[k] = vs
	}
	if tokenValue != "" && c.tokenHeader != "" {
		req.Header.Set(c.tokenHeader, tokenValue)
	}
	return req, nil
}

// buildURL assembles the final request URL. Fast path: when no per-request
// query override and no inline path query are present, it returns a simple
// string concat using the pre-encoded default query. Slow path: falls back
// to url.Values merging when overrides need to be resolved per request.
//
// path is expected to be a clean, already-escaped URL path component —
// IMDS endpoints take a small, fixed set of ASCII paths (like
// "/metadata/instance/compute/vmId"), all hard-coded in provider code.
// This function does NOT run url.JoinPath / url.Parse on path, so it
// does not percent-encode spaces or normalize "." / ".." segments. If
// you need to send a path with special characters, escape it before
// passing it in.
func (c *Client) buildURL(path string, rc requestConfig) (string, error) {
	base := c.baseURL
	rawPath, inlineQuery, hasInline := strings.Cut(path, "?")

	// Normalize leading slash. We don't use url.JoinPath — see the
	// function comment about path invariants.
	var pathPart string
	switch {
	case rawPath == "":
		pathPart = ""
	case rawPath[0] == '/':
		pathPart = rawPath
	default:
		pathPart = "/" + rawPath
	}

	// Fast path: no per-request query, no inline query.
	if len(rc.query) == 0 && !hasInline {
		if c.defaultQueryEncoded == "" {
			return base + pathPart, nil
		}
		return base + pathPart + "?" + c.defaultQueryEncoded, nil
	}

	// Slow path: need to merge defaults with inline and/or per-request query.
	var q url.Values
	if hasInline {
		// Parse the inline query via url.ParseQuery (cheaper than full url.Parse).
		parsed, err := url.ParseQuery(inlineQuery)
		if err != nil {
			return "", fmt.Errorf("httputil: parse inline query for path %q: %w", rawPath, err)
		}
		q = parsed
	} else {
		q = make(url.Values, len(c.defaultQuery)+len(rc.query))
	}
	for k, vs := range c.defaultQuery {
		if _, set := q[k]; !set {
			q[k] = vs
		}
	}
	for k, vs := range rc.query {
		q[k] = vs
	}
	encoded := q.Encode()
	if encoded == "" {
		return base + pathPart, nil
	}
	return base + pathPart + "?" + encoded, nil
}

func (c *Client) send(req *http.Request, path string) (*Response, error) {
	// G704: the request URL is caller-constructed by design — this package
	// exists to fetch caller-specified paths from IMDS endpoints.
	resp, err := c.http.Do(req) //nolint:gosec // G704
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBodySnippet))
		_, _ = io.Copy(io.Discard, resp.Body)
		me := &imds.MetadataError{
			Provider:   c.providerID,
			StatusCode: resp.StatusCode,
			Path:       path,
		}
		if len(snippet) > 0 {
			// %q on []byte escapes control characters and newlines so
			// multi-line error bodies don't garble logs or terminal
			// output, while preserving the raw bytes. Using %q on a
			// string would replace invalid UTF-8 with U+FFFD and lose
			// diagnostic fidelity for non-UTF-8 responses.
			me.Err = fmt.Errorf("response body snippet: %q", snippet)
		}
		return nil, me
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// resp.Header is not reused by the stdlib transport after the response
	// is returned, so exposing it directly is safe and saves a map clone.
	return &Response{
		Body:       body,
		Header:     resp.Header,
		StatusCode: resp.StatusCode,
	}, nil
}

// getToken returns the cached token, fetching a fresh one if empty. The
// mutex is released before calling TokenSource.Token so that (a) concurrent
// requests do not all serialize behind a slow token fetch, and (b) a
// misbehaving source that re-enters this Client will not deadlock. The
// trade-off: several goroutines hitting an empty cache simultaneously may
// each issue a fetch. Acceptable for IMDS — token endpoints are local and
// each returned token is valid; last-writer wins in the cache.
func (c *Client) getToken(ctx context.Context) (string, error) {
	c.tokenMu.Lock()
	if v := c.tokenValue; v != "" {
		c.tokenMu.Unlock()
		return v, nil
	}
	c.tokenMu.Unlock()

	v, err := c.tokenSource.Token(ctx)
	if err != nil {
		return "", err
	}

	c.tokenMu.Lock()
	c.tokenValue = v
	c.tokenMu.Unlock()
	return v, nil
}

// invalidateToken clears the cached token so the next getToken fetches fresh.
func (c *Client) invalidateToken() {
	c.tokenMu.Lock()
	c.tokenValue = ""
	c.tokenMu.Unlock()
}
