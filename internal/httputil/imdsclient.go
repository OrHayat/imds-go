package httputil

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	imds "github.com/OrHayat/imds-go"
)

// ErrMissingBaseURL is returned by NewClient when no base URL was configured.
var ErrMissingBaseURL = errors.New("httputil: Client requires WithBaseURL")

// ErrMissingProviderID is returned by NewClient when the provider ID is empty.
var ErrMissingProviderID = errors.New("httputil: Client requires a non-empty provider ID")

// Client is an application-level HTTP client for IMDS endpoints. It owns a
// base URL, default headers, and default query parameters, and handles the
// full request-response lifecycle (build, send, drain, close, error wrap) so
// provider clients never touch *http.Response directly.
//
// A Client is safe for concurrent use by multiple goroutines once constructed;
// all fields are set during NewClient and never mutated afterward.
type Client struct {
	http           *http.Client
	baseURL        string
	providerID     imds.ID
	defaultHeaders http.Header
	defaultQuery   url.Values

	// pendingTimeout is set by WithTimeout and applied by NewClient after
	// all options have run, so the option order does not matter.
	pendingTimeout time.Duration
}

// ClientOption configures a Client at construction time.
type ClientOption func(*Client)

// WithHTTPClient overrides the underlying *http.Client. If unset, the Client
// uses a link-local IMDS transport with retry. NewClient clones the supplied
// client before applying any pending timeout, so callers can safely share a
// *http.Client across providers.
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
// Per-request overrides via GetWithQuery replace the default for that request.
func WithDefaultQuery(name, value string) ClientOption {
	return func(cl *Client) {
		if cl.defaultQuery == nil {
			cl.defaultQuery = make(url.Values)
		}
		cl.defaultQuery.Set(name, value)
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
	return c, nil
}

// Get fetches the given path using the client's defaults. The response body
// is drained and closed internally. Non-200 responses are returned as a
// *imds.MetadataError.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	return c.GetWithQuery(ctx, path, nil)
}

// GetWithQuery fetches the given path, overriding the client's default query
// parameters with extra on a key-by-key basis. Keys present in extra replace
// the default for this request only; keys absent in extra keep the default.
func (c *Client) GetWithQuery(ctx context.Context, path string, extra url.Values) ([]byte, error) {
	req, err := c.buildRequest(ctx, path, extra)
	if err != nil {
		return nil, err
	}
	return c.do(req, path)
}

func (c *Client) buildRequest(ctx context.Context, path string, extra url.Values) (*http.Request, error) {
	rawPath, rawQuery, _ := strings.Cut(path, "?")
	joined, err := url.JoinPath(c.baseURL, rawPath)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(joined)
	if err != nil {
		return nil, err
	}
	if rawQuery != "" {
		u.RawQuery = rawQuery
	}

	q := u.Query()
	for k, vs := range c.defaultQuery {
		if _, set := q[k]; !set {
			q[k] = vs
		}
	}
	for k, vs := range extra {
		q[k] = vs
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range c.defaultHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return req, nil
}

func (c *Client) do(req *http.Request, path string) ([]byte, error) {
	// G704: the request URL is caller-constructed by design — this package
	// exists to fetch caller-specified paths from IMDS endpoints.
	resp, err := c.http.Do(req) //nolint:gosec // G704
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain so the connection can be reused; error body is discarded.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, &imds.MetadataError{
			Provider:   c.providerID,
			StatusCode: resp.StatusCode,
			Path:       path,
		}
	}
	return io.ReadAll(resp.Body)
}
