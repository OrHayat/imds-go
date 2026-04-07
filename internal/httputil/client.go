package httputil

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const defaultTimeout = 2 * time.Second

// DefaultHTTPClient creates an http.Client with IMDS defaults:
// link-local transport, retry on transient errors, 2s timeout.
func DefaultHTTPClient() *http.Client {
	return NewHTTPClient(nil, nil)
}

// NewHTTPClient creates an http.Client with retry transport.
// If base is nil, a link-local IMDS transport is used.
// If retryer is nil, DefaultRetryer is used.
// The returned client uses retryTransport wrapping the base.
func NewHTTPClient(base http.RoundTripper, retryer Retryer) *http.Client {
	if base == nil {
		base = newIMDSTransport()
	}
	if retryer == nil {
		retryer = DefaultRetryer{}
	}
	return &http.Client{
		Timeout: defaultTimeout,
		Transport: &retryTransport{
			base:    base,
			retryer: retryer,
		},
		// IMDS should never redirect requests so block them from this client.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ReadBody reads and closes the response body.
func ReadBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func noProxy(*http.Request) (*url.URL, error) { return nil, nil }

// newIMDSTransport returns a transport configured for link-local IMDS access.
func newIMDSTransport() *http.Transport {
	return &http.Transport{
		Proxy: noProxy,
		DialContext: (&net.Dialer{
			Timeout:   defaultTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:       10,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: true,
	}
}
