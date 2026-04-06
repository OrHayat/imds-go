package httputil

import (
	"io"
	"net"
	"net/http"
	"time"
)

const defaultTimeout = 2 * time.Second

// DefaultHTTPClient creates an http.Client with IMDS defaults:
// link-local transport, retry on 429/5xx, 2s timeout.
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
	}
}

// ReadBody reads and closes the response body.
func ReadBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// newIMDSTransport returns a transport configured for link-local IMDS access.
func newIMDSTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:       10,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: true,
	}
}
