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

// retryTransport wraps an http.RoundTripper with retry logic.
type retryTransport struct {
	base    http.RoundTripper
	retryer Retryer
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var lastErr error
	for attempt := range t.retryer.MaxAttempts() {
		// Reset body for retries (consumed after first attempt).
		if attempt > 0 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			req.Body = body
		}

		resp, err := t.base.RoundTrip(req)
		if err != nil {
			lastErr = err
			if req.Context().Err() != nil {
				return nil, req.Context().Err()
			}
			waitBackoff(req.Context(), t.retryer.BackoffDelay(attempt))
			continue
		}

		if t.retryer.IsRetryable(resp.StatusCode) {
			resp.Body.Close()
			lastErr = &StatusError{Code: resp.StatusCode, Method: req.Method, URL: req.URL.String()}
			waitBackoff(req.Context(), t.retryer.BackoffDelay(attempt))
			continue
		}

		return resp, nil
	}
	return nil, &RetryError{Err: lastErr}
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
