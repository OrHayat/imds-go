package httputil

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const defaultTimeout = 2 * time.Second

// Client wraps http.Client with IMDS-specific defaults and retry logic.
type Client struct {
	http    *http.Client
	retryer Retryer
}

// DefaultClient creates an HTTP client with IMDS defaults:
// link-local transport, 2s timeout, 3 retries.
func DefaultClient() *Client {
	return &Client{
		http: &http.Client{
			Timeout:   defaultTimeout,
			Transport: newIMDSTransport(),
		},
		retryer: DefaultRetryer{},
	}
}

// NewClient creates an HTTP client suitable for IMDS requests.
// If httpClient is nil, a default client with link-local transport is used.
// If retryer is nil, DefaultRetryer is used.
// The provided httpClient is never mutated.
func NewClient(httpClient *http.Client, retryer Retryer) *Client {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:   defaultTimeout,
			Transport: newIMDSTransport(),
		}
	}
	if retryer == nil {
		retryer = DefaultRetryer{}
	}
	return &Client{
		http:    httpClient,
		retryer: retryer,
	}
}

// Do executes an HTTP request with retries controlled by the Retryer.
func (c *Client) Do(ctx context.Context, method, url string, headers map[string]string) (*http.Response, error) {
	var lastErr error
	for attempt := range c.retryer.MaxAttempts() {
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			waitBackoff(ctx, c.retryer.BackoffDelay(attempt))
			continue
		}

		if c.retryer.IsRetryable(resp.StatusCode) {
			resp.Body.Close()
			lastErr = fmt.Errorf("http %d from %s %s", resp.StatusCode, method, url)
			waitBackoff(ctx, c.retryer.BackoffDelay(attempt))
			continue
		}

		return resp, nil
	}
	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
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
