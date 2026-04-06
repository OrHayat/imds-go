package httputil

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"time"
)

const (
	defaultTimeout    = 2 * time.Second
	defaultMaxRetries = 3
)

// Client wraps http.Client with IMDS-specific defaults: link-local dialer,
// short timeout, and retry with exponential backoff.
type Client struct {
	http       *http.Client
	maxRetries int
}

// DefaultClient creates an HTTP client with IMDS defaults:
// link-local transport, 2s timeout, 3 retries.
func DefaultClient() *Client {
	return &Client{
		http: &http.Client{
			Timeout:   defaultTimeout,
			Transport: newIMDSTransport(),
		},
		maxRetries: defaultMaxRetries,
	}
}

// NewClient creates an HTTP client suitable for IMDS requests.
// If httpClient is nil, a default client with a link-local transport is created.
// Timeout applies to individual requests (default 2s).
func NewClient(httpClient *http.Client, timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if httpClient == nil {
		return &Client{
			http: &http.Client{
				Timeout:   timeout,
				Transport: newIMDSTransport(),
			},
			maxRetries: defaultMaxRetries,
		}
	}
	if httpClient.Timeout == 0 {
		httpClient.Timeout = timeout
	}
	return &Client{
		http:       httpClient,
		maxRetries: defaultMaxRetries,
	}
}

// Do executes an HTTP request with retries on 429/5xx.
func (c *Client) Do(ctx context.Context, method, url string, headers map[string]string) (*http.Response, error) {
	var lastErr error
	for attempt := range c.maxRetries {
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
			backoff(ctx, attempt)
			continue
		}

		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			resp.Body.Close()
			lastErr = fmt.Errorf("http %d from %s %s", resp.StatusCode, method, url)
			backoff(ctx, attempt)
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

func backoff(ctx context.Context, attempt int) {
	d := time.Duration(math.Pow(2, float64(attempt))) * 200 * time.Millisecond
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// newIMDSTransport returns a transport configured for link-local IMDS access.
func newIMDSTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		TLSHandshakeTimeout: 2 * time.Second,
	}
}
