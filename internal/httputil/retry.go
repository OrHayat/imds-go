package httputil

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

const (
	defaultMaxAttempts = 3
	maxBackoff         = 5 * time.Second
)

// Retryer controls retry behavior for HTTP requests.
type Retryer interface {
	MaxAttempts() int
	BackoffDelay(attempt int) time.Duration
	IsRetryable(statusCode int) bool
}

// DefaultRetryer retries on 429/500/502/503/504 with exponential backoff.
// Zero value uses defaultMaxAttempts. Set Attempts explicitly to override.
type DefaultRetryer struct {
	Attempts *int
}

func (r DefaultRetryer) MaxAttempts() int {
	if r.Attempts == nil {
		return defaultMaxAttempts
	}
	return *r.Attempts
}

func (r DefaultRetryer) BackoffDelay(attempt int) time.Duration {
	d := time.Duration(math.Pow(2, float64(attempt))) * 200 * time.Millisecond
	return min(d, maxBackoff)
}

func (r DefaultRetryer) IsRetryable(statusCode int) bool {
	return statusCode == 429 || statusCode == 500 || statusCode == 502 || statusCode == 503 || statusCode == 504
}

// StatusError describes the retryable HTTP status that caused a retry failure.
// Wrapped inside RetryError; use errors.As to extract.
type StatusError struct {
	Code   int
	Method string
	URL    string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("http %d from %s %s", e.Code, e.Method, e.URL)
}

// RetryError is returned when all retry attempts are exhausted.
type RetryError struct {
	Err error
}

func (e *RetryError) Error() string {
	return fmt.Sprintf("max retries exceeded: %v", e.Err)
}

func (e *RetryError) Unwrap() error {
	return e.Err
}

// retryTransport wraps an http.RoundTripper with retry logic.
type retryTransport struct {
	base    http.RoundTripper
	retryer Retryer
}

// RoundTrip executes the request with retries on transient failures.
// Success = non-retryable status code. On failure it drains the response,
// backs off (except on the last attempt), and retries with a fresh body.
func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	maxAttempts := max(t.retryer.MaxAttempts(), 1)
	var lastErr error

	for attempt := range maxAttempts {
		if attempt > 0 {
			if err := t.resetBody(req); err != nil {
				return nil, err
			}
		}

		resp, err := t.base.RoundTrip(req)
		if err == nil && !t.retryer.IsRetryable(resp.StatusCode) {
			return resp, nil
		}

		lastErr = t.handleFailure(resp, err, req)
		if req.Context().Err() != nil {
			return nil, req.Context().Err()
		}

		if attempt < maxAttempts-1 {
			waitBackoff(req.Context(), t.retryer.BackoffDelay(attempt))
			if req.Context().Err() != nil {
				return nil, req.Context().Err()
			}
		}
	}

	return nil, &RetryError{Err: lastErr}
}

// resetBody rewinds the request body via GetBody for the next attempt.
func (t *retryTransport) resetBody(req *http.Request) error {
	if req.GetBody == nil {
		if req.Body != nil {
			return fmt.Errorf("cannot retry: request body is not replayable (GetBody is nil)")
		}
		return nil
	}
	body, err := req.GetBody()
	if err != nil {
		return err
	}
	req.Body = body
	return nil
}

// handleFailure drains the response body (for connection reuse) and returns the error.
func (t *retryTransport) handleFailure(resp *http.Response, err error, req *http.Request) error {
	if resp != nil && resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if err != nil {
		return err
	}
	return &StatusError{Code: resp.StatusCode, Method: req.Method, URL: req.URL.String()}
}

// waitBackoff sleeps for the given duration, respecting context cancellation.
func waitBackoff(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
