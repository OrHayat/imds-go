package httputil

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"time"
)

// Retryer controls retry behavior for HTTP requests.
type Retryer interface {
	MaxAttempts() int
	BackoffDelay(attempt int) time.Duration
	IsRetryable(statusCode int) bool
}

// DefaultRetryer retries on 429/5xx with exponential backoff.
type DefaultRetryer struct {
	Attempts int
}

func (r DefaultRetryer) MaxAttempts() int {
	if r.Attempts == 0 {
		return 3
	}
	return r.Attempts
}

func (r DefaultRetryer) BackoffDelay(attempt int) time.Duration {
	return time.Duration(math.Pow(2, float64(attempt))) * 200 * time.Millisecond
}

func (r DefaultRetryer) IsRetryable(statusCode int) bool {
	return statusCode == 429 || statusCode >= 500
}

// StatusError is returned when a retryable HTTP status exhausts all attempts.
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

// waitBackoff sleeps for the given duration, respecting context cancellation.
func waitBackoff(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
