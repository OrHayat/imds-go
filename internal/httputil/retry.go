package httputil

import (
	"context"
	"math"
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

// waitBackoff sleeps for the given duration, respecting context cancellation.
func waitBackoff(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
