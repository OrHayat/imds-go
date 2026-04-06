package imds

import (
	"net/http"
	"time"
)

// Options holds shared configuration for provider clients.
type Options struct {
	HTTPClient *http.Client
	Timeout    time.Duration
	BaseURL    string
}

// Option configures an Options struct.
type Option func(*Options)

// WithTimeout sets the HTTP request timeout.
func WithTimeout(d time.Duration) Option {
	return func(o *Options) {
		o.Timeout = d
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) Option {
	return func(o *Options) {
		o.HTTPClient = c
	}
}

// WithBaseURL overrides the IMDS endpoint URL. Primarily for testing.
func WithBaseURL(u string) Option {
	return func(o *Options) {
		o.BaseURL = u
	}
}

// Apply applies functional options over sensible defaults and returns the result.
func Apply(opts ...Option) Options {
	o := Options{
		Timeout: 2 * time.Second,
	}
	for _, fn := range opts {
		fn(&o)
	}
	return o
}
