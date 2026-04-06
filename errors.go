package imds

import (
	"errors"
	"fmt"
)

var (
	ErrNoProvider   = errors.New("imds: no cloud provider detected")
	ErrNotAvailable = errors.New("imds: metadata service not available")
	ErrNotSupported = errors.New("imds: operation not supported by this provider")
	ErrVerifyFailed = errors.New("imds: identity verification failed")
)

// MetadataError wraps an IMDS HTTP error with context.
type MetadataError struct {
	Provider   ID
	StatusCode int
	Path       string
	Err        error
}

func (e *MetadataError) Error() string {
	msg := fmt.Sprintf("imds %s: %s returned %d", e.Provider, e.Path, e.StatusCode)
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *MetadataError) Unwrap() error {
	return e.Err
}
