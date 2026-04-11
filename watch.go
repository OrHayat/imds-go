package imds

import "time"

// WatchConfig controls what is watched and how.
type WatchConfig struct {
	Interval time.Duration // polling interval, default 30s
}

// Event describes a metadata change or poll error.
type Event struct {
	Timestamp  time.Time         `json:"timestamp"`
	Old        *InstanceMetadata `json:"old,omitempty"`
	New        *InstanceMetadata `json:"new,omitempty"`
	Changed    []string          `json:"changed,omitempty"`
	Err        error             `json:"-"`
	ErrMessage string            `json:"error,omitempty"`
}
