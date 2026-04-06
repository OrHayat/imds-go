package imds

import "context"

// ID identifies a cloud provider.
type ID string

// Provider is the core interface every cloud IMDS client must implement.
type Provider interface {
	// ID returns the provider identifier.
	ID() ID

	// Probe checks if this provider's IMDS is available.
	// Returns (true, nil) if this is the provider, (false, nil) if not,
	// or (false, err) if the check failed.
	Probe(ctx context.Context) (bool, error)

	// GetMetadata fetches instance metadata from the provider's IMDS.
	GetMetadata(ctx context.Context) (*InstanceMetadata, error)

	// Watch monitors IMDS for metadata changes.
	// Most providers use PollWatch internally. GCP uses long polling.
	// The returned channel is closed when ctx is cancelled.
	Watch(ctx context.Context, cfg WatchConfig) (<-chan Event, error)
}

// ProbeGroup holds providers with an explicit priority level.
// Used by DetectPriority for priority-based detection.
type ProbeGroup struct {
	level     int
	providers []Provider
}

// Priority creates a probe group with the given priority level.
// Lower numbers run first. Providers within a group run concurrently.
func Priority(level int, providers ...Provider) ProbeGroup {
	return ProbeGroup{level: level, providers: providers}
}
