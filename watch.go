package imds

import (
	"context"
	"reflect"
	"time"
)

const defaultPollInterval = 30 * time.Second

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

func errorEvent(err error) Event {
	return Event{
		Timestamp:  time.Now(),
		Err:        err,
		ErrMessage: err.Error(),
	}
}

func changeEvent(old, new *InstanceMetadata, changed []string) Event {
	return Event{
		Timestamp: time.Now(),
		Old:       old,
		New:       new,
		Changed:   changed,
	}
}

// send sends an event on ch, respecting context cancellation.
// Returns false if ctx is done.
func send(ctx context.Context, ch chan<- Event, ev Event) bool {
	select {
	case ch <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

// PollWatch is a shared poll-based watch helper.
// Most providers delegate their Watch implementation to this function.
// GCP overrides with long polling instead.
func PollWatch(ctx context.Context, cfg WatchConfig, fetch func(context.Context) (*InstanceMetadata, error)) (<-chan Event, error) {
	interval := cfg.Interval
	if interval == 0 {
		interval = defaultPollInterval
	}

	ch := make(chan Event)
	go pollLoop(ctx, ch, interval, fetch)
	return ch, nil
}

func pollLoop(ctx context.Context, ch chan Event, interval time.Duration, fetch func(context.Context) (*InstanceMetadata, error)) {
	defer close(ch)

	old, err := fetch(ctx)
	if err != nil {
		send(ctx, ch, errorEvent(err))
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			old = pollOnce(ctx, ch, old, fetch)
		}
	}
}

func pollOnce(ctx context.Context, ch chan<- Event, old *InstanceMetadata, fetch func(context.Context) (*InstanceMetadata, error)) *InstanceMetadata {
	cur, err := fetch(ctx)
	if err != nil {
		send(ctx, ch, errorEvent(err))
		return old
	}

	changed := diffMetadata(old, cur)
	if len(changed) > 0 {
		send(ctx, ch, changeEvent(old, cur, changed))
	}
	return cur
}

// diffMetadata compares dynamic fields between two InstanceMetadata values.
// Static fields (instance info) are never compared — they don't change on a running instance.
func diffMetadata(old, new *InstanceMetadata) []string {
	var changed []string
	if !reflect.DeepEqual(old.Interfaces, new.Interfaces) {
		changed = append(changed, "interfaces")
	}
	if !reflect.DeepEqual(old.Tags, new.Tags) {
		changed = append(changed, "tags")
	}
	if !reflect.DeepEqual(old.AdditionalProperties, new.AdditionalProperties) {
		changed = append(changed, "additional_properties")
	}
	return changed
}
