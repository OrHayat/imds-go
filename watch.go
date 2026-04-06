package imds

import (
	"context"
	"fmt"
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

// send sends an event on ch. Drops the event if the buffer is full.
// Returns false if ctx is done.
func send(ctx context.Context, ch chan<- Event, ev Event) bool {
	select {
	case ch <- ev:
		return true
	case <-ctx.Done():
		return false
	default:
		return true // buffer full, drop event
	}
}

// PollWatch is a shared poll-based watch helper.
// Most providers delegate their Watch implementation to this function.
// GCP overrides with long polling instead.
func PollWatch(ctx context.Context, cfg WatchConfig, fetch func(context.Context) (*InstanceMetadata, error)) (<-chan Event, error) {
	interval := cfg.Interval
	if interval < 0 {
		return nil, fmt.Errorf("imds: invalid poll interval %v", interval)
	}
	if interval == 0 {
		interval = defaultPollInterval
	}

	// Buffered to decouple poll rate from consumer speed.
	// Events are dropped if the buffer is full (consumer too slow).
	ch := make(chan Event, 32)
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

// dynamicField defines a field that can change on a running instance.
type dynamicField struct {
	name    string
	changed func(old, new *InstanceMetadata) bool
}

var watchedFields = []dynamicField{
	{"interfaces", func(o, n *InstanceMetadata) bool { return !reflect.DeepEqual(o.Interfaces, n.Interfaces) }},
	{"tags", func(o, n *InstanceMetadata) bool { return !reflect.DeepEqual(o.Tags, n.Tags) }},
	{"spot_terminating", func(o, n *InstanceMetadata) bool { return o.SpotTerminating != n.SpotTerminating }},
	{"maintenance_events", func(o, n *InstanceMetadata) bool { return !reflect.DeepEqual(o.MaintenanceEvents, n.MaintenanceEvents) }},
	{"additional_properties", func(o, n *InstanceMetadata) bool { return !reflect.DeepEqual(o.AdditionalProperties, n.AdditionalProperties) }},
}

// diffMetadata compares dynamic fields between two InstanceMetadata values.
// Static fields (instance info) are never compared — they don't change on a running instance.
func diffMetadata(old, new *InstanceMetadata) []string {
	if old == nil || new == nil {
		return nil
	}
	var changed []string
	for _, f := range watchedFields {
		if f.changed(old, new) {
			changed = append(changed, f.name)
		}
	}
	return changed
}
