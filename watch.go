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
	Fields   []string      // top-level fields to watch, nil = all
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
	go pollLoop(ctx, ch, interval, cfg.Fields, fetch)
	return ch, nil
}

func pollLoop(ctx context.Context, ch chan Event, interval time.Duration, fields []string, fetch func(context.Context) (*InstanceMetadata, error)) {
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
			old = pollOnce(ctx, ch, old, fields, fetch)
		}
	}
}

func pollOnce(ctx context.Context, ch chan<- Event, old *InstanceMetadata, fields []string, fetch func(context.Context) (*InstanceMetadata, error)) *InstanceMetadata {
	cur, err := fetch(ctx)
	if err != nil {
		send(ctx, ch, errorEvent(err))
		return old
	}

	changed := diffMetadata(old, cur, fields)
	if len(changed) > 0 {
		send(ctx, ch, changeEvent(old, cur, changed))
	}
	return cur
}

// diffMetadata compares two InstanceMetadata values and returns which
// top-level fields changed. If fields is non-nil, only those fields are checked.
func diffMetadata(old, new *InstanceMetadata, fields []string) []string {
	type field struct {
		name string
		get  func(*InstanceMetadata) any
	}

	all := []field{
		{"instance", func(m *InstanceMetadata) any { return m.Instance }},
		{"interfaces", func(m *InstanceMetadata) any { return m.Interfaces }},
		{"tags", func(m *InstanceMetadata) any { return m.Tags }},
		{"additional_properties", func(m *InstanceMetadata) any { return m.AdditionalProperties }},
	}

	toCheck := all
	if len(fields) > 0 {
		filter := make(map[string]bool, len(fields))
		for _, f := range fields {
			filter[f] = true
		}
		toCheck = nil
		for _, f := range all {
			if filter[f.name] {
				toCheck = append(toCheck, f)
			}
		}
	}

	var changed []string
	for _, f := range toCheck {
		if !reflect.DeepEqual(f.get(old), f.get(new)) {
			changed = append(changed, f.name)
		}
	}
	return changed
}
