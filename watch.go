package imds

import (
	"context"
	"reflect"
	"time"
)

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

// PollWatch is a shared poll-based watch helper.
// Most providers delegate their Watch implementation to this function.
// GCP overrides with long polling instead.
func PollWatch(ctx context.Context, cfg WatchConfig, fetch func(context.Context) (*InstanceMetadata, error)) (<-chan Event, error) {
	interval := cfg.Interval
	if interval == 0 {
		interval = 30 * time.Second
	}

	ch := make(chan Event)
	go func() {
		defer close(ch)

		old, err := fetch(ctx)
		if err != nil {
			select {
			case ch <- Event{Timestamp: time.Now(), Err: err, ErrMessage: err.Error()}:
			case <-ctx.Done():
			}
			return
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cur, err := fetch(ctx)
				if err != nil {
					select {
					case ch <- Event{Timestamp: time.Now(), Err: err, ErrMessage: err.Error()}:
					case <-ctx.Done():
						return
					}
					continue
				}

				changed := diffMetadata(old, cur, cfg.Fields)
				if len(changed) > 0 {
					select {
					case ch <- Event{
						Timestamp: time.Now(),
						Old:       old,
						New:       cur,
						Changed:   changed,
					}:
					case <-ctx.Done():
						return
					}
				}
				old = cur
			}
		}
	}()

	return ch, nil
}

// diffMetadata compares two InstanceMetadata values and returns which
// top-level fields changed. If fields is non-nil, only those fields are checked.
func diffMetadata(old, new *InstanceMetadata, fields []string) []string {
	type fieldDef struct {
		name string
		get  func(*InstanceMetadata) any
	}

	allFields := []fieldDef{
		{"instance", func(m *InstanceMetadata) any { return m.Instance }},
		{"interfaces", func(m *InstanceMetadata) any { return m.Interfaces }},
		{"tags", func(m *InstanceMetadata) any { return m.Tags }},
		{"additional_properties", func(m *InstanceMetadata) any { return m.AdditionalProperties }},
	}

	check := allFields
	if len(fields) > 0 {
		filter := make(map[string]bool, len(fields))
		for _, f := range fields {
			filter[f] = true
		}
		check = nil
		for _, f := range allFields {
			if filter[f.name] {
				check = append(check, f)
			}
		}
	}

	var changed []string
	for _, f := range check {
		if !reflect.DeepEqual(f.get(old), f.get(new)) {
			changed = append(changed, f.name)
		}
	}
	return changed
}
