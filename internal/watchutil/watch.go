// Package watchutil holds helpers shared by provider packages in this
// module that implement the imds.Provider Watch method. It is internal on
// purpose: Send, PollWatch, DiffMetadata, ErrorEvent, and ChangeEvent are
// implementation primitives for provider implementations in this
// repository, not user-facing API. External packages cannot import this
// package; consumers building their own imds.Provider must implement
// Watch from scratch.
package watchutil

import (
	"context"
	"fmt"
	"reflect"
	"time"

	imds "github.com/OrHayat/imds-go"
)

const defaultPollInterval = 30 * time.Second

func ErrorEvent(err error) imds.Event {
	return imds.Event{
		Timestamp:  time.Now(),
		Err:        err,
		ErrMessage: err.Error(),
	}
}

func ChangeEvent(old, new *imds.InstanceMetadata, changed []string) imds.Event {
	return imds.Event{
		Timestamp: time.Now(),
		Old:       old,
		New:       new,
		Changed:   changed,
	}
}

// Send tries to send an event on ch. Drops the event if the buffer is full.
// May return false if ctx is done, but this is best-effort — callers must
// not rely on the return value to detect cancellation. The poll loop checks
// ctx.Done() independently on each iteration.
func Send(ctx context.Context, ch chan<- imds.Event, ev imds.Event) bool {
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
func PollWatch(ctx context.Context, cfg imds.WatchConfig, fetch func(context.Context) (*imds.InstanceMetadata, error)) (<-chan imds.Event, error) {
	interval := cfg.Interval
	if interval < 0 {
		return nil, fmt.Errorf("imds: invalid poll interval %v", interval)
	}
	if interval == 0 {
		interval = defaultPollInterval
	}

	// Buffered to decouple poll rate from consumer speed.
	// Events are dropped if the buffer is full (consumer too slow).
	ch := make(chan imds.Event, 32)
	go pollLoop(ctx, ch, interval, fetch)
	return ch, nil
}

func pollLoop(ctx context.Context, ch chan imds.Event, interval time.Duration, fetch func(context.Context) (*imds.InstanceMetadata, error)) {
	defer close(ch)

	// Initial fetch may fail (e.g. IMDS not ready on boot). Emit error
	// and continue polling — don't kill the watch on a transient failure.
	var old *imds.InstanceMetadata
	if m, err := fetch(ctx); err != nil {
		Send(ctx, ch, ErrorEvent(err))
	} else {
		old = m
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

func pollOnce(ctx context.Context, ch chan<- imds.Event, old *imds.InstanceMetadata, fetch func(context.Context) (*imds.InstanceMetadata, error)) *imds.InstanceMetadata {
	cur, err := fetch(ctx)
	if err != nil {
		Send(ctx, ch, ErrorEvent(err))
		return old
	}

	changed := DiffMetadata(old, cur)
	if len(changed) > 0 {
		Send(ctx, ch, ChangeEvent(old, cur, changed))
	}
	return cur
}

// dynamicField defines a field that can change on a running instance.
type dynamicField struct {
	name    string
	changed func(old, new *imds.InstanceMetadata) bool
}

var watchedFields = []dynamicField{
	{"interfaces", func(o, n *imds.InstanceMetadata) bool { return !reflect.DeepEqual(o.Interfaces, n.Interfaces) }},
	{"tags", func(o, n *imds.InstanceMetadata) bool { return !reflect.DeepEqual(o.Tags, n.Tags) }},
	{"spot_terminating", func(o, n *imds.InstanceMetadata) bool { return o.SpotTerminating != n.SpotTerminating }},
	{"maintenance_events", func(o, n *imds.InstanceMetadata) bool { return !reflect.DeepEqual(o.MaintenanceEvents, n.MaintenanceEvents) }},
	{"additional_properties", func(o, n *imds.InstanceMetadata) bool { return !reflect.DeepEqual(o.AdditionalProperties, n.AdditionalProperties) }},
}

// DiffMetadata compares dynamic fields between two InstanceMetadata values.
// Static fields (instance info) are never compared — they don't change on a running instance.
func DiffMetadata(old, new *imds.InstanceMetadata) []string {
	if new == nil {
		return nil
	}
	if old == nil {
		// First successful fetch — report all dynamic fields as changed.
		var all []string
		for _, f := range watchedFields {
			all = append(all, f.name)
		}
		return all
	}
	var changed []string
	for _, f := range watchedFields {
		if f.changed(old, new) {
			changed = append(changed, f.name)
		}
	}
	return changed
}
