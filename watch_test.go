package imds

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDiffMetadata_NoChanges(t *testing.T) {
	m := &InstanceMetadata{
		Interfaces: []NetworkInterface{{PrivateIPv4s: []string{"10.0.0.1"}}},
		Tags:       map[string]string{"env": "prod"},
	}
	if changed := diffMetadata(m, m); len(changed) != 0 {
		t.Fatalf("expected no changes, got %v", changed)
	}
}

func TestDiffMetadata_InterfaceChange(t *testing.T) {
	old := &InstanceMetadata{
		Interfaces: []NetworkInterface{{PrivateIPv4s: []string{"10.0.0.1"}}},
	}
	new := &InstanceMetadata{
		Interfaces: []NetworkInterface{{PrivateIPv4s: []string{"10.0.0.2"}}},
	}
	changed := diffMetadata(old, new)
	if len(changed) != 1 || changed[0] != "interfaces" {
		t.Fatalf("expected [interfaces], got %v", changed)
	}
}

func TestDiffMetadata_TagChange(t *testing.T) {
	old := &InstanceMetadata{Tags: map[string]string{"env": "prod"}}
	new := &InstanceMetadata{Tags: map[string]string{"env": "staging"}}
	changed := diffMetadata(old, new)
	if len(changed) != 1 || changed[0] != "tags" {
		t.Fatalf("expected [tags], got %v", changed)
	}
}

func TestDiffMetadata_SpotTerminating(t *testing.T) {
	old := &InstanceMetadata{SpotTerminating: false}
	new := &InstanceMetadata{SpotTerminating: true}
	changed := diffMetadata(old, new)
	if len(changed) != 1 || changed[0] != "spot_terminating" {
		t.Fatalf("expected [spot_terminating], got %v", changed)
	}
}

func TestDiffMetadata_MaintenanceEvents(t *testing.T) {
	old := &InstanceMetadata{}
	new := &InstanceMetadata{
		MaintenanceEvents: []MaintenanceEvent{{Type: "reboot", Status: "scheduled"}},
	}
	changed := diffMetadata(old, new)
	if len(changed) != 1 || changed[0] != "maintenance_events" {
		t.Fatalf("expected [maintenance_events], got %v", changed)
	}
}

func TestDiffMetadata_AdditionalProperties(t *testing.T) {
	old := &InstanceMetadata{AdditionalProperties: map[string]any{"k": "v1"}}
	new := &InstanceMetadata{AdditionalProperties: map[string]any{"k": "v2"}}
	changed := diffMetadata(old, new)
	if len(changed) != 1 || changed[0] != "additional_properties" {
		t.Fatalf("expected [additional_properties], got %v", changed)
	}
}

func TestDiffMetadata_MultipleChanges(t *testing.T) {
	old := &InstanceMetadata{
		Tags:            map[string]string{"env": "prod"},
		SpotTerminating: false,
	}
	new := &InstanceMetadata{
		Tags:            map[string]string{"env": "staging"},
		SpotTerminating: true,
	}
	changed := diffMetadata(old, new)
	if len(changed) != 2 {
		t.Fatalf("expected 2 changes, got %v", changed)
	}
}

func TestDiffMetadata_NilOld(t *testing.T) {
	new := &InstanceMetadata{Tags: map[string]string{"v": "1"}}
	changed := diffMetadata(nil, new)
	if len(changed) != len(watchedFields) {
		t.Fatalf("expected all %d fields, got %v", len(watchedFields), changed)
	}
}

func TestDiffMetadata_NilNew(t *testing.T) {
	old := &InstanceMetadata{Tags: map[string]string{"v": "1"}}
	changed := diffMetadata(old, nil)
	if len(changed) != 0 {
		t.Fatalf("expected no changes on nil new, got %v", changed)
	}
}

func TestDiffMetadata_BothNil(t *testing.T) {
	changed := diffMetadata(nil, nil)
	if len(changed) != 0 {
		t.Fatalf("expected no changes on both nil, got %v", changed)
	}
}

func TestDiffMetadata_StaticFieldsIgnored(t *testing.T) {
	old := &InstanceMetadata{Instance: InstanceInfo{ID: "i-111", Hostname: "a"}}
	new := &InstanceMetadata{Instance: InstanceInfo{ID: "i-222", Hostname: "b"}}
	changed := diffMetadata(old, new)
	if len(changed) != 0 {
		t.Fatalf("expected no changes for static fields, got %v", changed)
	}
}

func TestPollOnce_EmitsChangeEvent(t *testing.T) {
	old := &InstanceMetadata{Tags: map[string]string{"v": "1"}}
	cur := &InstanceMetadata{Tags: map[string]string{"v": "2"}}
	fetch := func(ctx context.Context) (*InstanceMetadata, error) { return cur, nil }

	ch := make(chan Event, 1)
	got := pollOnce(context.Background(), ch, old, fetch)

	if got != cur {
		t.Fatal("expected pollOnce to return new metadata")
	}
	ev := <-ch
	if len(ev.Changed) != 1 || ev.Changed[0] != "tags" {
		t.Fatalf("expected [tags], got %v", ev.Changed)
	}
}

func TestPollOnce_NoChangeNoEvent(t *testing.T) {
	m := &InstanceMetadata{Tags: map[string]string{"v": "1"}}
	fetch := func(ctx context.Context) (*InstanceMetadata, error) {
		return &InstanceMetadata{Tags: map[string]string{"v": "1"}}, nil
	}

	ch := make(chan Event, 1)
	got := pollOnce(context.Background(), ch, m, fetch)

	if got == m {
		t.Fatal("expected new metadata pointer even without changes")
	}
	if len(ch) != 0 {
		t.Fatal("expected no event on unchanged metadata")
	}
}

func TestPollOnce_FetchError(t *testing.T) {
	old := &InstanceMetadata{}
	fetch := func(ctx context.Context) (*InstanceMetadata, error) {
		return nil, errors.New("timeout")
	}

	ch := make(chan Event, 1)
	got := pollOnce(context.Background(), ch, old, fetch)

	if got != old {
		t.Fatal("expected old metadata returned on error")
	}
	ev := <-ch
	if ev.Err == nil || ev.ErrMessage != "timeout" {
		t.Fatalf("expected error event, got %v", ev)
	}
}

func TestPollWatch_EmitsChange(t *testing.T) {
	call := 0
	fetch := func(ctx context.Context) (*InstanceMetadata, error) {
		call++
		if call == 1 {
			return &InstanceMetadata{Tags: map[string]string{"v": "1"}}, nil
		}
		return &InstanceMetadata{Tags: map[string]string{"v": "2"}}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch, err := PollWatch(ctx, WatchConfig{Interval: 50 * time.Millisecond}, fetch)
	if err != nil {
		t.Fatal(err)
	}

	ev := <-ch
	if ev.Err != nil {
		t.Fatalf("unexpected error: %v", ev.Err)
	}
	if len(ev.Changed) != 1 || ev.Changed[0] != "tags" {
		t.Fatalf("expected [tags], got %v", ev.Changed)
	}
}

func TestPollWatch_EmitsErrorEvent(t *testing.T) {
	call := 0
	fetch := func(ctx context.Context) (*InstanceMetadata, error) {
		call++
		if call == 1 {
			return &InstanceMetadata{}, nil
		}
		return nil, errors.New("imds down")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	ch, err := PollWatch(ctx, WatchConfig{Interval: 50 * time.Millisecond}, fetch)
	if err != nil {
		t.Fatal(err)
	}

	ev := <-ch
	if ev.Err == nil {
		t.Fatal("expected error event")
	}
	if ev.ErrMessage != "imds down" {
		t.Fatalf("expected 'imds down', got %q", ev.ErrMessage)
	}
}

func TestPollWatch_ClosesOnCancel(t *testing.T) {
	fetch := func(ctx context.Context) (*InstanceMetadata, error) {
		return &InstanceMetadata{}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch, err := PollWatch(ctx, WatchConfig{Interval: 50 * time.Millisecond}, fetch)
	if err != nil {
		t.Fatal(err)
	}

	cancel()

	// Channel should close
	for ev := range ch {
		_ = ev
	}
}
