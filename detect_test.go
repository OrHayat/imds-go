package imds

import (
	"context"
	"errors"
	"testing"
)

type mockProvider struct {
	id        ID
	probeOK   bool
	probeErr  error
	metadata  *InstanceMetadata
	watchChan chan Event
}

func (m *mockProvider) ID() ID { return m.id }
func (m *mockProvider) Probe(ctx context.Context) (bool, error) {
	return m.probeOK, m.probeErr
}
func (m *mockProvider) GetMetadata(ctx context.Context) (*InstanceMetadata, error) {
	return m.metadata, nil
}
func (m *mockProvider) Watch(ctx context.Context, cfg WatchConfig) (<-chan Event, error) {
	return m.watchChan, nil
}

func TestDetect_MatchesProvider(t *testing.T) {
	aws := &mockProvider{id: "aws", probeOK: true}
	p, err := Detect(t.Context(), aws)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID() != "aws" {
		t.Fatalf("expected aws, got %s", p.ID())
	}
}

func TestDetect_SkipsFalseNil(t *testing.T) {
	notMe := &mockProvider{id: "azure", probeOK: false}
	isMe := &mockProvider{id: "aws", probeOK: true}
	p, err := Detect(t.Context(), notMe, isMe)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID() != "aws" {
		t.Fatalf("expected aws, got %s", p.ID())
	}
}

func TestDetect_AllFalseNil(t *testing.T) {
	a := &mockProvider{id: "aws", probeOK: false}
	b := &mockProvider{id: "azure", probeOK: false}
	_, err := Detect(t.Context(), a, b)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrNoProvider) {
		t.Fatalf("expected ErrNoProvider, got %v", err)
	}
}

func TestDetect_ProbeError(t *testing.T) {
	fail := &mockProvider{id: "aws", probeOK: false, probeErr: errors.New("timeout")}
	_, err := Detect(t.Context(), fail)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrNoProvider) {
		t.Fatalf("expected ErrNoProvider, got %v", err)
	}
}

func TestDetect_ErrorAndMatch(t *testing.T) {
	fail := &mockProvider{id: "azure", probeOK: false, probeErr: errors.New("timeout")}
	ok := &mockProvider{id: "aws", probeOK: true}
	p, err := Detect(t.Context(), fail, ok)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID() != "aws" {
		t.Fatalf("expected aws, got %s", p.ID())
	}
}

func TestDetect_Empty(t *testing.T) {
	_, err := Detect(t.Context())
	if !errors.Is(err, ErrNoProvider) {
		t.Fatalf("expected ErrNoProvider, got %v", err)
	}
}

func TestDetect_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	slow := &mockProvider{id: "aws", probeOK: false, probeErr: context.Canceled}
	_, err := Detect(ctx, slow)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDetectPriority_HighPriorityFirst(t *testing.T) {
	custom := &mockProvider{id: "custom", probeOK: true}
	aws := &mockProvider{id: "aws", probeOK: true}
	p, err := DetectPriority(t.Context(),
		Priority(2, aws),
		Priority(1, custom),
	)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID() != "custom" {
		t.Fatalf("expected custom (priority 1), got %s", p.ID())
	}
}

func TestDetectPriority_FallsToNextGroup(t *testing.T) {
	notMe := &mockProvider{id: "custom", probeOK: false}
	aws := &mockProvider{id: "aws", probeOK: true}
	p, err := DetectPriority(t.Context(),
		Priority(1, notMe),
		Priority(2, aws),
	)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID() != "aws" {
		t.Fatalf("expected aws, got %s", p.ID())
	}
}

func TestDetectPriority_AllFail(t *testing.T) {
	a := &mockProvider{id: "a", probeOK: false}
	b := &mockProvider{id: "b", probeOK: false}
	_, err := DetectPriority(t.Context(),
		Priority(1, a),
		Priority(2, b),
	)
	if !errors.Is(err, ErrNoProvider) {
		t.Fatalf("expected ErrNoProvider, got %v", err)
	}
}

func TestDetectPriority_Empty(t *testing.T) {
	_, err := DetectPriority(t.Context())
	if !errors.Is(err, ErrNoProvider) {
		t.Fatalf("expected ErrNoProvider, got %v", err)
	}
}

func TestDetect_BothMatchPrefersFirst(t *testing.T) {
	// Both providers match — should deterministically return the first one.
	a := &mockProvider{id: "first", probeOK: true}
	b := &mockProvider{id: "second", probeOK: true}

	// Run multiple times to catch non-determinism
	for range 20 {
		p, err := Detect(t.Context(), a, b)
		if err != nil {
			t.Fatal(err)
		}
		if p.ID() != "first" {
			t.Fatalf("expected first, got %s", p.ID())
		}
	}
}
