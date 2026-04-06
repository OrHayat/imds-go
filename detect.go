package imds

import (
	"context"
	"errors"
	"sort"
	"sync"
)

// Detect probes providers concurrently to determine which cloud the instance
// is running on. All providers run in parallel, first match wins.
// Returns ErrNoProvider with aggregated probe errors if no provider matches.
func Detect(ctx context.Context, providers ...Provider) (Provider, error) {
	if len(providers) == 0 {
		return nil, ErrNoProvider
	}
	p, errs := probeAll(ctx, providers)
	if p != nil {
		return p, nil
	}
	return nil, errors.Join(append([]error{ErrNoProvider}, errs...)...)
}

// DetectPriority probes providers in priority groups.
// Groups are probed in priority order (lowest number first).
// Within a group, all providers probe concurrently and the first match wins.
// If no provider in a group matches, the next group is tried.
func DetectPriority(ctx context.Context, groups ...ProbeGroup) (Provider, error) {
	if len(groups) == 0 {
		return nil, ErrNoProvider
	}

	sort.Slice(groups, func(i, j int) bool {
		return groups[i].level < groups[j].level
	})

	var allErrors []error
	for _, g := range groups {
		p, errs := probeAll(ctx, g.providers)
		if p != nil {
			return p, nil
		}
		allErrors = append(allErrors, errs...)
	}

	return nil, errors.Join(append([]error{ErrNoProvider}, allErrors...)...)
}

type probeResult struct {
	index    int
	provider Provider
	ok       bool
	err      error
}

// probeAll runs all providers concurrently. If multiple match,
// the one earliest in the input slice wins (deterministic).
func probeAll(ctx context.Context, providers []Provider) (Provider, []error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan probeResult, len(providers))
	var wg sync.WaitGroup

	for i, p := range providers {
		wg.Add(1)
		go func(i int, p Provider) {
			defer wg.Done()
			ok, err := p.Probe(ctx)
			results <- probeResult{index: i, provider: p, ok: ok, err: err}
			if ok && err == nil {
				cancel()
			}
		}(i, p)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	matchedIdx := -1
	var matched Provider
	var errs []error
	for r := range results {
		if r.err != nil {
			errs = append(errs, r.err)
		} else if r.ok && (matched == nil || r.index < matchedIdx) {
			matched = r.provider
			matchedIdx = r.index
		}
	}
	return matched, errs
}
