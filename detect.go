package imds

import (
	"context"
	"errors"
	"sort"
	"sync"
)

// ProbeGroup holds providers with an explicit priority level.
type ProbeGroup struct {
	level     int
	providers []Provider
}

func (g ProbeGroup) probeProviders() []Provider { return g.providers }
func (g ProbeGroup) probePriority() int         { return g.level }

// Priority creates a probe group with the given priority level.
// Lower numbers run first. Providers within a group run concurrently.
func Priority(level int, providers ...Provider) ProbeGroup {
	return ProbeGroup{level: level, providers: providers}
}

// Detect probes providers to determine which cloud the instance is running on.
// Accepts both Provider values (priority 0) and ProbeGroup values.
// Groups are probed in priority order (lowest first). Within a group,
// all providers probe concurrently and the first match wins.
// Returns ErrNoProvider with aggregated probe errors if no provider matches.
func Detect(ctx context.Context, targets ...ProbeTarget) (Provider, error) {
	if len(targets) == 0 {
		return nil, ErrNoProvider
	}

	groups := groupByPriority(targets)
	var allErrors []error

	for _, g := range groups {
		p, errs := probeGroup(ctx, g)
		if p != nil {
			return p, nil
		}
		allErrors = append(allErrors, errs...)
	}

	return nil, errors.Join(append([]error{ErrNoProvider}, allErrors...)...)
}

type priorityGroup struct {
	level     int
	providers []Provider
}

func groupByPriority(targets []ProbeTarget) []priorityGroup {
	m := make(map[int][]Provider)
	for _, t := range targets {
		level := t.probePriority()
		m[level] = append(m[level], t.probeProviders()...)
	}

	groups := make([]priorityGroup, 0, len(m))
	for level, providers := range m {
		groups = append(groups, priorityGroup{level: level, providers: providers})
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].level < groups[j].level
	})
	return groups
}

type probeResult struct {
	provider Provider
	err      error
}

func probeGroup(ctx context.Context, g priorityGroup) (Provider, []error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan probeResult, len(g.providers))
	var wg sync.WaitGroup

	for _, p := range g.providers {
		wg.Add(1)
		go func(p Provider) {
			defer wg.Done()
			ok, err := p.Probe(ctx)
			results <- probeResult{provider: p, err: err}
			if ok && err == nil {
				cancel()
			}
		}(p)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var matched Provider
	var errs []error
	for r := range results {
		if r.err != nil {
			errs = append(errs, r.err)
		} else if matched == nil {
			matched = r.provider
		}
	}
	return matched, errs
}
