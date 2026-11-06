// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package deploy provides a dependency-graph runner for kube-init's
// system-component installation: a component runs the moment its
// declared deps reach Ready, bounded by MaxParallel.
package deploy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

// Graph is an unordered collection of Components plus options that
// control how Run executes them.
type Graph struct {
	// Components are the units of work. Order does not matter;
	// dependencies are expressed via Component.PolicyDeps (and, in a
	// future revision, via structural rules over Manifests).
	Components []Component

	// MaxParallel caps how many components run concurrently. 0
	// (default) means unbounded — every ready component starts
	// immediately. Set to 1 to force serial execution (useful for
	// debugging).
	MaxParallel int

	// RetryCtx is the parent context for BestEffort background
	// retries. Non-nil enables retries per RetryPolicy: a component
	// whose Apply fails or whose Ready times out under
	// BestEffort=true is re-attempted in a goroutine tied to this
	// ctx, so the retry loop survives Graph.Run's return.
	//
	// Callers must pass a ctx whose lifetime is at least as long
	// as the daemon that owns the Graph — passing Run's own ctx
	// (typically a per-invocation workCtx) defeats the purpose
	// because retries die the moment Run returns.
	//
	// Nil (default) disables retries: log the failure, continue.
	RetryCtx context.Context

	// RetryPolicy overrides the default backoff schedule for
	// RetryCtx-driven retries. Zero-valued fields fall back to
	// defaultRetryPolicy.
	RetryPolicy RetryPolicy

	// RetryCallback fires per retry attempt with (name, attempt,
	// err). Optional — pubsub-status publishers wire this to
	// surface "X still retrying, attempt N/6" without tailing
	// logs.
	RetryCallback RetryCallback

	// BeforeApply, when set, is called with the component name
	// immediately before that component's Apply runs, and may block
	// for as long as it likes. Its purpose is the operator
	// breakpoint (state.WaitForItem): hold the graph just before a
	// named component installs so a device can be inspected at that
	// point. Kept as a hook rather than a direct call so this
	// package stays free of filesystem paths.
	//
	// Blocking here holds one component and everything downstream of
	// it; peers with no dependency on it keep running.
	BeforeApply func(ctx context.Context, name string)

	// Bus receives the signals components emit, and serves Awaits for
	// signals whose producer is outside the graph. Pass a
	// daemon-scoped Bus to let the control socket report readiness;
	// when nil a throwaway Bus is created for the run.
	Bus *Bus

	// Retries, when non-nil, counts the BestEffort retry loops still
	// running after Run returns. A caller about to do something that
	// destroys in-flight work — stopping k3s cancels every image pull
	// under it — uses AwaitQuiescent to hold off while a component is
	// still converging.
	Retries *RetryTracker
}

// Run plans the graph, resolves edges, and executes components as
// their dependencies become satisfied. Blocks until every
// non-BestEffort component has reached Ready (or one has failed) or
// until ctx is cancelled.
//
// Behaviour summary:
//   - Components with no deps start immediately.
//   - Each component's Apply runs first; on success its Ready runs.
//   - A component becomes "satisfied" once Apply and Ready both
//     succeed (or are skipped, or BestEffort'd through).
//   - The first non-BestEffort failure cancels a derived context
//     shared by every in-flight component; peers observe ctx.Done
//     and terminate. Run returns the first error (alphabetical);
//     secondary errors are appended.
//   - Caller ctx cancellation aborts all in-flight components and
//     surfaces as ctx.Err().
//
// Validation errors (empty name, duplicate, unknown dep, self-dep,
// cycle) are returned before any component runs.
func (g Graph) Run(ctx context.Context) error {
	edges, order, awaits, err := g.plan()
	if err != nil {
		return err
	}

	if len(g.Components) == 0 {
		return nil
	}

	log.Printf("deploy: graph resolved with %d component(s) and %d edge(s)",
		len(g.Components), len(edges))
	for _, e := range edges {
		log.Printf("deploy: edge %s → %s (%s)", e.From, e.To, e.Rule)
	}

	return g.runScheduler(ctx, order, edges, awaits)
}

// Edges returns the resolved dependency edges without running the
// graph. Errors surface exactly as in Run's validation pass.
func (g Graph) Edges() ([]Edge, error) {
	edges, _, _, err := g.plan()
	return edges, err
}

// plan validates the graph, derives structural edges from Manifests,
// merges in PolicyDeps, checks for cycles, and returns:
//   - edges: the full list of dependency edges (each tagged with its
//     origin rule) in a deterministic order (sort by From, To).
//   - order: the component names in a topologically stable order —
//     used only by tests / diagnostics that want a fixed traversal.
//
// The scheduler does NOT consume `order` directly; it drives itself
// off remaining-dep counts derived from `edges`.
func (g Graph) plan() (edges []Edge, order []string, awaits map[string][]Signal, err error) {
	if len(g.Components) == 0 {
		return nil, nil, nil, nil
	}

	byName := make(map[string]*Component, len(g.Components))
	for i := range g.Components {
		c := &g.Components[i]
		if c.Name == "" {
			return nil, nil, nil, errors.New("deploy: component has empty Name")
		}
		if _, dup := byName[c.Name]; dup {
			return nil, nil, nil, fmt.Errorf("deploy: duplicate component name %q", c.Name)
		}
		byName[c.Name] = c
	}

	// Signals: Requires against an in-graph producer becomes an edge;
	// against a registered external producer becomes a runtime Await.
	signalEdges, awaits, err := resolveSignals(g.Components)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("deploy: resolve signals: %w", err)
	}
	edges = append(edges, signalEdges...)

	// PolicyDeps: ordering that is not a readiness condition.
	// Validated against byName.
	for _, c := range g.Components {
		for _, d := range c.PolicyDeps {
			if d == c.Name {
				return nil, nil, nil, fmt.Errorf(
					"deploy: component %q depends on itself", c.Name)
			}
			if _, ok := byName[d]; !ok {
				return nil, nil, nil, fmt.Errorf(
					"deploy: component %q PolicyDeps names unknown component %q",
					c.Name, d)
			}
			edges = append(edges, Edge{From: d, To: c.Name, Rule: "policy"})
		}
	}

	// Deterministic edge order for logs / tests.
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].To != edges[j].To {
			return edges[i].To < edges[j].To
		}
		return edges[i].Rule < edges[j].Rule
	})

	// Cycle detection + topological ordering (Kahn's algorithm).
	// This also validates that edges don't reference unknown names,
	// but structural and policy passes have already validated that.
	inDegree := make(map[string]int, len(g.Components))
	children := make(map[string][]string, len(g.Components))
	for _, c := range g.Components {
		inDegree[c.Name] = 0
	}
	// Deduplicate edges by (From, To) — structural + policy may
	// legitimately name the same edge twice; each rule still logs
	// once, but the counting-arithmetic below needs uniques.
	seen := make(map[string]bool, len(edges))
	for _, e := range edges {
		key := e.From + "→" + e.To
		if seen[key] {
			continue
		}
		seen[key] = true
		inDegree[e.To]++
		children[e.From] = append(children[e.From], e.To)
	}

	var ready []string
	for name, d := range inDegree {
		if d == 0 {
			ready = append(ready, name)
		}
	}
	sort.Strings(ready)

	remaining := len(g.Components)
	for len(ready) > 0 {
		n := ready[0]
		ready = ready[1:]
		order = append(order, n)
		remaining--
		// Enqueue children whose remaining in-degree drops to zero.
		kids := append([]string(nil), children[n]...)
		sort.Strings(kids)
		for _, k := range kids {
			inDegree[k]--
			if inDegree[k] == 0 {
				ready = append(ready, k)
			}
		}
	}
	if remaining > 0 {
		stuck := make([]string, 0, remaining)
		for name, d := range inDegree {
			if d > 0 {
				stuck = append(stuck, name)
			}
		}
		sort.Strings(stuck)
		return nil, nil, nil, fmt.Errorf(
			"deploy: dependency cycle detected; unscheduled components: %s",
			strings.Join(stuck, ", "))
	}
	return edges, order, awaits, nil
}

// runScheduler executes the components as their dependencies become
// satisfied. A component starts the moment its individual deps are
// Ready.
//
// Concurrency is bounded by g.MaxParallel (unbounded when zero).
// The first non-BestEffort failure cancels the graph ctx and drains
// in-flight goroutines before returning.
func (g Graph) runScheduler(
	ctx context.Context, order []string, edges []Edge,
	awaits map[string][]Signal,
) error {
	bus := g.Bus
	if bus == nil {
		bus = NewBus()
	}

	// Build lookup tables from the plan.
	byName := make(map[string]*Component, len(g.Components))
	for i := range g.Components {
		byName[g.Components[i].Name] = &g.Components[i]
	}
	remainingDeps := make(map[string]int, len(g.Components))
	children := make(map[string][]string, len(g.Components))
	seen := make(map[string]bool, len(edges))
	for _, e := range edges {
		key := e.From + "→" + e.To
		if seen[key] {
			continue
		}
		seen[key] = true
		remainingDeps[e.To]++
		children[e.From] = append(children[e.From], e.To)
	}

	// Derived ctx we can cancel on first non-BestEffort failure to
	// propagate stop to every in-flight goroutine.
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	// Optional in-flight semaphore.
	var sem chan struct{}
	if g.MaxParallel > 0 {
		sem = make(chan struct{}, g.MaxParallel)
	}

	// Result channel for completed components. Buffered so a
	// completing goroutine never blocks on the coordinator.
	results := make(chan result, len(g.Components))

	// launched / completed counters are single-threaded (only the
	// coordinator loop below touches them). The runner is done when
	// completed == launched — every scheduled goroutine has emitted
	// its result. Components whose deps failed simply never get
	// launched, so they're excluded from the count. This avoids the
	// WaitGroup-reuse race that a "wait for all + close(results)"
	// helper goroutine would introduce (Add(1) from the coordinator
	// after Wait() has already returned is a Go runtime panic).
	launched := 0
	completed := 0

	// launch spawns a component's Apply+Ready in a bounded
	// goroutine. Increments launched (coordinator-only, no race).
	launch := func(name string) {
		c := byName[name]
		launched++
		go func() {
			if sem != nil {
				select {
				case sem <- struct{}{}:
				case <-runCtx.Done():
					results <- result{name: name, err: runCtx.Err(), step: "queue"}
					return
				}
			}
			// The slot covers Apply only. Ready blocks on informer
			// watches rather than working, and holding a slot across a
			// multi-minute convergence wait would let one slow
			// component stall every queued peer. released is touched
			// by this goroutine alone, so no synchronisation is needed.
			released := false
			release := func() {
				if sem != nil && !released {
					released = true
					<-sem
				}
			}
			defer release()

			runOne(runCtx, c, results, g.RetryCtx, g.RetryPolicy, g.RetryCallback,
				bus, g.Retries, awaits[c.Name], release, g.BeforeApply)
		}()
	}

	// Kick off every root component (zero remaining deps).
	roots := make([]string, 0)
	for _, name := range order {
		if remainingDeps[name] == 0 {
			roots = append(roots, name)
		}
	}
	for _, name := range roots {
		launch(name)
	}

	// Coordinator loop: consume results, enqueue newly-unblocked
	// children, collect errors. First non-BestEffort failure cancels
	// runCtx (peers observe promptly); errors continue to drain so
	// no goroutine leaks.
	var firstErr error
	var otherErrs []result
	for completed < launched {
		r := <-results
		completed++
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
				cancelRun()
			}
			otherErrs = append(otherErrs, r)
			// Do NOT enqueue children of a failed component — their
			// remainingDeps entry stays > 0, so they never launch and
			// don't contribute to the completed==launched exit
			// condition. Peers already in-flight will observe runCtx.Done
			// and return promptly.
			continue
		}
		// r is a success — enqueue every child whose remaining
		// in-degree drops to zero.
		kids := append([]string(nil), children[r.name]...)
		sort.Strings(kids)
		for _, k := range kids {
			remainingDeps[k]--
			if remainingDeps[k] == 0 {
				launch(k)
			}
		}
	}

	if firstErr == nil {
		return nil
	}
	// Return the alphabetically-first error with the rest appended for context.
	sort.Slice(otherErrs, func(i, j int) bool { return otherErrs[i].name < otherErrs[j].name })
	head := otherErrs[0]
	if len(otherErrs) == 1 {
		return fmt.Errorf("component %q %s: %w", head.name, head.step, head.err)
	}
	rest := make([]string, 0, len(otherErrs)-1)
	for _, e := range otherErrs[1:] {
		rest = append(rest, fmt.Sprintf("%q %s: %v", e.name, e.step, e.err))
	}
	return fmt.Errorf("component %q %s: %w (also: %s)",
		head.name, head.step, head.err, strings.Join(rest, "; "))
}

// result is what runOne emits per component. name identifies the
// component; step is "apply", "ready", "queue", or "" on success;
// err is nil on success.
type result struct {
	name string
	step string
	err  error
}

// runOne executes Apply then (if non-nil) Ready for a single
// component. BestEffort components never emit a non-nil err: their
// failures are logged with a "BEST-EFFORT" prefix, downstream deps
// are unblocked immediately, and — if retryCtx is non-nil — a
// background goroutine is spawned to keep re-attempting Apply/Ready
// per retryPolicy (design §4.5.4). The background loop lives until
// success, retryCtx cancel, or MaxAttempts.
func runOne(
	ctx context.Context, c *Component, results chan<- result,
	retryCtx context.Context, retryPolicy RetryPolicy, retryCallback RetryCallback,
	bus *Bus, retries *RetryTracker, awaitSigs []Signal, releaseSlot func(),
	beforeApply func(context.Context, string),
) {
	start := time.Now()

	// Signals with an external producer have no edge to gate on, so
	// they are waited for here.
	if len(awaitSigs) > 0 {
		log.Printf("deploy: %s: awaiting external signal(s) %v", c.Name, awaitSigs)
		if err := bus.Await(ctx, awaitSigs...); err != nil {
			if c.BestEffort {
				log.Printf("deploy: %s: BEST-EFFORT await FAILED (treated as success, downstream NOT blocked): %v",
					c.Name, err)
				spawnBestEffortRetry(retryCtx, c, retryPolicy, retryCallback, bus, retries, err, "await")
				results <- result{name: c.Name}
				return
			}
			log.Printf("deploy: %s: await FAILED: %v", c.Name, err)
			results <- result{name: c.Name, step: "await", err: err}
			return
		}
	}

	// emit publishes this component's signals. Called only on genuine
	// success — a BestEffort failure releases dependents via its edge
	// but must not claim a readiness that does not hold.
	emit := func() {
		for _, s := range c.Emits {
			bus.Emit(s)
		}
	}

	if c.Apply != nil {
		if beforeApply != nil {
			beforeApply(ctx, c.Name)
		}
		log.Printf("deploy: %s: apply starting", c.Name)
		if err := c.Apply(ctx); err != nil {
			if c.BestEffort {
				log.Printf("deploy: %s: BEST-EFFORT apply FAILED after %s (treated as success, downstream NOT blocked): %v",
					c.Name, time.Since(start).Round(time.Millisecond), err)
				spawnBestEffortRetry(retryCtx, c, retryPolicy, retryCallback, bus, retries, err, "apply")
				results <- result{name: c.Name}
				return
			}
			log.Printf("deploy: %s: apply FAILED after %s: %v",
				c.Name, time.Since(start).Round(time.Millisecond), err)
			results <- result{name: c.Name, step: "apply", err: err}
			return
		}
		log.Printf("deploy: %s: apply complete in %s",
			c.Name, time.Since(start).Round(time.Millisecond))
	}

	// Apply is done, so hand the concurrency slot to a queued peer
	// before entering the (cheap, watch-driven) Ready wait.
	releaseSlot()

	if c.Ready == nil {
		emit()
		results <- result{name: c.Name}
		return
	}

	readyTimeout := c.ReadyTimeout
	if c.BestEffort && readyTimeout <= 0 {
		readyTimeout = defaultReadyTimeout
	}

	readyStart := time.Now()
	log.Printf("deploy: %s: ready starting", c.Name)
	if err := runReadyGuarded(ctx, c, readyTimeout); err != nil {
		if c.BestEffort {
			elapsed := time.Since(readyStart).Round(time.Millisecond)
			switch {
			case errors.Is(err, ErrNoProgress):
				log.Printf("deploy: %s: BEST-EFFORT ready STALLED after %s (no progress for %s, treated as success, downstream NOT blocked): %v",
					c.Name, elapsed, readyTimeout, err)
			case errors.Is(err, context.DeadlineExceeded):
				log.Printf("deploy: %s: BEST-EFFORT ready TIMED OUT after %s (cap=%s, treated as success, downstream NOT blocked): %v",
					c.Name, elapsed, readyTimeout, err)
			default:
				log.Printf("deploy: %s: BEST-EFFORT ready FAILED after %s (treated as success, downstream NOT blocked): %v",
					c.Name, elapsed, err)
			}
			spawnBestEffortRetry(retryCtx, c, retryPolicy, retryCallback, bus, retries, err, "ready")
			results <- result{name: c.Name}
			return
		}
		log.Printf("deploy: %s: ready FAILED after %s: %v",
			c.Name, time.Since(readyStart).Round(time.Millisecond), err)
		results <- result{name: c.Name, step: "ready", err: err}
		return
	}
	log.Printf("deploy: %s: ready complete in %s (total %s)",
		c.Name, time.Since(readyStart).Round(time.Millisecond),
		time.Since(start).Round(time.Millisecond))
	emit()
	results <- result{name: c.Name}
}
