// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package deploy provides a declarative DAG runner for component
// installation in the kube-init daemon.
//
// The earlier shell-driven design expressed component ordering as a
// sequence of imperative function calls. That made dependency
// constraints implicit, gave nowhere natural to hang per-step
// readiness waits (so "apply succeeded" got conflated with "resource
// is ready"), and forced independent steps to run serially because
// the ordering contract lived in source-line order.
//
// This package replaces that with a typed graph of Nodes. Each Node
// declares a name, the names of nodes it depends on, an Apply step,
// and an optional WaitReady step. Graph.Run topologically sorts the
// graph (panics on cycle — cycles are programmer errors, not
// runtime conditions) and runs nodes in waves: a wave is the
// maximal set of nodes whose dependencies have all completed.
// Within a wave nodes run concurrently; the next wave does not
// start until every node in the current wave has finished both
// steps.
//
// The engine is intentionally small: no persistent state, no
// internal retries (retries belong inside Apply via
// kubectlx.ApplyWithBackoff), no skip-on-marker logic (idempotency
// belongs inside Apply too). Callers compose those pieces.
package deploy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// defaultBestEffortWaitReadyTimeout caps a BestEffort Node's
// WaitReady step when BestEffortWaitReadyTimeout is left at zero.
// Chosen to be long enough for a healthy controller to converge on
// a modestly-loaded node but short enough that a stuck
// best-effort wait does not visibly delay later phases.
const defaultBestEffortWaitReadyTimeout = 30 * time.Second

// StepFunc is the signature of an Apply or WaitReady step. Both are
// cancelled via the caller's context.
type StepFunc func(ctx context.Context) error

// Node is a single unit of work in the deploy graph.
type Node struct {
	// Name uniquely identifies the node. Used for dependency
	// resolution and log/error messages. Must be non-empty and
	// unique within a graph.
	Name string

	// Deps is the list of node names that must complete (both Apply
	// and WaitReady) before this node's Apply runs. References to
	// nodes not in the graph cause Run to return an error.
	Deps []string

	// Apply performs the kubectl apply (or equivalent) for this
	// node. Required.
	Apply StepFunc

	// WaitReady is the typed readiness wait that must succeed before
	// dependent nodes can start. Optional: leave nil for terminal
	// work whose readiness is implied by Apply (RBAC, ConfigMaps,
	// plans consumed by an already-Ready controller, ...).
	WaitReady StepFunc

	// BestEffort, when true, downgrades any error from Apply or
	// WaitReady to a logged warning. Downstream nodes that depend
	// on this one are NOT blocked, the wave is NOT cancelled, and
	// Run does not return an error on this node's behalf.
	//
	// Use for optional components whose failure should not gate the
	// rest of the deploy: subsequent steady-state ticks will
	// reconcile, and a failed first-boot apply shouldn't halt the
	// daemon.
	//
	// BestEffort applies to the entire node, not just one step. If
	// Apply errors, WaitReady is skipped (there is nothing to wait
	// on); both the error and the skip are logged.
	BestEffort bool

	// BestEffortWaitReadyTimeout caps how long WaitReady may run on
	// a BestEffort node before the wave abandons it. Ignored when
	// BestEffort is false (the caller's ctx governs in that case).
	//
	// Without this cap a BestEffort node whose WaitReady relies on a
	// long kubectl-wait timeout could hold the whole wave for that
	// full timeout, defeating the point of marking it best-effort.
	//
	// Zero applies defaultBestEffortWaitReadyTimeout.
	BestEffortWaitReadyTimeout time.Duration
}

// Graph is an unordered collection of Nodes plus options that
// control how Run executes them.
type Graph struct {
	// Nodes are the units of work. Order does not matter;
	// dependencies are expressed via Node.Deps.
	Nodes []Node

	// MaxParallel caps how many nodes within a single wave run
	// concurrently. 0 (default) means unbounded — every independent
	// node in a wave starts immediately. Set to 1 to force serial
	// execution within a wave (useful for debugging).
	MaxParallel int
}

// Run topologically sorts the graph and executes nodes wave by wave.
//
// Behaviour:
//   - Nodes within a wave run concurrently (subject to MaxParallel).
//   - Each node's Apply runs first; on success its WaitReady runs.
//   - A wave completes only after every node has finished both
//     steps. The next wave does not start until then.
//   - The first node failure cancels a derived context shared by
//     all nodes in the same wave so peers stop promptly. Other
//     waves never start. Run returns the first error (with node
//     name and step prefixed); secondary errors are appended.
//   - Caller's ctx cancellation aborts all in-flight nodes and
//     returns ctx.Err().
//
// Validation errors (duplicate name, missing dep, empty Apply,
// cycle) are returned before any node runs.
func (g Graph) Run(ctx context.Context) error {
	waves, err := g.plan()
	if err != nil {
		return err
	}

	log.Printf("deploy: executing graph with %d nodes in %d wave(s)",
		len(g.Nodes), len(waves))
	for i, wave := range waves {
		names := make([]string, len(wave))
		for j, n := range wave {
			names[j] = n.Name
		}
		log.Printf("deploy: wave %d/%d starting (%d node(s): %s)",
			i+1, len(waves), len(wave), strings.Join(names, ", "))
		start := time.Now()
		if err := g.runWave(ctx, wave); err != nil {
			return fmt.Errorf("wave %d/%d: %w", i+1, len(waves), err)
		}
		log.Printf("deploy: wave %d/%d complete in %s",
			i+1, len(waves), time.Since(start).Round(time.Millisecond))
	}
	log.Printf("deploy: all %d node(s) complete", len(g.Nodes))
	return nil
}

// plan validates the graph and returns a deterministic wave
// schedule. A "wave" is the set of nodes whose dependencies have
// all been scheduled in earlier waves; within a wave nodes are
// independent. Within-wave order is alphabetical by name so logs
// and test assertions are stable.
func (g Graph) plan() ([][]Node, error) {
	if len(g.Nodes) == 0 {
		return nil, nil
	}

	byName := make(map[string]Node, len(g.Nodes))
	for _, n := range g.Nodes {
		if n.Name == "" {
			return nil, errors.New("deploy: node has empty Name")
		}
		if _, dup := byName[n.Name]; dup {
			return nil, fmt.Errorf("deploy: duplicate node name %q", n.Name)
		}
		if n.Apply == nil {
			return nil, fmt.Errorf("deploy: node %q has nil Apply", n.Name)
		}
		byName[n.Name] = n
	}
	for _, n := range g.Nodes {
		for _, d := range n.Deps {
			if _, ok := byName[d]; !ok {
				return nil, fmt.Errorf(
					"deploy: node %q depends on unknown node %q", n.Name, d)
			}
			if d == n.Name {
				return nil, fmt.Errorf(
					"deploy: node %q depends on itself", n.Name)
			}
		}
	}

	// Kahn's algorithm, batched into waves.
	remaining := make(map[string]Node, len(g.Nodes))
	for k, v := range byName {
		remaining[k] = v
	}
	done := make(map[string]bool, len(g.Nodes))

	var waves [][]Node
	for len(remaining) > 0 {
		var ready []Node
		for _, n := range remaining {
			ok := true
			for _, d := range n.Deps {
				if !done[d] {
					ok = false
					break
				}
			}
			if ok {
				ready = append(ready, n)
			}
		}
		if len(ready) == 0 {
			stuck := make([]string, 0, len(remaining))
			for name := range remaining {
				stuck = append(stuck, name)
			}
			sort.Strings(stuck)
			return nil, fmt.Errorf(
				"deploy: dependency cycle detected; unscheduled nodes: %s",
				strings.Join(stuck, ", "))
		}
		sort.Slice(ready, func(i, j int) bool { return ready[i].Name < ready[j].Name })
		waves = append(waves, ready)
		for _, n := range ready {
			delete(remaining, n.Name)
			done[n.Name] = true
		}
	}
	return waves, nil
}

// runWave executes a single wave's nodes. Returns the first error
// observed (with node-name + step context) and cancels peers as
// soon as one node fails.
//
// Implementation: each node runs in its own goroutine bounded by an
// optional MaxParallel semaphore. The first non-nil result cancels
// waveCtx which propagates into every peer's Apply / WaitReady;
// peers terminate, the coordinator drains every remaining result
// so we don't leak goroutines, then reports failures in
// alphabetical order so two runs with simultaneous failures report
// the same head.
func (g Graph) runWave(ctx context.Context, wave []Node) error {
	waveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var sem chan struct{}
	if g.MaxParallel > 0 {
		sem = make(chan struct{}, g.MaxParallel)
	}

	results := make(chan stepResult, len(wave))
	var wg sync.WaitGroup
	for _, n := range wave {
		n := n
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sem != nil {
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-waveCtx.Done():
					results <- stepResult{n.Name, "queue", waveCtx.Err()}
					return
				}
			}
			runOne(waveCtx, n, results)
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var errs []stepResult
	for r := range results {
		if r.err != nil {
			if len(errs) == 0 {
				cancel()
			}
			errs = append(errs, r)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	sort.Slice(errs, func(i, j int) bool { return errs[i].node < errs[j].node })
	first := errs[0]
	if len(errs) == 1 {
		return fmt.Errorf("node %q %s: %w", first.node, first.step, first.err)
	}
	others := make([]string, 0, len(errs)-1)
	for _, e := range errs[1:] {
		others = append(others, fmt.Sprintf("%q %s: %v", e.node, e.step, e.err))
	}
	return fmt.Errorf("node %q %s: %w (also: %s)",
		first.node, first.step, first.err, strings.Join(others, "; "))
}

// stepResult is the outcome of executing a single node. step is ""
// on success, "apply" / "waitReady" / "queue" on failure to
// indicate which phase failed.
type stepResult struct {
	node string
	step string
	err  error
}

// runOne executes Apply then (if non-nil) WaitReady for a single
// node, emitting exactly one result.
//
// BestEffort nodes never emit a non-nil err: their failures are
// logged with a "BEST-EFFORT" prefix so log scanners can spot them,
// and the node reports success so the wave continues. WaitReady on
// a BestEffort node runs under a sub-context bounded by
// BestEffortWaitReadyTimeout (defaulting when zero) so a slow-to-
// converge wait cannot hold the entire wave.
func runOne(ctx context.Context, n Node, results chan<- stepResult) {
	start := time.Now()
	log.Printf("deploy: %s: apply starting", n.Name)
	if err := n.Apply(ctx); err != nil {
		if n.BestEffort {
			log.Printf("deploy: %s: BEST-EFFORT apply FAILED after %s (treated as success, downstream NOT blocked): %v",
				n.Name, time.Since(start).Round(time.Millisecond), err)
			results <- stepResult{n.Name, "", nil}
			return
		}
		log.Printf("deploy: %s: apply FAILED after %s: %v",
			n.Name, time.Since(start).Round(time.Millisecond), err)
		results <- stepResult{n.Name, "apply", err}
		return
	}
	log.Printf("deploy: %s: apply complete in %s",
		n.Name, time.Since(start).Round(time.Millisecond))

	if n.WaitReady == nil {
		results <- stepResult{n.Name, "", nil}
		return
	}

	waitCtx := ctx
	var waitCancel context.CancelFunc
	var waitTimeout time.Duration
	if n.BestEffort {
		waitTimeout = n.BestEffortWaitReadyTimeout
		if waitTimeout <= 0 {
			waitTimeout = defaultBestEffortWaitReadyTimeout
		}
		waitCtx, waitCancel = context.WithTimeout(ctx, waitTimeout)
		defer waitCancel()
	}

	waitStart := time.Now()
	log.Printf("deploy: %s: waitReady starting", n.Name)
	if err := n.WaitReady(waitCtx); err != nil {
		if n.BestEffort {
			elapsed := time.Since(waitStart).Round(time.Millisecond)
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				log.Printf("deploy: %s: BEST-EFFORT waitReady TIMED OUT after %s (cap=%s, treated as success, downstream NOT blocked): %v",
					n.Name, elapsed, waitTimeout, err)
			} else {
				log.Printf("deploy: %s: BEST-EFFORT waitReady FAILED after %s (treated as success, downstream NOT blocked): %v",
					n.Name, elapsed, err)
			}
			results <- stepResult{n.Name, "", nil}
			return
		}
		log.Printf("deploy: %s: waitReady FAILED after %s: %v",
			n.Name, time.Since(waitStart).Round(time.Millisecond), err)
		results <- stepResult{n.Name, "waitReady", err}
		return
	}
	log.Printf("deploy: %s: waitReady complete in %s (total %s)",
		n.Name, time.Since(waitStart).Round(time.Millisecond),
		time.Since(start).Round(time.Millisecond))
	results <- stepResult{n.Name, "", nil}
}
