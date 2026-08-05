// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"time"
)

// StepFunc is the signature of the imperative Apply / Ready helper on
// a Component. Both are cancelled via the caller's context.
type StepFunc func(ctx context.Context) error

// ReadyPredicate blocks until a Component reaches its operational
// Ready condition or the caller's context / ReadyTimeout expires.
type ReadyPredicate = StepFunc

// ProgressFunc reports an opaque token summarising how much work a
// Component has completed. Successive tokens are compared for equality
// only — any change counts as progress and the value is never
// interpreted. An error is treated as "progress unknown" and leaves
// the no-progress timer running.
type ProgressFunc func(ctx context.Context) (string, error)

// Manifest is one apply-able input to a Component. Exactly one of
// File / URL / Bytes is set. Used as a source-of-truth for
// structural dep derivation.
type Manifest struct {
	File  string
	URL   string
	Bytes []byte
}

// Component is a single unit of work in the deploy graph.
type Component struct {
	// Name uniquely identifies the component. Used in log lines and
	// PolicyDeps references. Must be non-empty and unique within a
	// Graph.
	Name string

	// Manifests are the raw files/URLs/bytes this component
	// applies. The runner parses them (once, up front) to build the
	// (gvk, ns, name) inventory used for structural dep derivation.
	// Empty slice is allowed — the component then relies entirely
	// on Apply + PolicyDeps for ordering.
	Manifests []Manifest

	// Apply performs the imperative side of the component's install
	// (state markers, filesystem staging, symlinks, etc.). Runs
	// after any Manifests have been applied — for components whose
	// entire install is a YAML apply this can be nil.
	Apply StepFunc

	// Ready blocks until the component has reached its operational
	// Ready condition or ctx / ReadyTimeout expires. Optional —
	// omit for components whose readiness is implied by Apply
	// (RBAC, ConfigMaps, plans consumed by an already-Ready
	// controller).
	Ready ReadyPredicate

	// BestEffort downgrades any error from Apply / Ready to a
	// logged warning. Downstream components that depend on this
	// one are NOT blocked, the graph run is NOT aborted.
	BestEffort bool

	// ReadyTimeout caps how long Ready may run. Non-BestEffort:
	// exceeding fails the graph. BestEffort: exceeding is logged
	// and treated as success.
	//
	// Zero applies defaultReadyTimeout for BestEffort components;
	// non-BestEffort components run under the caller's ctx when
	// ReadyTimeout is zero.
	//
	// When Progress is set this becomes a NO-PROGRESS deadline: the
	// budget restarts every time Progress reports a changed token, and
	// ReadyCeiling bounds the total instead.
	ReadyTimeout time.Duration

	// Progress optionally reports whether Ready is advancing. Setting
	// it converts ReadyTimeout from a wall clock into a no-progress
	// deadline, so a component that is slow but working is not
	// cancelled — which matters because cancelling discards the work
	// (an interrupted image pull loses its in-flight layer, and the
	// process-group stop that follows a completed deploy cancels any
	// pull still running).
	//
	// Nil keeps the plain wall-clock behaviour.
	Progress ProgressFunc

	// ReadyCeiling bounds Ready in wall-clock terms when Progress is
	// set, so a component that reports progress forever without ever
	// becoming Ready still terminates. Ignored when Progress is nil.
	//
	// Zero applies defaultReadyCeilingFactor x ReadyTimeout.
	ReadyCeiling time.Duration

	// PolicyDeps names other components in the same graph that
	// must reach Ready before this component's Apply runs. Reserved
	// for ordering that is not a readiness condition — longhorn
	// depends on manifests because storage-classes.yaml must be
	// staged in the k3s auto-deploy dir, a filesystem fact no signal
	// expresses better. Prefer Requires/Emits for anything that is a
	// readiness condition. Merged with signal-derived edges.
	PolicyDeps []string

	// Requires gates this component's Apply until every named signal
	// holds. A signal produced by another component in the graph
	// resolves to a dependency edge at plan time; one listed in
	// externalSignals resolves to a runtime Bus.Await. A signal with
	// neither producer fails graph construction.
	Requires []Signal

	// Emits names the signals this component produces. They are
	// emitted once Ready returns nil (or Apply, when Ready is nil).
	// A component that fails does not emit — note this diverges from
	// the scheduling edge for BestEffort components, whose failure
	// still releases dependents while leaving the signal unset.
	Emits []Signal
}

// Edge is one dependency edge in the resolved graph.
type Edge struct {
	// From is the name of the component that must be Ready first.
	From string
	// To is the name of the dependent component whose Apply is
	// gated on From reaching Ready.
	To string
	// Rule names the derivation source: "signal" or "policy". Exactly
	// one per edge.
	Rule string

	// Signal is the condition that produced this edge, set only when
	// Rule is "signal". Carried so a status reader can say which
	// condition a component is waiting on rather than only that it has
	// an unsatisfied predecessor.
	Signal Signal
}

// defaultReadyTimeout caps a BestEffort Component's Ready step when
// ReadyTimeout is left at zero. Chosen to be long enough for a
// healthy controller to converge on a modestly-loaded node but short
// enough that a stuck best-effort wait does not visibly delay later
// phases.
const defaultReadyTimeout = 30 * time.Second

// RetryPolicy governs BestEffort background retries. A component
// whose Apply fails or whose Ready times out under BestEffort=true is
// re-attempted in the background per this policy.
//
// Zero values apply defaultRetryPolicy.
type RetryPolicy struct {
	// Initial is the first inter-attempt sleep. Zero = 30s.
	Initial time.Duration

	// Factor is the exponential multiplier applied between
	// attempts. Zero = 2.0.
	Factor float64

	// Cap caps the per-attempt sleep after exponential growth.
	// Zero = 5min.
	Cap time.Duration

	// MaxAttempts is the absolute cap on retry count (including
	// the first re-Apply after the initial failure — the original
	// in-graph attempt is NOT counted). Zero = 6, which yields a
	// ~30-minute total budget under the default schedule.
	MaxAttempts int
}

// withDefaults returns a copy of p with zero fields filled from
// defaultRetryPolicy.
func (p RetryPolicy) withDefaults() RetryPolicy {
	if p.Initial <= 0 {
		p.Initial = defaultRetryPolicy.Initial
	}
	if p.Factor <= 0 {
		p.Factor = defaultRetryPolicy.Factor
	}
	if p.Cap <= 0 {
		p.Cap = defaultRetryPolicy.Cap
	}
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = defaultRetryPolicy.MaxAttempts
	}
	return p
}

// defaultRetryPolicy is what .withDefaults() applies for zero-value
// RetryPolicy. Exposed as a var (not a const) only so tests can
// point-adjust; production code should not mutate it.
var defaultRetryPolicy = RetryPolicy{
	Initial:     30 * time.Second,
	Factor:      2.0,
	Cap:         5 * time.Minute,
	MaxAttempts: 6,
}

// RetryCallback is fired on every BestEffort retry attempt. `attempt`
// is 1-indexed and counts only the retries — the original failing
// invocation inside the graph run does not fire this callback.
// `err` is the error from the just-completed attempt; nil means the
// retry succeeded and the loop will exit.
//
// Consumers typically publish a "component X still retrying, attempt
// N/6" status line to pubsub so on-device operators can see slow
// convergence without tailing kube-init logs.
type RetryCallback func(name string, attempt int, err error)
