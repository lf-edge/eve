// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package clustermode runs the single↔HA-cluster transitions that
// kube-init drives in response to controller-side configuration
// changes.
//
// Single→cluster is a flat *step runner*: a fixed sequence of
// small, individually-testable steps executed in order under one
// context. Between every step the runner checks ctx.Err() so a
// SIGTERM/cancel is honoured promptly, and an optional progress
// callback lets the parent FSM publish "which step is running
// right now" in its status string.
//
// We deliberately did NOT build a sub-FSM here:
//   - the sequence is almost entirely linear (two boolean guards
//     on IsBootstrapNode and ClusterTypeBase);
//   - there are no loops or retries between steps;
//   - the runner does not need to react to external events while
//     running — the parent FSM queues those and processes them
//     after the runner returns.
//
// Single→cluster step order:
//
//  1. discover-cluster-status      EdgeNodeClusterStatus + ClusterType
//  2. uninstall-base-components    iff ClusterType==Base
//  3. rotate-token                 iff IsBootstrapNode (k3s still running)
//  4. multus-reset                 uninstall + re-apply pinned to ClusterIP
//  5. unmark-node-labels           force label re-apply on next deploy
//  6. stop-k3s
//  7. run-hooks
//  8. clear-tls-if-join            non-bootstrap: drop server PKI + unmark debug user
//  9. provision-config             write cluster-mode drop-in
//
// 10. write-join-marker            non-bootstrap: stuck-join watchdog
// 11. apply-registration           stage controller-supplied AddOn manifest
//
// Cluster→single is a one-shot cleanup that ends in
// RebootWithReason and under normal circumstances does not return.
// It is implemented inline (not as a step list) because there's
// nothing to sequence against and no value in step-by-step
// progress before a reboot.
package clustermode

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/components"
	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// Supervisor is the subset of *k3s.Supervisor the runner uses.
// Declared as an interface so tests can supply a fake.
//
// Stop returns an error only when the runner could surface
// extra context (e.g. ErrPortsStillBound); StepStopK3s treats
// errors as non-fatal and logs them with an explicit pointer at
// the next-Start consequence.
type Supervisor interface {
	Stop() error
	RunHooks() []k3s.HookResult
}

// ProgressFn is called once with the step name immediately before
// each step runs. Must not block.
type ProgressFn func(step string)

// Runner sequences the single→cluster transition steps.
type Runner struct {
	sup      Supervisor
	progress ProgressFn

	// Discovered once at the start of Run and reused by later steps.
	cs *k3s.ClusterStatus
	ct k3s.ClusterType
}

// NewRunner constructs a Runner. sup may be nil — in that case
// the stop-k3s and run-hooks steps are no-ops (useful for tests).
// progress may be nil.
func NewRunner(sup Supervisor, progress ProgressFn) *Runner {
	return &Runner{sup: sup, progress: progress}
}

// step bundles a step name with its function so Run can iterate.
type step struct {
	name string
	fn   func(context.Context) error
}

// Run executes the single→cluster transition end-to-end.
// ctx.Err() is checked between every step; cancellation
// mid-sequence returns the context error and skips remaining
// steps.
func (r *Runner) Run(ctx context.Context) error {
	steps := []step{
		{"discover-cluster-status", r.StepDiscover},
		{"uninstall-base-components", r.StepUninstallIfBase},
		{"rotate-token", r.StepRotateTokenIfBootstrap},
		{"multus-reset", r.StepMultusReset},
		{"unmark-node-labels", r.StepUnmarkNodeLabels},
		{"stop-k3s", r.StepStopK3s},
		{"run-hooks", r.StepRunHooks},
		{"clear-tls-if-join", r.StepClearTLSIfNonBootstrap},
		{"provision-config", r.StepProvisionConfig},
		{"write-join-marker", r.StepWriteJoinMarkerIfNonBootstrap},
		{"apply-registration", r.StepApplyRegistration},
	}

	log.Printf("cluster transition: single → cluster starting (%d steps)",
		len(steps))
	for _, s := range steps {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("cluster transition cancelled before %q: %w",
				s.name, err)
		}
		if r.progress != nil {
			r.progress(s.name)
		}
		log.Printf("cluster transition step: %s", s.name)
		if err := s.fn(ctx); err != nil {
			return fmt.Errorf("step %q: %w", s.name, err)
		}
	}
	log.Printf("cluster transition: single → cluster complete")
	return nil
}

// StepDiscover loads EdgeNodeClusterStatus and the cluster type
// into r. All later steps depend on these fields.
//
// Both reads propagate their error: a missing or corrupt cluster
// type would otherwise silently downgrade a Base-mode transition
// into Replicated and skip StepUninstallIfBase. The FSM will
// retry on the next tick.
func (r *Runner) StepDiscover(_ context.Context) error {
	cs, err := k3s.GetClusterStatus()
	if err != nil {
		return fmt.Errorf("get cluster status: %w", err)
	}
	r.cs = cs

	ct, err := k3s.GetClusterType()
	if err != nil {
		return fmt.Errorf("get cluster type: %w", err)
	}
	r.ct = ct

	log.Printf("cluster transition: type=%v bootstrap=%v clusterIP=%s",
		r.ct, r.cs.IsBootstrapNode, r.cs.ClusterIP)
	return nil
}

// StepUninstallIfBase removes replicated-storage components when
// the target cluster type is Base. UninstallAll requires k3s to
// be running (it waits for API + node readiness internally).
//
// Most uninstall errors are logged and swallowed — partial
// uninstall is recoverable post-reboot. The one exception is
// ErrLonghornUninstallTimedOut: UninstallAll surfaces that
// sentinel specifically so the FSM aborts and retries on the
// next tick instead of marching past a half-shredded Longhorn
// installation. Honour the contract here.
func (r *Runner) StepUninstallIfBase(ctx context.Context) error {
	if r.ct != k3s.ClusterTypeBase {
		log.Printf("not base mode (type=%v) — skipping uninstall", r.ct)
		return nil
	}
	log.Printf("base mode — uninstalling replicated-storage components")
	if err := components.UninstallAll(ctx); err != nil {
		if errors.Is(err, components.ErrLonghornUninstallTimedOut) {
			return fmt.Errorf("UninstallAll: %w", err)
		}
		log.Printf("warning: UninstallAll: %v", err)
	}
	return nil
}

// StepRotateTokenIfBootstrap rotates the k3s cluster token to the
// controller-supplied value. Only bootstrap nodes need this —
// joining nodes pick the token up via the join config written in
// StepProvisionConfig. k3s must still be running.
//
// On successful rotation it arms MasterleaseCleanupFlag so the
// health worker's CleanupStaleMasterleases pass removes the
// pre-conversion single-node etcd lease on a later tick (addresses
// upstream commit d5664c079).
func (r *Runner) StepRotateTokenIfBootstrap(ctx context.Context) error {
	if !r.cs.IsBootstrapNode {
		log.Printf("not bootstrap node — skipping token rotate")
		return nil
	}
	if err := k3s.RotateToNewToken(ctx, r.cs.EncryptedToken); err != nil {
		return fmt.Errorf("rotate cluster token: %w", err)
	}
	if err := state.Mark(MasterleaseCleanupFlag); err != nil {
		// Non-fatal: cleanup failing to be scheduled is worse
		// than the transition aborting. Log loudly.
		log.Printf("WARNING: arm masterlease-cleanup flag: %v", err)
	}
	return nil
}

// StepMultusReset tears down the existing Multus daemonset, removes
// the rendered template (so ApplyMultusCNI re-renders with the new
// cluster IP), and re-applies pinned to ClusterIP/32.
//
// Best-effort throughout, including the apply. Multus owns pod
// networking for the new ClusterIP, which argues for treating a failure
// here as fatal, but that is not worth what failing costs: everything
// after this step — stop-k3s, clear-tls-if-join, provision-config — is
// what actually makes the node able to join, and skipping it is
// unrecoverable. A Multus daemonset still carrying the old node IP, by
// contrast, is re-applied by the deploy graph on the next pass. A
// transient CRD race in this step is enough to fail a transition, which
// would leave the node permanently unable to join for the sake of
// something that heals itself.
//
// This matches the effective behaviour of the shell implementation:
// cluster-init.sh only *rendered* the YAML during the transition and
// left the apply to its main loop, so it had no way to fail a
// transition on Multus.
func (r *Runner) StepMultusReset(ctx context.Context) error {
	// Unmark rather than uninstall. The node IP this step exists to
	// change lives in one field of the Multus ConfigMap; the marker is
	// only unmarked here because ApplyMultusCNI early-returns when it
	// is set. Uninstalling to achieve that was catastrophically
	// disproportionate: UninstallMultus deletes the whole rendered
	// manifest, and a CustomResourceDefinition object is cluster-scoped
	// however namespaced its CRs are — so re-addressing one joining
	// node removed the NetworkAttachmentDefinition kind from the entire
	// cluster, cascading away eve-kube-app/network-instance-attachment
	// and breaking pod sandbox creation on every node until it was
	// re-applied. It also created the CRD/CR race that then had to be
	// handled on the way back in. Observed 2026-08-02: pods wedged in
	// ContainerCreating cluster-wide during a single node's join.
	if err := state.Unmark(state.MultusInitialized); err != nil {
		log.Printf("warning: unmark multus-initialized: %v", err)
	}
	if err := os.Remove(components.MultusYAMLDst); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("warning: remove %s: %v", components.MultusYAMLDst, err)
	}
	addr := components.NodeAddress{IP: r.cs.ClusterIP, Prefix: "/32"}
	if err := components.ApplyMultusCNI(ctx, addr); err != nil {
		log.Printf("WARNING: apply multus with cluster IP: %v — continuing; "+
			"the health loop re-applies while multus-initialized is clear, "+
			"and aborting here would skip clear-tls-if-join and leave the "+
			"node unable to join", err)
		return nil
	}

	// The apply updates the ConfigMap, but the DaemonSet's install
	// container writes the CNI conf once at pod start, so the pods must
	// come back for the new node IP to reach /etc/cni/net.d.
	if err := components.RestartMultusDaemonSet(ctx); err != nil {
		log.Printf("warning: restart multus daemonset: %v", err)
	}
	return nil
}

// StepUnmarkNodeLabels clears the node-labels-initialized marker
// so the next deploy/health tick re-applies labels with the new
// cluster identity. Non-fatal on failure.
func (r *Runner) StepUnmarkNodeLabels(_ context.Context) error {
	if err := state.Unmark(state.NodeLabelsInitialized); err != nil {
		log.Printf("warning: unmark node-labels-initialized: %v", err)
	}
	return nil
}

// StepStopK3s stops the k3s supervisor (blocks until the process
// tree is gone and the API ports are free). No-op when sup is nil.
//
// Stop errors are logged but not propagated: typically
// "ports still bound", which the post-restart k3s.Start will
// surface as EADDRINUSE with a clearer error chain than we can
// produce here. The log line names that consequence explicitly so
// a postmortem can connect the two.
func (r *Runner) StepStopK3s(_ context.Context) error {
	if r.sup == nil {
		log.Printf("no supervisor — skipping stop-k3s")
		return nil
	}
	if err := r.sup.Stop(); err != nil {
		log.Printf("warning: supervisor stop: %v "+
			"(the next k3s.Start may fail with EADDRINUSE)", err)
	}
	return nil
}

// StepRunHooks runs the pre-restart hooks via the supervisor.
//
// Unlike a plain restart, a failure under hooks.d/required/ does not
// abort here: the transition has already mutated cluster state (etcd
// masterleases, TLS material, cluster config) and stopping partway
// leaves that inconsistent, which is worse than proceeding with
// whatever the hook failed to install. The failure is logged loudly
// and the sequence continues.
func (r *Runner) StepRunHooks(_ context.Context) error {
	if r.sup == nil {
		log.Printf("no supervisor — skipping run-hooks")
		return nil
	}
	for _, h := range r.sup.RunHooks() {
		if h.Required && h.Err != nil {
			log.Printf("WARNING: required hook %s failed (exit %d) mid-transition; "+
				"continuing to avoid a half-applied transition: %v",
				h.Name, h.ExitCode, h.Err)
		}
	}
	return nil
}

// StepClearTLSIfNonBootstrap drops the k3s server TLS material so
// the joining node can be re-issued certs by the bootstrap node,
// and forces debug-user regeneration on the next deploy.
//
// Bootstrap nodes keep their CA/PKI — they are the issuer that
// joining nodes will trust.
//
// RemoveServerTLSDir failures propagate: stale server TLS
// material on a joining node guarantees the rejoin fails at TLS
// handshake with no breadcrumb pointing back here. The debug-
// user Unmark is best-effort because a stale marker only delays
// debug-cert refresh, doesn't break the rejoin.
func (r *Runner) StepClearTLSIfNonBootstrap(_ context.Context) error {
	if r.cs.IsBootstrapNode {
		log.Printf("bootstrap node — skipping TLS clear")
		return nil
	}
	if err := k3s.RemoveServerTLSDir(); err != nil {
		return fmt.Errorf("remove server TLS dir: %w", err)
	}
	if err := state.Unmark(state.DebugUserInitialized); err != nil {
		log.Printf("warning: unmark debug-user: %v", err)
	}
	return nil
}

// StepProvisionConfig writes the cluster-mode k3s config (bootstrap
// or join). isFirstBoot=true forces the join-side wait for the
// bootstrap server inside k3s.ProvisionClusterConfig — a transition
// should not skip that wait even though k3s has already been
// running once on this node.
func (r *Runner) StepProvisionConfig(ctx context.Context) error {
	if err := k3s.ProvisionClusterConfig(ctx, true); err != nil {
		return fmt.Errorf("provision cluster config: %w", err)
	}
	return nil
}

// StepWriteJoinMarkerIfNonBootstrap writes the
// transition-to-cluster marker (format: "<unix_ts> <reboot_count>")
// so monitor.CheckClusterTransitionDone can detect a stuck join
// and reboot. Bootstrap nodes don't need the marker — they are
// the cluster they're joining.
//
// Failure is non-fatal: without the marker the watchdog won't
// auto-reboot on a stuck join, but the join itself can still
// succeed.
func (r *Runner) StepWriteJoinMarkerIfNonBootstrap(_ context.Context) error {
	if r.cs.IsBootstrapNode {
		return nil
	}
	marker := fmt.Sprintf("%d 0", time.Now().Unix())
	if err := state.AtomicWriteFile(string(state.TransitionToCluster),
		[]byte(marker), 0644); err != nil {
		log.Printf("warning: write transition marker: %v", err)
		return nil
	}
	log.Printf("wrote join marker %q", marker)
	return nil
}

// StepApplyRegistration stages any controller-delivered
// registration manifest so k3s auto-applies it on next start.
// Idempotent; failures are warnings.
func (r *Runner) StepApplyRegistration(_ context.Context) error {
	if err := components.RegistrationCheckApply(); err != nil {
		log.Printf("warning: registration check/apply: %v", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Cluster → single
// ---------------------------------------------------------------------------

// RunClusterToSingle performs the cluster → single-node
// cleanup-then-reboot. Under normal circumstances RebootWithReason
// does not return.
//
// Steps:
//  1. Drop any controller-delivered registration manifest.
//  2. Clear the native-kubernetes-mode marker so the post-reboot
//     single node uninstalls K3sBase-conversion components on its
//     own.
//  3. Mark ConvertToSingleNode so the next boot triggers
//     RestoreVarLib. THIS marker is load-bearing — without it the
//     restored /var/lib stays in cluster-mode state and the single
//     node will keep behaving as if it were a cluster member.
//     A failure here aborts before the reboot.
//  4. Reboot.
//
// If RebootWithReason itself returns an error (e.g. /sbin/reboot
// is missing), the NativeKubernetesMode unmark and
// ConvertToSingleNode mark are already on disk. The caller must
// retry — the next attempt will be a no-op on the markers and try
// the reboot again.
func RunClusterToSingle() error {
	log.Printf("cluster transition: cluster → single starting")

	if err := components.RegistrationCleanup(); err != nil {
		log.Printf("warning: registration cleanup: %v", err)
	}
	if err := state.Unmark(state.NativeKubernetesMode); err != nil {
		log.Printf("warning: unmark native-kubernetes-mode: %v", err)
	}
	if err := state.Mark(state.ConvertToSingleNode); err != nil {
		// Load-bearing marker: without it the post-reboot
		// RestoreVarLib never runs and the cluster→single
		// transition silently fails. Abort before reboot.
		return fmt.Errorf("mark convert-to-single-node: %w", err)
	}

	reason := "Transition from cluster mode to single node"
	if err := state.RebootWithReason(reason); err != nil {
		return fmt.Errorf("reboot for cluster-to-single: %w", err)
	}
	// RebootWithReason blocks; reaching here would be unexpected.
	log.Printf("cluster transition: cluster → single reboot returned (unexpected)")
	return nil
}
