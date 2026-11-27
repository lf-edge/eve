// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/edgenodeinfo"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kcus"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	"github.com/lf-edge/eve/pkg/kube/kube-init/tiebreaker"
	"github.com/lf-edge/eve/pkg/pillar/types"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Component identifiers managed by the cluster-update loop. The
// names match what update-component expects on its --component
// flag, so they are part of the external contract with that binary.
const (
	CompMultus   = "multus"
	CompKubevirt = "kubevirt"
	CompCDI      = "cdi"
	CompLonghorn = "longhorn"
)

// readyPollInterval is the cadence at which compCheckReady is
// polled after a successful upgrade. Five seconds keeps the loop
// responsive without spamming the kube-apiserver during the multi-
// minute pod restarts that follow a manifest re-apply.
var readyPollInterval = 5 * time.Second

// readyPollTimeout bounds how long upgradeComponent will wait for
// a component to report ready after an upgrade. If
// update-component itself keeps failing to even execute (binary
// missing, OOM-killed), this is what surfaces the fault to the
// caller instead of spinning forever.
var readyPollTimeout = 15 * time.Minute

// longhornReadyPollTimeout is readyPollTimeout for Longhorn, whose
// readiness includes the live engine upgrade of every attached
// volume, one volume per node at a time.
var longhornReadyPollTimeout = 60 * time.Minute

// compUpdateTimeout bounds one update-component --upgrade run. The
// helper bounds its own waits (ready before applying, version after
// applying, uptime); this covers them with some slack so a hung
// helper cannot keep the pass from ending.
var compUpdateTimeout = 40 * time.Minute

// compFinalizeTimeout bounds one update-component --finalize run,
// which at most waits for one longhorn-manager rollout.
var compFinalizeTimeout = 15 * time.Minute

// uncordonTimeout bounds the wait for the local node to be
// schedulable before Longhorn is upgraded.
var uncordonTimeout = 10 * time.Minute

// uncordonPollInterval is the cadence of that wait.
var uncordonPollInterval = 15 * time.Second

// tieBreakerNodeLabel marks the node of a three-node cluster that
// holds no workloads and stays cordoned.
const tieBreakerNodeLabel = "tie-breaker-node"

// reapplyTieBreakerLonghorn is a variable so tests can replace it.
var reapplyTieBreakerLonghorn = tiebreaker.LonghornConfigReapply

// ErrUpdateFailed marks a component update that ended in failure
// and will not be retried for this KubeVersion. Errors that do not
// wrap it are transient: the pass did not get as far as changing a
// component and can simply be run again.
var ErrUpdateFailed = errors.New("kube component update failed")

// ErrUpdateDeferred marks a pass that stopped, for a reason that can
// clear up on its own, before changing a component or with only a
// finalize step owed: a component not ready at its current version,
// this node still cordoned, or an upgraded component not converged
// yet. It is not latched; the pass runs again later.
var ErrUpdateDeferred = errors.New("kube component update deferred")

// compUpdateExitNotStarted is update-component's exit code for an
// --upgrade or --finalize that stopped before changing anything, and
// for a --check-upgrade-ready that says no.
const compUpdateExitNotStarted = 2

// compProbeTimeout bounds one update-component readiness probe.
const compProbeTimeout = 2 * time.Minute

// passComponents are the components a pass updates, in order.
var passComponents = []string{CompMultus, CompKubevirt, CompCDI, CompLonghorn}

// passFailed latches a failed pass for the lifetime of the process.
// updateFailed reads the same fact from the status pillar keeps,
// but that status is not published on a device without an applied
// version, and the pass must not be re-run either way.
var passFailed atomic.Bool

// ComponentPassPending reports whether this build still has a
// component update pass to run on this node: its KubeVersion is
// above the one the node last applied.
func ComponentPassPending() bool {
	return !appliedVersionGEQ(VersionGet(), KubeVersion)
}

// CheckClusterComponents iterates the managed cluster components,
// detects version drift via the update-component binary, and runs
// the upgrade-then-wait-ready cycle for any out-of-date component.
//
// Only one node in an HA cluster should drive this — the FSM is
// responsible for that election. This function does no leader
// election of its own.
func CheckClusterComponents(ctx context.Context) error {
	appliedVersion := VersionGet()
	kubeVersionStr := strconv.Itoa(KubeVersion)

	// applied >= target means either we are already converged
	// (==) or EVE has been downgraded (<). Downgrades are not
	// supported: skip the update pass rather than re-run
	// migrations or component "updates" that are actually
	// downgrades.
	if appliedVersionGEQ(appliedVersion, KubeVersion) {
		log.Printf("update: cluster components at applied=%s, target=%d — no update",
			appliedVersion, KubeVersion)
		ReleaseStaleUpdateStatus()
		return nil
	}

	if passFailed.Load() || updateFailed() {
		log.Printf("update: previous attempt at version %s failed, will not retry",
			kubeVersionStr)
		return fmt.Errorf("previous update to kube version %s: %w",
			kubeVersionStr, ErrUpdateFailed)
	}

	if err := checkClusterReady(ctx); err != nil {
		return fmt.Errorf("cluster not ready: %w", err)
	}

	for _, comp := range passComponents {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := upgradeComponent(ctx, comp); err != nil {
			return err
		}
	}

	if err := VersionSet(); err != nil {
		return fmt.Errorf("persist applied kube version: %w", err)
	}
	log.Printf("update: all components at version %s", kubeVersionStr)
	return nil
}

// ReleaseStaleUpdateStatus advances a KubeClusterUpdateStatus that
// names an unfinished step to completion, on a node whose components
// are converged for this build.
//
// zedagent keeps the device in BaseOsUpdating for as long as that
// status names an unfinished component. Two things leave one behind
// although nothing is left to do. A k3s update publishes "k3s
// completed" and then reboots; on the way back up the component
// pass has nothing left to do and publishes nothing. And a pass
// interrupted by a reboot into the other partition leaves its last
// in-flight step. Reaching this point means the components are
// converged for this build, so the last step is retroactively
// finished. A failed status is left alone: it is terminal and its
// error is worth keeping.
func ReleaseStaleUpdateStatus() {
	status, ok := kcus.Get()
	if !ok || !updateStatusUnfinished(status) {
		return
	}
	log.Printf("update: status left at %v/%v — advancing to %s completed",
		status.Component, status.Status, CompLonghorn)
	PublishUpdateStatus(CompLonghorn, StatusCompleted, "")
}

// updateStatusUnfinished reports whether a status names a step that
// a later step was still expected to follow.
func updateStatusUnfinished(status types.KubeClusterUpdateStatus) bool {
	switch status.Status {
	case types.CompStatusDownload, types.CompStatusInProgress:
		return true
	case types.CompStatusCompleted:
		return status.Component == types.CompK3s
	}
	return false
}

func upgradeComponent(ctx context.Context, comp string) error {
	installed, err := componentIsInstalled(ctx, comp)
	if err != nil {
		return fmt.Errorf("check %s installed: %w", comp, err)
	}
	if !installed {
		log.Printf("update: component %s not installed, skipping", comp)
		return nil
	}

	atVersion, err := compIsRunningExpectedVersion(ctx, comp)
	if err != nil {
		return fmt.Errorf("check %s version: %w", comp, err)
	}
	if atVersion {
		log.Printf("update: component %s already at expected version", comp)
		// A pass interrupted after the version moved comes back
		// here, its post-upgrade step possibly still owed. The
		// version can move before the component has converged
		// (Longhorn's does before the engines are upgraded), so a
		// pass this node was in the middle of waits for that first.
		if interruptedUpgrade(comp) {
			log.Printf("update: resuming the interrupted update of %s", comp)
			PublishUpdateStatus(comp, StatusInProgress, "")
			if err := waitComponentReady(ctx, comp); err != nil {
				return failUpdate(ctx, comp, "wait ready", err)
			}
		}
		// Another node's upgrade may still be converging. Nothing
		// here is irreversible, so any finalize error defers the
		// pass rather than recording it done without the step.
		if err := compFinalize(ctx, comp); err != nil {
			if !errors.Is(err, ErrUpdateDeferred) {
				err = fmt.Errorf("%w: %w", ErrUpdateDeferred, err)
			}
			return fmt.Errorf("finalize component %s: %w", comp, err)
		}
		compPostUpgrade(ctx, comp)
		PublishUpdateStatus(comp, StatusCompleted, "")
		return nil
	}

	log.Printf("update: upgrading component %s", comp)
	if comp == CompLonghorn {
		if err := waitNodeUncordoned(ctx); err != nil {
			if ctx.Err() == nil {
				err = fmt.Errorf("%w: %w", ErrUpdateDeferred, err)
			}
			return fmt.Errorf("pre-update component %s: %w", comp, err)
		}
	}
	PublishUpdateStatus(comp, StatusDownload, "")
	if err := compUpdate(ctx, comp); err != nil {
		if errors.Is(err, ErrUpdateDeferred) {
			return fmt.Errorf("update component %s: %w", comp, err)
		}
		return failUpdate(ctx, comp, "update", err)
	}
	PublishUpdateStatus(comp, StatusInProgress, "")
	if err := waitComponentReady(ctx, comp); err != nil {
		return failUpdate(ctx, comp, "wait ready", err)
	}
	if err := compFinalize(ctx, comp); err != nil {
		if errors.Is(err, ErrUpdateDeferred) {
			return fmt.Errorf("finalize component %s: %w", comp, err)
		}
		return failUpdate(ctx, comp, "finalize", err)
	}
	compPostUpgrade(ctx, comp)
	PublishUpdateStatus(comp, StatusCompleted, "")
	log.Printf("update: component %s ready", comp)
	return nil
}

// PassCanStart reports whether a pending pass would now get past the
// checks that defer it: the cluster answers, every component still
// to update is ready to be, Longhorn's on a schedulable node, and
// every component already updated has converged. It waits for nothing
// and does not log; the pass itself says why it stops.
func PassCanStart(ctx context.Context) bool {
	if checkClusterReady(ctx) != nil {
		return false
	}
	for _, comp := range passComponents {
		installed, err := componentIsInstalled(ctx, comp)
		if err != nil {
			return false
		}
		if !installed {
			continue
		}
		atVersion, err := compIsRunningExpectedVersion(ctx, comp)
		if err != nil {
			return false
		}
		if atVersion {
			if ready, _, err := compCheckReady(ctx, comp); err != nil || !ready {
				return false
			}
			continue
		}
		if comp == CompLonghorn {
			if ok, err := nodeUncordoned(ctx); err != nil || !ok {
				return false
			}
		}
		if !compCheckUpgradeReady(ctx, comp) {
			return false
		}
	}
	return true
}

// failUpdate ends the update of comp, which may have changed it, in
// failure: published, latched, and not retried for this KubeVersion.
// A cancelled ctx is not a failure of the update but kube-init or k3s
// going away; the pass resumes on the way back up.
func failUpdate(ctx context.Context, comp, step string, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%s component %s: %w", step, comp, err)
	}
	passFailed.Store(true)
	PublishUpdateStatus(comp, StatusFailed, err.Error())
	return fmt.Errorf("%s component %s: %w: %w", step, comp, ErrUpdateFailed, err)
}

// interruptedUpgrade reports whether this node's last published
// update status has it in the middle of updating comp to this
// KubeVersion.
func interruptedUpgrade(comp string) bool {
	status, ok := kcus.Get()
	return ok && status.Component == types.KubeCompFromStr(comp) &&
		status.DestinationKubeUpdateVersion == uint32(KubeVersion) &&
		updateStatusUnfinished(status)
}

// waitNodeUncordoned waits until the local node is schedulable.
// Longhorn treats a cordoned node as one being drained: it stops
// scheduling replicas onto it and marks its instance manager not
// ready, which is not a state to upgrade engines in. pillar
// uncordons the node once it is Ready after boot. A tie-breaker node
// stays cordoned for good and holds no replicas, so it is exempt.
func waitNodeUncordoned(ctx context.Context) error {
	nodeName := state.ToK8sName(edgenodeinfo.DeviceName())
	deadline := time.Now().Add(uncordonTimeout)
	ticker := time.NewTicker(uncordonPollInterval)
	defer ticker.Stop()
	for {
		ok, err := nodeUncordoned(ctx)
		if err != nil {
			log.Printf("update: %v", err)
		} else if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("node %s still cordoned after %s", nodeName, uncordonTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// nodeUncordoned reports whether the local node is schedulable, or is
// the tie-breaker, which stays cordoned for good.
func nodeUncordoned(ctx context.Context) (bool, error) {
	nodeName := state.ToK8sName(edgenodeinfo.DeviceName())
	node, err := kubeclient.Default().Clientset.CoreV1().Nodes().
		Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("get node %s: %w", nodeName, err)
	}
	return !node.Spec.Unschedulable || node.Labels[tieBreakerNodeLabel] == "true", nil
}

// compReadyTimeout returns how long comp may take to report ready
// after an upgrade.
func compReadyTimeout(comp string) time.Duration {
	if comp == CompLonghorn {
		return longhornReadyPollTimeout
	}
	return readyPollTimeout
}

// waitComponentReady polls compCheckReady until it returns true,
// the context is cancelled, or readyPollTimeout elapses. The
// timeout protects against an update-component binary that keeps
// failing to launch — without it, the upgrade loop would spin
// indefinitely on a configuration fault with only StatusDownload
// visible to the controller.
func waitComponentReady(ctx context.Context, comp string) error {
	timeout := compReadyTimeout(comp)
	log.Printf("update: waiting for component %s to be ready (timeout %s)",
		comp, timeout)
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(readyPollInterval)
	defer ticker.Stop()

	var notReady string
	for {
		ready, detail, err := compCheckReady(ctx, comp)
		if err != nil {
			// Probe could not execute — distinct from "ran and
			// reported not-ready". Log and continue polling: a
			// transient hiccup in update-component must not
			// prematurely fail the upgrade, but we want the
			// underlying error visible.
			log.Printf("update: check ready %s: %v", comp, err)
		} else if ready {
			return nil
		} else if detail != "" {
			notReady = detail
		}
		if time.Now().After(deadline) {
			if notReady != "" {
				return fmt.Errorf("component %s not ready within %s: %s",
					comp, timeout, notReady)
			}
			return fmt.Errorf("component %s not ready within %s",
				comp, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// checkClusterReady probes the cluster API. Returns nil when both
// `kubectl cluster-info` and update-component's --check-api-ready
// succeed; otherwise wraps the most descriptive failure.
func checkClusterReady(ctx context.Context) error {
	// Reachability probe: any typed API call is fine — use the
	// version endpoint since it doesn't require RBAC. Failure
	// surfaces as a dial or auth error, both of which are what
	// the caller wants to know.
	if _, err := kubeclient.Default().Discovery.ServerVersion(); err != nil {
		return fmt.Errorf("api server version probe: %w", err)
	}
	apiCmd := exec.CommandContext(ctx, compUpdatePath, "--check-api-ready")
	apiCmd.Env = append(os.Environ(), "KUBECONFIG="+state.K3sKubeconfig)
	if out, err := apiCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("update-component --check-api-ready: %w (output: %s)",
			err, truncateForLog(string(out), 1024))
	}
	return nil
}

// componentIsInstalled reports whether the namespace owned by a
// component exists.
//
// Returns (true, nil) when the namespace is present, (false, nil)
// only when kubectl ran to completion and reported "NotFound" via
// a non-zero exit, and (false, err) when kubectl itself could not
// be executed (binary missing, RBAC fault, server unreachable).
// The distinction is load-bearing: the old shape — returning false
// on any error — caused a missing kubectl to silently mark every
// component "not installed" and let VersionSet declare a green
// upgrade for a device that was never inspected.
func componentIsInstalled(ctx context.Context, comp string) (bool, error) {
	var ns string
	switch comp {
	case CompKubevirt:
		ns = kubectlx.KubeVirtNamespace
	case CompCDI:
		ns = kubectlx.CDINamespace
	case CompLonghorn:
		ns = kubectlx.LonghornNamespace
	default:
		// multus has no dedicated namespace (it runs as a
		// DaemonSet in kube-system). Treated as always-installed
		// to match the contract of the update-component helper.
		return true, nil
	}

	_, err := kubeclient.Default().Clientset.CoreV1().
		Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if err == nil {
		return true, nil
	}
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return false, fmt.Errorf("get namespace %s: %w", ns, err)
}

// compIsRunningExpectedVersion asks update-component to compare the
// in-cluster manifest of comp against the expected_versions.yaml
// manifest. Returns (true, nil) on exit 0, (false, nil) when the
// helper ran and reported a mismatch (any non-zero ExitError), and
// (false, err) when the helper itself could not be executed —
// distinguishing "helper says drift" from "helper is broken" so
// the caller cannot silently green-flag a never-inspected
// component.
func compIsRunningExpectedVersion(ctx context.Context, comp string) (bool, error) {
	cmd := exec.CommandContext(ctx, compUpdatePath,
		"--versions-file", versionsFile,
		"--component", comp,
		"--compare")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+state.K3sKubeconfig)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return false, fmt.Errorf("update-component --compare %s: %w (output: %s)",
		comp, err, truncateForLog(string(out), 1024))
}

// compUpdate asks update-component to apply the upgrade defined in
// expected_versions.yaml for comp. Any non-zero exit is surfaced
// with combined stdout/stderr so the failure mode is visible in
// kube-init logs. Output is truncated to bound the error string —
// it is later attached to a PublishUpdateStatus argv and a
// megabyte of helper noise would hit E2BIG on a small device.
func compUpdate(ctx context.Context, comp string) error {
	ctx, cancel := context.WithTimeout(ctx, compUpdateTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, compUpdatePath,
		"--versions-file", versionsFile,
		"--component", comp,
		"--upgrade")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+state.K3sKubeconfig)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("update-component %s did not finish within %s",
				comp, compUpdateTimeout)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == compUpdateExitNotStarted {
			return fmt.Errorf("update-component %s: %w: %s",
				comp, ErrUpdateDeferred, truncateForLog(string(out), 4096))
		}
		return fmt.Errorf("update-component %s: %w (output: %s)",
			comp, err, truncateForLog(string(out), 4096))
	}
	return nil
}

// compFinalize asks update-component to run comp's post-upgrade
// step. Only Longhorn has one: it puts back the upgrade version
// check that a large step starts longhorn-manager without. A no-op
// for the other components and whenever nothing is owed.
func compFinalize(ctx context.Context, comp string) error {
	ctx, cancel := context.WithTimeout(ctx, compFinalizeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, compUpdatePath,
		"--versions-file", versionsFile,
		"--component", comp,
		"--finalize")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+state.K3sKubeconfig)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("update-component --finalize %s did not finish within %s",
				comp, compFinalizeTimeout)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == compUpdateExitNotStarted {
			return fmt.Errorf("update-component --finalize %s: %w: %s",
				comp, ErrUpdateDeferred, truncateForLog(string(out), 4096))
		}
		return fmt.Errorf("update-component --finalize %s: %w (output: %s)",
			comp, err, truncateForLog(string(out), 4096))
	}
	return nil
}

// compCheckUpgradeReady asks update-component, once, whether an
// --upgrade of comp would get past its readiness check now.
func compCheckUpgradeReady(ctx context.Context, comp string) bool {
	ctx, cancel := context.WithTimeout(ctx, compProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, compUpdatePath,
		"--versions-file", versionsFile,
		"--component", comp,
		"--check-upgrade-ready")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+state.K3sKubeconfig)
	return cmd.Run() == nil
}

// compPostUpgrade restores cluster configuration that upgrading
// comp undoes. Only Longhorn has any: its upgrade recreates objects
// the tie-breaker configuration had patched. A failure is logged and
// does not fail the update, since the component itself is upgraded
// and no volume data is placed differently because of it.
func compPostUpgrade(ctx context.Context, comp string) {
	if comp != CompLonghorn {
		return
	}
	applied, err := reapplyTieBreakerLonghorn(ctx)
	switch {
	case err != nil:
		log.Printf("WARNING: re-apply tie-breaker config after %s update: %v", comp, err)
	case applied:
		log.Printf("update: tie-breaker config re-applied after %s update", comp)
	}
}

// compCheckReady asks update-component to verify that comp has
// converged on its expected version and is Ready. Returns (true,
// "", nil) on exit 0, (false, detail, nil) when the helper ran and
// reported not-ready, with what it said was not ready, and (false,
// "", err) when the helper could not be executed.
func compCheckReady(ctx context.Context, comp string) (bool, string, error) {
	cmd := exec.CommandContext(ctx, compUpdatePath,
		"--versions-file", versionsFile,
		"--component", comp,
		"--check-comp-ready")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+state.K3sKubeconfig)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true, "", nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, truncateForLog(string(out), 1024), nil
	}
	return false, "", fmt.Errorf("update-component --check-comp-ready %s: %w (output: %s)",
		comp, err, truncateForLog(string(out), 1024))
}
