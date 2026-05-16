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
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
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

	if appliedVersion == kubeVersionStr {
		log.Printf("update: cluster components already at version %s",
			kubeVersionStr)
		return nil
	}

	if updateFailed() {
		log.Printf("update: previous attempt at version %s failed, will not retry",
			kubeVersionStr)
		return fmt.Errorf("previous update to kube version %s failed",
			kubeVersionStr)
	}

	if err := checkClusterReady(ctx); err != nil {
		return fmt.Errorf("cluster not ready: %w", err)
	}

	for _, comp := range []string{CompMultus, CompKubevirt, CompCDI, CompLonghorn} {
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
		PublishUpdateStatus(comp, StatusCompleted, "")
		return nil
	}

	log.Printf("update: upgrading component %s", comp)
	PublishUpdateStatus(comp, StatusDownload, "")

	if err := compUpdate(ctx, comp); err != nil {
		PublishUpdateStatus(comp, StatusFailed, err.Error())
		return fmt.Errorf("update component %s: %w", comp, err)
	}

	if err := waitComponentReady(ctx, comp); err != nil {
		PublishUpdateStatus(comp, StatusFailed, err.Error())
		return fmt.Errorf("wait component %s ready: %w", comp, err)
	}
	PublishUpdateStatus(comp, StatusCompleted, "")
	log.Printf("update: component %s ready", comp)
	return nil
}

// waitComponentReady polls compCheckReady until it returns true,
// the context is cancelled, or readyPollTimeout elapses. The
// timeout protects against an update-component binary that keeps
// failing to launch — without it, the upgrade loop would spin
// indefinitely on a configuration fault with only StatusDownload
// visible to the controller.
func waitComponentReady(ctx context.Context, comp string) error {
	log.Printf("update: waiting for component %s to be ready (timeout %s)",
		comp, readyPollTimeout)
	deadline := time.Now().Add(readyPollTimeout)
	ticker := time.NewTicker(readyPollInterval)
	defer ticker.Stop()

	for {
		ready, err := compCheckReady(ctx, comp)
		if err != nil {
			// Probe could not execute — distinct from "ran and
			// reported not-ready". Log and continue polling: a
			// transient hiccup in update-component must not
			// prematurely fail the upgrade, but we want the
			// underlying error visible.
			log.Printf("update: check ready %s: %v", comp, err)
		} else if ready {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("component %s not ready within %s",
				comp, readyPollTimeout)
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
// succeed; otherwise wraps the most descriptive failure. A "not
// ready" answer from the cluster is also surfaced as an error so
// callers can decide whether to retry — the previous bool-only
// shape could not distinguish "cluster says no" from "probe binary
// missing".
func checkClusterReady(ctx context.Context) error {
	if _, err := kubectlx.Run("cluster-info"); err != nil {
		return fmt.Errorf("kubectl cluster-info: %w", err)
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
		ns = "kubevirt"
	case CompCDI:
		ns = "cdi"
	case CompLonghorn:
		ns = "longhorn-system"
	default:
		// multus has no dedicated namespace (it runs as a
		// DaemonSet in kube-system). Treated as always-installed
		// to match the contract of the update-component helper.
		return true, nil
	}

	cmd := exec.CommandContext(ctx, "kubectl", "get", "namespace", ns)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+state.K3sKubeconfig)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// kubectl ran and returned non-zero. Most commonly that
		// is the namespace not existing; we report "not
		// installed" without an error so the upgrade loop skips
		// the component cleanly.
		return false, nil
	}
	return false, fmt.Errorf("kubectl get namespace %s: %w (output: %s)",
		ns, err, truncateForLog(string(out), 1024))
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
	cmd := exec.CommandContext(ctx, compUpdatePath,
		"--versions-file", versionsFile,
		"--component", comp,
		"--upgrade")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+state.K3sKubeconfig)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("update-component %s: %w (output: %s)",
			comp, err, truncateForLog(string(out), 4096))
	}
	return nil
}

// compCheckReady asks update-component to verify that comp's
// in-cluster resources have converged to a Ready state. Returns
// (true, nil) on exit 0, (false, nil) when the helper ran and
// reported not-ready, and (false, err) when the helper could not
// be executed.
func compCheckReady(ctx context.Context, comp string) (bool, error) {
	cmd := exec.CommandContext(ctx, compUpdatePath,
		"--versions-file", versionsFile,
		"--component", comp,
		"--check-comp-ready")
	cmd.Env = append(os.Environ(), "KUBECONFIG="+state.K3sKubeconfig)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return false, fmt.Errorf("update-component --check-comp-ready %s: %w (output: %s)",
		comp, err, truncateForLog(string(out), 1024))
}
