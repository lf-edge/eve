// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// Uninstall constants. Versions are mirrored from install constants
// in components.go so a bump in one place flows to the other (a
// genuine version skew would surface as a 404 from these URLs).
const (
	longhornUninstallVersion  = "v1.9.1"
	longhornUninstallSettings = "/etc/longhorn_uninstall_settings.yaml"
	longhornUninstallJobURL   = "https://raw.githubusercontent.com/longhorn/longhorn/" +
		longhornUninstallVersion + "/uninstall/uninstall.yaml"
	longhornDeployURL = "https://raw.githubusercontent.com/longhorn/longhorn/" +
		longhornUninstallVersion + "/deploy/longhorn.yaml"

	// 1000 iterations * 5s = ~83 minutes; Longhorn's data-shred step
	// can take 30+ minutes on a populated cluster.
	longhornUninstallMaxPolls     = 1000
	longhornUninstallPollInterval = 5 * time.Second

	// replicatedStorageUninstallComplete is a one-shot "we got to
	// the end" marker so a kube-init restart after uninstall
	// doesn't retry the whole flow.
	replicatedStorageUninstallComplete state.Marker = "/var/lib/replicated-storage-uninstall-complete"
)

// ErrLonghornUninstallTimedOut is returned by UninstallLonghorn
// when the uninstall Job did not complete inside the poll budget.
// UninstallAll aborts on this sentinel rather than continuing to
// BaseK3sMode marking: declaring base-k3s mode while Longhorn
// volumes are half-shredded would leave the cluster in a worse
// state than failing loud.
var ErrLonghornUninstallTimedOut = errors.New("longhorn uninstall job did not complete within poll budget")

// UninstallAll runs the full base-k3s-mode conversion: drains the
// API, uninstalls every component in reverse dependency order, and
// sets the BaseK3sMode marker on success.
//
// Per-component failures are normally warnings — uninstall
// continues across stale state so partial-uninstall scenarios
// converge instead of leaving the daemon stuck behind a broken
// component.
//
// Exception: ErrLonghornUninstallTimedOut from UninstallLonghorn
// aborts the flow. Marking BaseK3sMode while Longhorn's data-shred
// Job is still running would leave volumes in an inconsistent
// state; better to surface the timeout to the FSM so it can
// retry on the next tick.
func UninstallAll(ctx context.Context) error {
	log.Printf("starting component uninstall for base-k3s mode conversion")

	if err := state.Mark(longhornUninstallGuard); err != nil {
		return fmt.Errorf("mark uninstall in progress: %w", err)
	}
	if err := waitForAPIServer(ctx); err != nil {
		return fmt.Errorf("wait for API server: %w", err)
	}
	if err := waitForAllNodesReady(ctx); err != nil {
		return fmt.Errorf("wait for nodes ready: %w", err)
	}

	for _, step := range []struct {
		name string
		fn   func(context.Context) error
	}{
		{"descheduler", UninstallDescheduler},
		{"longhorn", UninstallLonghorn},
		{"cdi", UninstallCDI},
		{"kubevirt", UninstallKubeVirt},
		{"multus", UninstallMultus},
	} {
		err := step.fn(ctx)
		if err == nil {
			continue
		}
		if errors.Is(err, ErrLonghornUninstallTimedOut) {
			return fmt.Errorf("%s uninstall: %w", step.name, err)
		}
		log.Printf("warning: %s uninstall: %v", step.name, err)
	}

	if err := state.Unmark(longhornUninstallGuard); err != nil {
		log.Printf("warning: unmark uninstall guard: %v", err)
	}
	if err := state.Mark(state.BaseK3sMode); err != nil {
		return fmt.Errorf("mark base-k3s mode: %w", err)
	}
	if err := state.Mark(replicatedStorageUninstallComplete); err != nil {
		log.Printf("warning: mark uninstall complete: %v", err)
	}
	log.Printf("component uninstall complete, base-k3s mode set")
	return nil
}

// UninstallDescheduler removes descheduler RBAC and the policy
// ConfigMap. Delete failures are warnings (best-effort cleanup).
func UninstallDescheduler(ctx context.Context) error {
	log.Printf("uninstalling descheduler")
	for _, f := range []string{deschedulerRBAC, deschedulerPolicy} {
		if _, err := kubectl("delete", "-f", f, "--wait=false"); err != nil {
			log.Printf("warning: delete %s: %v", f, err)
		}
	}
	log.Printf("descheduler uninstall complete")
	return nil
}

// UninstallLonghorn performs the full Longhorn teardown:
// post-install config cleanup, apply uninstall settings, create
// uninstall job, poll until done (~83 min worst case), delete
// deploy/job/storage classes, and clear the marker.
//
// The first three steps fail-hard because they own the path that
// actually shreds data — proceeding past a failure here risks
// inconsistent on-disk state. Post-shred cleanup steps log-and-
// continue so a partial-uninstall scenario converges instead of
// stranding the daemon behind a transient kubectl error.
func UninstallLonghorn(ctx context.Context) error {
	log.Printf("uninstalling Longhorn")

	longhornPostInstallConfigClean()

	if err := kubectlx.ApplyWithBackoff(ctx,
		longhornUninstallSettings, kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("apply longhorn uninstall settings: %w", err)
	}
	if err := kubectlx.CreateWithBackoff(ctx,
		longhornUninstallJobURL, kubectlx.ApplyOptions{}); err != nil {
		return fmt.Errorf("create longhorn uninstall job: %w", err)
	}
	if err := waitForLonghornUninstallJob(ctx); err != nil {
		// Caller (UninstallAll) special-cases ErrLonghornUninstallTimedOut
		// and aborts; other errors propagate as ordinary failures.
		return fmt.Errorf("wait for longhorn uninstall job: %w", err)
	}

	for _, url := range []string{longhornDeployURL, longhornUninstallJobURL} {
		if _, err := kubectl("delete", "-f", url); err != nil {
			log.Printf("warning: delete %s: %v", url, err)
		}
	}
	if err := deleteLonghornStorageClasses(ctx); err != nil {
		log.Printf("warning: delete longhorn storage classes: %v", err)
	}
	if err := state.Unmark(state.LonghornInitialized); err != nil {
		log.Printf("warning: unmark longhorn initialized: %v", err)
	}
	log.Printf("Longhorn uninstall complete")
	return nil
}

// UninstallCDI removes the CDI CR and operator.
func UninstallCDI(ctx context.Context) error {
	log.Printf("uninstalling CDI")
	cdiOperatorURL := fmt.Sprintf(
		"https://github.com/kubevirt/containerized-data-importer/releases/download/%s/cdi-operator.yaml",
		cdiVersion)
	cdiCRURL := fmt.Sprintf(
		"https://github.com/kubevirt/containerized-data-importer/releases/download/%s/cdi-cr.yaml",
		cdiVersion)
	for _, url := range []string{cdiCRURL, cdiOperatorURL} {
		if _, err := kubectl("delete", "-f", url, "--wait=true"); err != nil {
			log.Printf("warning: delete %s: %v", url, err)
		}
	}
	log.Printf("CDI uninstall complete")
	return nil
}

// UninstallKubeVirt removes the KubeVirt CR, operator, API services,
// webhooks, and every kubevirt.io label from every node.
func UninstallKubeVirt(ctx context.Context) error {
	log.Printf("uninstalling KubeVirt")

	if _, err := kubectl("delete", "-n", kubevirtNamespace,
		"kubevirt", "kubevirt", "--wait=true"); err != nil {
		log.Printf("warning: delete kubevirt CR: %v", err)
	}
	if _, err := kubectl("delete", "apiservices",
		"v1.subresources.kubevirt.io"); err != nil {
		log.Printf("warning: delete kubevirt apiservice: %v", err)
	}
	for _, w := range []struct{ kind, name string }{
		{"mutatingwebhookconfigurations", "virt-api-mutator"},
		{"validatingwebhookconfigurations", "virt-operator-validator"},
		{"validatingwebhookconfigurations", "virt-api-validator"},
	} {
		if _, err := kubectl("delete", w.kind, w.name); err != nil {
			log.Printf("warning: delete %s %s: %v", w.kind, w.name, err)
		}
	}
	// --wait=false on the operator delete — virt-operator pods can
	// hang after API resources are gone; we don't want to block the
	// whole uninstall on that.
	if _, err := kubectl("delete", "-f", kubevirtOperator,
		"--wait=false"); err != nil {
		log.Printf("warning: delete kubevirt operator: %v", err)
	}
	if err := removeKubeVirtNodeLabels(ctx); err != nil {
		log.Printf("warning: remove kubevirt node labels: %v", err)
	}
	if err := state.Unmark(state.KubevirtInitialized); err != nil {
		log.Printf("warning: unmark kubevirt initialized: %v", err)
	}
	log.Printf("KubeVirt uninstall complete")
	return nil
}

// UninstallMultus removes the Multus DaemonSet and the
// initialization marker.
func UninstallMultus(ctx context.Context) error {
	log.Printf("uninstalling Multus")
	if _, err := kubectl("delete", "-f", multusYAMLDst, "--wait=true"); err != nil {
		log.Printf("warning: delete multus daemonset: %v", err)
	}
	if err := state.Unmark(state.MultusInitialized); err != nil {
		log.Printf("warning: unmark multus initialized: %v", err)
	}
	log.Printf("Multus uninstall complete")
	return nil
}

// CleanupStorageClasses removes storage-classes.yaml, the k3s AddOn,
// and the lh-sc-rep1 storage class.
func CleanupStorageClasses(ctx context.Context) error {
	log.Printf("cleaning up storage classes")
	scManifest := filepath.Join(manifestsDst, "storage-classes.yaml")
	if err := os.Remove(scManifest); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("warning: remove %s: %v", scManifest, err)
	}
	if _, err := kubectl("-n", "kube-system", "delete",
		"AddOn/storage-classes"); err != nil {
		log.Printf("warning: delete storage-classes AddOn: %v", err)
	}
	if _, err := kubectl("delete", "sc", "lh-sc-rep1"); err != nil {
		log.Printf("warning: delete lh-sc-rep1 storage class: %v", err)
	}
	log.Printf("storage classes cleanup complete")
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// waitForAPIServer polls `kubectl cluster-info` until it succeeds.
func waitForAPIServer(ctx context.Context) error {
	log.Printf("waiting for API server...")
	for {
		if _, err := kubectl("cluster-info"); err == nil {
			log.Printf("API server is available")
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for API server: %w", ctx.Err())
		case <-time.After(5 * time.Second):
		}
	}
}

// waitForAllNodesReady polls until every node reports Ready (or
// Ready,SchedulingDisabled for cordoned nodes).
func waitForAllNodesReady(ctx context.Context) error {
	log.Printf("waiting for all nodes to be Ready...")
	for {
		ready, err := allNodesReady()
		if err == nil && ready {
			log.Printf("all nodes are Ready")
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for nodes: %w", ctx.Err())
		case <-time.After(5 * time.Second):
		}
	}
}

// allNodesReady reports whether every node in `kubectl get nodes`
// output starts its status column with "Ready". Empty output is
// treated as an error so a transient API miss doesn't pass.
func allNodesReady() (bool, error) {
	out, err := kubectl("get", "nodes", "--no-headers")
	if err != nil {
		return false, err
	}
	return parseAllNodesReady(out)
}

// parseAllNodesReady is the pure half of allNodesReady. Returns
// true iff every non-blank line's status column (field[1]) starts
// with "Ready" — accepting both "Ready" and "Ready,SchedulingDisabled".
// Returns (false, error) when there are zero rows.
func parseAllNodesReady(out string) (bool, error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return false, fmt.Errorf("no nodes found")
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "Ready") {
			return false, nil
		}
	}
	return true, nil
}

// waitForLonghornUninstallJob polls .status.succeeded on the
// longhorn-uninstall job until it equals "1" or the poll budget is
// exhausted.
func waitForLonghornUninstallJob(ctx context.Context) error {
	log.Printf("waiting for Longhorn uninstall job (max %d polls × %v)...",
		longhornUninstallMaxPolls, longhornUninstallPollInterval)
	for i := 0; i < longhornUninstallMaxPolls; i++ {
		out, err := kubectl("get", "job/longhorn-uninstall",
			"-n", longhornNamespace,
			"-o", "jsonpath={.status.succeeded}")
		if err == nil && strings.TrimSpace(out) == "1" {
			log.Printf("Longhorn uninstall job succeeded after %d polls", i+1)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for longhorn uninstall job: %w", ctx.Err())
		case <-time.After(longhornUninstallPollInterval):
		}
	}
	return fmt.Errorf("%w: %d polls × %v",
		ErrLonghornUninstallTimedOut,
		longhornUninstallMaxPolls, longhornUninstallPollInterval)
}

// longhornPostInstallConfigClean removes the runtime longhorn-cfg
// from the auto-deploy dir.
func longhornPostInstallConfigClean() {
	cfgPath := filepath.Join(manifestsDst, "longhorn-cfg.yaml")
	if err := os.Remove(cfgPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("warning: remove %s: %v", cfgPath, err)
	}
}

// deleteLonghornStorageClasses removes every storage class whose
// provisioner is driver.longhorn.io.
func deleteLonghornStorageClasses(ctx context.Context) error {
	out, err := kubectl("get", "sc",
		"-o", `jsonpath={range .items[?(@.provisioner=="driver.longhorn.io")]}{.metadata.name}{" "}{end}`)
	if err != nil {
		return fmt.Errorf("list longhorn storage classes: %w", err)
	}
	for _, sc := range strings.Fields(strings.TrimSpace(out)) {
		if _, err := kubectl("delete", "sc", sc); err != nil {
			log.Printf("warning: delete storage class %s: %v", sc, err)
		}
	}
	return nil
}

// nodeMetadata is the JSON shape we need from `kubectl get <node>
// -o json` to enumerate labels.
type nodeMetadata struct {
	Metadata struct {
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
}

// removeKubeVirtNodeLabels deletes every label containing
// "kubevirt.io" from every node. Per-node failures are logged AND
// counted; the function returns an error when any node was not
// successfully scrubbed, so the caller can decide whether to
// surface it (the base-k3s-mode cluster carrying stale
// kubevirt.io labels is a real misconfiguration, not a no-op).
func removeKubeVirtNodeLabels(ctx context.Context) error {
	out, err := kubectl("get", "node", "-o", "NAME")
	if err != nil {
		return fmt.Errorf("get node names: %w", err)
	}
	var failed int
	for _, node := range strings.Fields(strings.TrimSpace(out)) {
		if node == "" {
			continue
		}
		nodeJSON, err := kubectl("get", node, "-o", "json")
		if err != nil {
			log.Printf("warning: get %s: %v", node, err)
			failed++
			continue
		}
		var meta nodeMetadata
		if err := json.Unmarshal([]byte(nodeJSON), &meta); err != nil {
			log.Printf("warning: unmarshal node %s JSON: %v", node, err)
			failed++
			continue
		}
		labelsToRemove := kubeVirtLabelsToRemove(meta.Metadata.Labels)
		if len(labelsToRemove) == 0 {
			continue
		}
		args := append([]string{"label", node}, labelsToRemove...)
		if _, err := kubectl(args...); err != nil {
			log.Printf("warning: remove kubevirt labels from %s: %v", node, err)
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d node(s) retained kubevirt.io labels", failed)
	}
	return nil
}

// kubeVirtLabelsToRemove returns the kubectl-label argument forms
// (`key-` suffix) for every label containing "kubevirt.io".
func kubeVirtLabelsToRemove(labels map[string]string) []string {
	var out []string
	for key := range labels {
		if strings.Contains(key, "kubevirt.io") {
			out = append(out, key+"-")
		}
	}
	return out
}
