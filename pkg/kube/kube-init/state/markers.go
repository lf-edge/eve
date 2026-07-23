// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"fmt"
	"os"
)

// Component progress markers — one-shot init outcomes recorded under
// /var/lib so the daemon can pick up where it left off across restarts
// without re-running expensive setup. EVE's /var/lib is tmpfs, so
// these markers do NOT survive reboots — cross-reboot state belongs
// in /persist.
//
// All markers carry the Marker type so go vet flags a bare string
// accidentally passed to IsMarked / Mark / Unmark. Untyped string
// literals still convert implicitly so const declarations stay
// uncluttered.
//
// The filenames are an external contract: the EVE base-OS debug
// tooling greps for these specific names, so renaming a marker is a
// coordinated change, not a refactor.
const (
	AllComponentsInitialized Marker = "/var/lib/all_components_initialized"

	K3sInstalledUnpacked Marker = "/var/lib/k3s_installed_unpacked"

	MultusInitialized Marker = "/var/lib/multus_initialized"

	KubevirtInitialized Marker = "/var/lib/kubevirt_initialized"

	// KubevirtFeatureGatesMigrated is distinct from KubevirtInitialized
	// so the one-shot KubeVirt feature-gate migration runs exactly
	// once even if KubeVirt is re-initialized later.
	KubevirtFeatureGatesMigrated Marker = "/var/lib/kubevirt-feature-gates-migrated"

	LonghornInitialized Marker = "/var/lib/longhorn_initialized"

	DebugUserInitialized Marker = "/var/lib/debuguser-initialized"

	NodeLabelsInitialized Marker = "/var/lib/node-labels-initialized"
)

// Cluster-mode markers. EdgeNodeClusterMode and NativeKubernetesMode
// are mutually exclusive in any consistent state; the cluster-mode
// transition flow is responsible for keeping them so. Likewise
// ConvertToSingleNode and TransitionToCluster are mutually exclusive
// request files consumed and unmarked by that flow.
const (
	EdgeNodeClusterMode Marker = "/var/lib/edge-node-cluster-mode"

	// NativeKubernetesMode is the legacy CLUSTER_TYPE_K3S_BASE
	// conversion-complete gate: set once the replicated-storage
	// components (KubeVirt, CDI, Longhorn) have been uninstalled
	// so that follow-up boots know to skip re-installing them.
	// K3S_BASE is being phased out in favour of
	// CLUSTER_TYPE_REPLICATED_STORAGE + the
	// EdgeNodeClusterConfig.EnableNativeK8SOrchestration opt-in
	// (which keeps kubevirt/longhorn installed); the wording overlap
	// with that opt-in is coincidental and not a shared meaning.
	// The file name is an external contract (see the package-level
	// comment) — do not renumber without coordinating with the
	// EVE debug tooling.
	NativeKubernetesMode Marker = "/var/lib/native-kubernetes-mode"

	ConvertToSingleNode Marker = "/var/lib/convert-to-single-node"

	TransitionToCluster Marker = "/var/lib/transition-to-cluster"

	// RequestRetouchMultus asks the daemon to re-apply the Multus
	// DaemonSet — used after cluster-mode transitions where Multus
	// pods may have been orphaned by the node-name change.
	RequestRetouchMultus Marker = "/var/lib/request-retouch-multus"
)

// legacyBaseK3sMode is the pre-rename NativeKubernetesMode path.
// Used only by MigrateLegacyBaseK3sMode on boot; nothing else
// should read or write it.
const legacyBaseK3sMode Marker = "/var/lib/base-k3s-mode"

// MigrateLegacyBaseK3sMode renames the legacy /var/lib/base-k3s-mode
// marker to /var/lib/native-kubernetes-mode if the legacy file
// exists and the new one does not. Devices that completed the
// K3sBase conversion under an older EVE image carry the legacy
// name; without this rename the new code would treat an already-
// converted device as un-converted (re-installing KubeVirt and
// friends). Idempotent and safe on cold boots where neither file
// exists.
func MigrateLegacyBaseK3sMode() error {
	legacyPresent, err := IsMarked(legacyBaseK3sMode)
	if err != nil {
		return fmt.Errorf("check legacy base-k3s-mode marker: %w", err)
	}
	if !legacyPresent {
		return nil
	}
	newPresent, err := IsMarked(NativeKubernetesMode)
	if err != nil {
		return fmt.Errorf("check native-kubernetes-mode marker: %w", err)
	}
	if newPresent {
		// Both present: legacy is stale. Remove it so subsequent
		// boots don't repeat the check work.
		if err := Unmark(legacyBaseK3sMode); err != nil {
			return fmt.Errorf("remove stale legacy marker: %w", err)
		}
		return nil
	}
	if err := os.Rename(string(legacyBaseK3sMode), string(NativeKubernetesMode)); err != nil {
		return fmt.Errorf("rename %s -> %s: %w",
			legacyBaseK3sMode, NativeKubernetesMode, err)
	}
	return nil
}
