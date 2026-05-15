// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

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

// Cluster-mode markers. EdgeNodeClusterMode and BaseK3sMode are
// mutually exclusive in any consistent state; the cluster-mode
// transition flow is responsible for keeping them so. Likewise
// ConvertToSingleNode and TransitionToCluster are mutually exclusive
// request files consumed and unmarked by that flow.
const (
	EdgeNodeClusterMode Marker = "/var/lib/edge-node-cluster-mode"

	BaseK3sMode Marker = "/var/lib/base-k3s-mode"

	ConvertToSingleNode Marker = "/var/lib/convert-to-single-node"

	TransitionToCluster Marker = "/var/lib/transition-to-cluster"

	// RequestRetouchMultus asks the daemon to re-apply the Multus
	// DaemonSet — used after cluster-mode transitions where Multus
	// pods may have been orphaned by the node-name change.
	RequestRetouchMultus Marker = "/var/lib/request-retouch-multus"
)
