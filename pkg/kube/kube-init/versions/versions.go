// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package versions is the single source of the component versions
// this build of kube-init expects. Everything that names a version —
// manifest paths, release URLs, pre-loaded image tags — derives from
// a const here so a bump is one edit rather than a hunt.
//
// Deliberately a leaf: it imports nothing from kube-init, so any
// package can consume it without a cycle.
//
// Two things outside the Go tree still carry these versions and must
// be bumped in the same commit:
//
//   - update-component/expected_versions.yaml, which drives the
//     drift check for multus/kubevirt/cdi/longhorn;
//   - pkg/kube/kubevirt-operator.yaml, a vendored upstream manifest
//     that names the virt-operator image and sets KUBEVIRT_VERSION.
package versions

// Cluster component versions. Only K3s is overridable at runtime:
// the controller's k3s.version config item arrives as
// KubeConfig.K3sVersion and takes priority over the const below (see
// update.getDesiredK3sVersion). The rest have no config item, so
// these consts are the only declaration kube-init reads.
const (
	K3s      = "v1.34.2+k3s1"
	KubeVirt = "v1.7.3"
	CDI      = "v1.57.1"
	Longhorn = "v1.9.1"
	Multus   = "v3.9.3"

	Descheduler             = "v0.29.0"
	SystemUpgradeController = "v0.19.2"

	// Alpine is the SUC Plan's upgrade-container image.
	Alpine = "3.21"
)

// Longhorn ships these alongside its own release but they follow the
// upstream CSI sidecar cadence, so they do not track Longhorn above.
const (
	SupportBundleKit       = "v0.0.61"
	CSIAttacher            = "v4.9.0-20250709"
	CSIProvisioner         = "v5.3.0-20250709"
	CSINodeDriverRegistrar = "v2.14.0-20250709"
	CSIResizer             = "v1.14.0-20250709"
	CSISnapshotter         = "v8.3.0-20250709"
	CSILivenessProbe       = "v2.16.0-20250709"
)
