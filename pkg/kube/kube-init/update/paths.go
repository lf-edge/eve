// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package update

// On-disk paths owned by this package. Declared as `var` rather than
// `const` so unit tests can redirect them onto temp dirs. Production
// callers MUST treat these as constants.

var (
	// AppliedKubeVersion records the last KubeVersion successfully
	// applied by this device. /var/lib in the kube container is a
	// bind-mount of /persist/vault/kube (ext4) or the etcd zvol
	// (zfs) — see cluster-init.sh — so the marker survives reboot
	// and lets CheckClusterComponents short-circuit when the
	// applied version already matches.
	AppliedKubeVersion = "/var/lib/applied-kube-version"

	// compUpdatePath is the helper binary that knows how to
	// version-compare and upgrade individual cluster components.
	compUpdatePath = "/usr/bin/update-component"

	// versionsFile is the manifest of expected component versions
	// that update-component reads.
	versionsFile = "/etc/expected_versions.yaml"

	// deschedulerJobYAML is the descheduler job manifest.
	deschedulerJobYAML = "/etc/descheduler-job.yaml"

	// deschedulerBootMarker prevents re-running the descheduler
	// job more than once per boot. /tmp clears on every boot so
	// the marker is naturally scoped to this boot cycle.
	deschedulerBootMarker = "/tmp/descheduler-ran-onboot"

	// pillarRootfs is where the pillar container's rootfs is
	// mounted into the host namespace. The zedkube binary used to
	// publish update status lives inside it and depends on shared
	// libraries also inside it.
	pillarRootfs = "/hostfs/containers/services/pillar/rootfs"

	// zedkubeBinRel is the zedkube binary path relative to
	// pillarRootfs.
	zedkubeBinRel = "/opt/zededa/bin/zedkube"

	// pillarLibDirRel is the shared library directory relative to
	// pillarRootfs, used as LD_LIBRARY_PATH when invoking
	// zedkubeBinRel.
	pillarLibDirRel = "/usr/lib/"
)
