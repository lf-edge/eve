// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Paths owned by InstallSRIOVManifests. var so tests can redirect.
//
//   - SRIOVNumvfsGlob is the kernel-exposed sysfs entry that reveals
//     SR-IOV-capable PCI devices. Using /sys/bus/pci instead of
//     /sys/class/net because the kube container's network namespace
//     typically does not include the host's NICs; /sys/bus/pci is
//     namespace-independent and exposes sriov_numvfs regardless of
//     which netns owns the netdev.
//   - SRIOVBinSrc is the sriov-cni binary baked into the kube
//     container image by pkg/kube/Dockerfile (COPY --from=
//     sriov-cni-bin /usr/bin/sriov /out/usr/bin/sriov).
//   - SRIOVCNIBinDirs are the destinations for the binary. Multus
//     uses /var/lib/cni/bin (its binDir); /opt/cni/bin is the
//     k3s/flannel path and is kept in sync so tooling that looks
//     there finds the binary too.
//   - SRIOVManifestName is the DaemonSet manifest filename
//     installed into the k3s auto-deploy dir.
var (
	SRIOVNumvfsGlob   = "/sys/bus/pci/devices/*/sriov_numvfs"
	SRIOVBinSrc       = "/usr/bin/sriov"
	SRIOVCNIBinDirs   = []string{"/var/lib/cni/bin", "/opt/cni/bin"}
	SRIOVManifestName = "sriov-device-plugin.yaml"
)

// InstallSRIOVManifests stages the sriov-cni binary into the CNI
// bin directories and installs the sriov-network-device-plugin
// DaemonSet manifest into the k3s auto-deploy directory, but only
// on hardware that actually exposes SR-IOV-capable PCI devices.
//
// Idempotent and safe to call on every steady-state tick: content
// is compared against the existing destination before writing, so
// repeat calls are stat-and-read with no disk write. That matches
// the shell version's `cp -u` semantics and avoids the in-use
// overwrite risk that a blind copy would carry for the sriov
// binary while a Multus-launched plugin is reading it.
//
// On hardware without SR-IOV devices, returns nil silently — the
// caller calls this from the per-tick worker regardless of
// device class, so a quiet no-op is the correct behaviour.
//
// Mirrors install_sriov_manifests() from upstream commit
// a2bb3a52c ("pillar, kube: SR-IOV VF passthrough via Multus +
// sriov-cni for KubeVirt").
func InstallSRIOVManifests() error {
	return installSRIOVManifests(manifestsSrc, manifestsDst)
}

// installSRIOVManifests is the path-parameterised core of
// InstallSRIOVManifests. Tests pass t.TempDir() locations; the
// public wrapper uses the package-level paths the rest of the
// components/ code shares (manifestsSrc, manifestsDst).
func installSRIOVManifests(manifestsSrcDir, manifestsDstDir string) error {
	matches, err := filepath.Glob(SRIOVNumvfsGlob)
	if err != nil {
		return fmt.Errorf("glob %s: %w", SRIOVNumvfsGlob, err)
	}
	if len(matches) == 0 {
		return nil
	}
	if _, err := os.Stat(manifestsDstDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// k3s auto-deploy dir not ready yet (very early
			// boot — the dir is owned by the k3s server). Next
			// tick retries; until then the manifest can't be
			// consumed anyway.
			return nil
		}
		return fmt.Errorf("stat %s: %w", manifestsDstDir, err)
	}
	binData, err := os.ReadFile(SRIOVBinSrc)
	if err != nil {
		return fmt.Errorf("read %s: %w", SRIOVBinSrc, err)
	}
	for _, dir := range SRIOVCNIBinDirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		dst := filepath.Join(dir, "sriov")
		if err := copyIfChanged(dst, binData, 0o755); err != nil {
			return fmt.Errorf("stage sriov binary to %s: %w", dst, err)
		}
	}
	manifestSrc := filepath.Join(manifestsSrcDir, SRIOVManifestName)
	manifestDst := filepath.Join(manifestsDstDir, SRIOVManifestName)
	manifestData, err := os.ReadFile(manifestSrc)
	if err != nil {
		return fmt.Errorf("read %s: %w", manifestSrc, err)
	}
	if err := copyIfChanged(manifestDst, manifestData, 0o644); err != nil {
		return fmt.Errorf("copy SR-IOV manifest: %w", err)
	}
	return nil
}

// copyIfChanged writes data to dst only when the file's current
// contents differ. A missing dst is "different" — file is created.
// Permissions are set on first write only; if the file already
// exists with matching content, its mode is left alone.
//
// The point of the content compare (vs an unconditional write) is
// to avoid breaking any process that has the destination file open
// while we run — the sriov binary specifically may be exec'd by
// Multus mid-tick. Skip-on-same-bytes makes the steady-state path
// a no-op write.
func copyIfChanged(dst string, data []byte, mode os.FileMode) error {
	if existing, err := os.ReadFile(dst); err == nil {
		if bytes.Equal(existing, data) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", dst, err)
	}
	if err := os.WriteFile(dst, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	log.Printf("installed %s", dst)
	return nil
}
