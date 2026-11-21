// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Paths owned by InstallSRIOVManifests. var so tests can redirect.
//
//   - SRIOVNumvfsGlob is the kernel-exposed sysfs entry that reveals
//     SR-IOV-capable PCI devices. Using /sys/bus/pci instead of
//     /sys/class/net because the kube container's network namespace
//     typically does not include the host's NICs; /sys/bus/pci is
//     namespace-independent and exposes sriov_numvfs regardless of
//     which netns owns the netdev. A match is a necessary but not a
//     sufficient signal — see sriovNetworkVFsPresent.
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

// pciClassNetwork is the PCI base class for network controllers as it
// appears in the sysfs "class" attribute, which the kernel formats as
// 0xBBSSPP (base class, subclass, prog-if). Matching the base class
// alone admits every network subclass: Ethernet is 0x020000, the
// wireless controllers on the same boxes are 0x028000.
const pciClassNetwork = "0x02"

// Identity of the objects the manifest creates, needed to retract them
// by name. Must track pkg/kube/sriov/sriov-device-plugin.yaml.
const (
	sriovNamespace      = "kube-system"
	sriovDaemonSetName  = "kube-sriov-device-plugin"
	sriovServiceAccount = "sriov-device-plugin"
)

// sriovDeleteWorkload deletes the objects the manifest created. var so
// tests can exercise the reconcile without an API server.
var sriovDeleteWorkload = deleteSRIOVWorkload

// sriovWorkloadGone latches once the workload has been confirmed
// absent, so the steady-state tick costs nothing on the overwhelming
// majority of nodes — no VFs, and nothing ever staged to retract.
var sriovWorkloadGone bool

// ReconcileSRIOVManifests stages the sriov-cni binary into the CNI
// bin directories and installs the sriov-network-device-plugin
// DaemonSet manifest into the k3s auto-deploy directory, but only
// on hosts that actually have SR-IOV network VFs configured.
//
// Idempotent and safe to call on every steady-state tick: content
// is compared against the existing destination before writing, so
// repeat calls are stat-and-read with no disk write. Avoids the
// in-use overwrite risk that a blind copy would carry for the sriov
// binary while a Multus-launched plugin is reading it.
//
// On hosts with no SR-IOV network VFs it instead retracts the manifest
// and the objects k3s applied from it, so a node that a previous EVE
// version wrongly deployed the plugin to is remediated on upgrade
// rather than crashlooping forever. The per-tick caller makes this a
// reconcile in both directions; it is silent when there is nothing to
// do, and stops making API calls once the retraction is confirmed.
func ReconcileSRIOVManifests(ctx context.Context) error {
	return reconcileSRIOVManifests(ctx, manifestsSrc, manifestsDst)
}

// reconcileSRIOVManifests is the path-parameterised core of
// ReconcileSRIOVManifests. Tests pass t.TempDir() locations; the
// public wrapper uses the package-level paths the rest of the
// components/ code shares (manifestsSrc, manifestsDst).
func reconcileSRIOVManifests(ctx context.Context, manifestsSrcDir, manifestsDstDir string) error {
	present, err := sriovNetworkVFsPresent()
	if err != nil {
		return err
	}
	manifestDst := filepath.Join(manifestsDstDir, SRIOVManifestName)
	if !present {
		return retractSRIOVDevicePlugin(ctx, manifestDst)
	}
	// VFs can appear on a host we retracted from earlier (a device
	// model gaining an SR-IOV PF), so drop the latch on the way in.
	sriovWorkloadGone = false
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
	manifestData, err := os.ReadFile(manifestSrc)
	if err != nil {
		return fmt.Errorf("read %s: %w", manifestSrc, err)
	}
	if err := copyIfChanged(manifestDst, manifestData, 0o644); err != nil {
		return fmt.Errorf("copy SR-IOV manifest: %w", err)
	}
	return nil
}

// retractSRIOVDevicePlugin undoes a staging this host should never
// have had. It is what remediates a node the old capability-only gate
// already deployed the plugin to: the staged manifest survives reboots
// and EVE upgrades and k3s re-applies it from disk every boot, so
// tightening the gate alone would leave those nodes crashlooping.
//
// The file goes first, then the objects. k3s's deploy controller would
// re-apply the manifest if it were still on disk when the DaemonSet
// disappeared, so deleting in the other order just churns.
//
// Deleting the objects explicitly rather than leaving it to k3s: the
// deploy controller does record what it applied, in the Addon's
// addon.k3s.cattle.io/gvks annotation ("apps/v1, Kind=DaemonSet;/v1,
// Kind=ServiceAccount" here), and that is the only thing tying the
// objects back to the file since it sets no ownerReferences on them.
// But relying on another component's cleanup for the whole
// remediation makes it silently version-dependent, and the delete is
// cheap and idempotent — so EVE owns it and k3s's own GC is a backstop
// rather than the mechanism.
func retractSRIOVDevicePlugin(ctx context.Context, manifestPath string) error {
	removed, err := removeStagedManifest(manifestPath)
	if err != nil {
		return err
	}
	if removed {
		// Something was staged, so the workload is presumed up
		// whatever an earlier tick concluded.
		sriovWorkloadGone = false
	}
	if sriovWorkloadGone {
		return nil
	}
	if err := sriovDeleteWorkload(ctx); err != nil {
		// Non-fatal, and deliberately not latched: the next tick
		// retries, and k3s's Addon GC is the backstop meanwhile.
		return fmt.Errorf("retract SR-IOV device plugin: %w", err)
	}
	sriovWorkloadGone = true
	return nil
}

// removeStagedManifest deletes a staged manifest if present, reporting
// whether it had anything to do.
func removeStagedManifest(path string) (bool, error) {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("remove %s: %w", path, err)
	}
	log.Printf("retracted %s: no SR-IOV network VFs on this host", path)
	return true, nil
}

// deleteSRIOVWorkload removes the DaemonSet and ServiceAccount the
// manifest created. Already-absent objects are a success — this runs
// on every node with no SR-IOV NIC, where there was never anything to
// delete.
func deleteSRIOVWorkload(ctx context.Context) error {
	if !kubeclient.HasDefault() {
		return errors.New("kube client not initialised yet")
	}
	cs := kubeclient.Default().Clientset
	if err := kubectlx.IgnoreNotFound(cs.AppsV1().
		DaemonSets(sriovNamespace).
		Delete(ctx, sriovDaemonSetName, metav1.DeleteOptions{})); err != nil {
		return fmt.Errorf("delete DaemonSet %s/%s: %w",
			sriovNamespace, sriovDaemonSetName, err)
	}
	if err := kubectlx.IgnoreNotFound(cs.CoreV1().
		ServiceAccounts(sriovNamespace).
		Delete(ctx, sriovServiceAccount, metav1.DeleteOptions{})); err != nil {
		return fmt.Errorf("delete ServiceAccount %s/%s: %w",
			sriovNamespace, sriovServiceAccount, err)
	}
	return nil
}

// sriovNetworkVFsPresent reports whether this host has a network PCI
// function with SR-IOV VFs actually instantiated.
//
// Both halves matter, and testing "does the glob match anything" had
// neither:
//
//   - Network class: sriov_numvfs is exposed by every SR-IOV-capable
//     function, not only by NICs. An NVIDIA GPU advertising vGPU
//     capability (class 0x030000, sriov_totalvfs=1) satisfied the bare
//     glob by itself, so the device plugin was deployed to boxes with
//     no SR-IOV NIC at all.
//   - numvfs > 0: capability is not configuration. zedkube builds the
//     plugin's ConfigMap from the IoNetEthVF bundles in
//     AssignableAdapters, which exist only once domainmgr has created
//     the VFs. With no VFs that ConfigMap is a legitimately empty
//     resourceList, and the upstream plugin exits(1) rather than idle
//     on an empty resourceList — so the pod crashloops for the life of
//     the node and holds kube-init out of StateRunning.
//
// Unreadable attributes are skipped rather than fatal: this runs on
// every steady-state tick, and a device vanishing mid-walk is a
// hotplug race, not a failure.
func sriovNetworkVFsPresent() (bool, error) {
	matches, err := filepath.Glob(SRIOVNumvfsGlob)
	if err != nil {
		return false, fmt.Errorf("glob %s: %w", SRIOVNumvfsGlob, err)
	}
	for _, numvfsPath := range matches {
		numvfs, err := readSysfsUint(numvfsPath)
		if err != nil || numvfs == 0 {
			continue
		}
		if !isPCINetworkClass(filepath.Join(filepath.Dir(numvfsPath), "class")) {
			continue
		}
		return true, nil
	}
	return false, nil
}

// readSysfsUint reads a sysfs attribute holding a single decimal value.
func readSysfsUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// isPCINetworkClass reports whether the sysfs PCI class attribute at
// path belongs to a network controller. An unreadable attribute reads
// as "not a NIC": the gate this feeds should stay closed unless the
// hardware positively identifies itself.
func isPCINetworkClass(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(string(data)), pciClassNetwork)
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
