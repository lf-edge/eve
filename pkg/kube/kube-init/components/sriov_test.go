// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Sysfs class attribute values for the two device kinds that matter
// here: a real NIC, and the SR-IOV-capable GPU that used to be
// mistaken for one.
const (
	classEthernet = "0x020000\n"
	classVGA      = "0x030000\n"
)

// redirectSRIOVPaths seeds source-side test fixtures and swaps the
// SRIOV* package-level vars (bin source, CNI bin dirs).
// manifestsSrc/Dst are constants for the rest of the package so the
// test calls installSRIOVManifests directly with t.TempDir() paths
// instead of redirecting them. The glob is owned by seedSRIOVDevices.
func redirectSRIOVPaths(t *testing.T) (root, manifestsDir, manifestsAutoDeploy string) {
	t.Helper()
	stubSRIOVWorkloadDelete(t)
	root = t.TempDir()
	binSrc := filepath.Join(root, "sriov-bin")
	manifestsDir = filepath.Join(root, "manifests-src")
	manifestsAutoDeploy = filepath.Join(root, "manifests-dst")

	if err := os.WriteFile(binSrc, []byte("FAKE_SRIOV_BINARY"), 0o755); err != nil {
		t.Fatalf("seed bin: %v", err)
	}
	if err := os.MkdirAll(manifestsDir, 0o755); err != nil {
		t.Fatalf("mkdir manifests-src: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(manifestsDir, "sriov-device-plugin.yaml"),
		[]byte("apiVersion: v1\nkind: ConfigMap\n"), 0o644); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	if err := os.MkdirAll(manifestsAutoDeploy, 0o755); err != nil {
		t.Fatalf("mkdir manifests-dst: %v", err)
	}

	oldBin := SRIOVBinSrc
	oldBinDirs := SRIOVCNIBinDirs

	SRIOVBinSrc = binSrc
	SRIOVCNIBinDirs = []string{
		filepath.Join(root, "cni-bin-varlib"),
		filepath.Join(root, "cni-bin-opt"),
	}

	t.Cleanup(func() {
		SRIOVBinSrc = oldBin
		SRIOVCNIBinDirs = oldBinDirs
	})
	return
}

// fakePCIDevice describes one entry to materialise under the fake
// /sys/bus/pci/devices tree. An empty numvfs means the device exposes
// no sriov_numvfs at all (not SR-IOV capable), so the glob skips it.
type fakePCIDevice struct {
	bdf    string
	numvfs string
	class  string
}

// seedSRIOVDevices builds a fake /sys/bus/pci/devices tree and points
// SRIOVNumvfsGlob at it. The glob keeps its wildcard so the real
// multi-device walk is exercised rather than a single hard-coded path.
func seedSRIOVDevices(t *testing.T, devs ...fakePCIDevice) {
	t.Helper()
	root := t.TempDir()
	for _, d := range devs {
		dir := filepath.Join(root, d.bdf)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d.bdf, err)
		}
		if d.numvfs != "" {
			if err := os.WriteFile(filepath.Join(dir, "sriov_numvfs"),
				[]byte(d.numvfs), 0o644); err != nil {
				t.Fatalf("seed sriov_numvfs for %s: %v", d.bdf, err)
			}
		}
		if d.class != "" {
			if err := os.WriteFile(filepath.Join(dir, "class"),
				[]byte(d.class), 0o644); err != nil {
				t.Fatalf("seed class for %s: %v", d.bdf, err)
			}
		}
	}
	old := SRIOVNumvfsGlob
	SRIOVNumvfsGlob = filepath.Join(root, "*", "sriov_numvfs")
	t.Cleanup(func() { SRIOVNumvfsGlob = old })
}

// nicWithVFs is the happy-path fixture: an Ethernet controller with
// VFs instantiated.
func nicWithVFs() fakePCIDevice {
	return fakePCIDevice{bdf: "0000:03:00.0", numvfs: "4\n", class: classEthernet}
}

// assertNoStaging fails if anything was written to the auto-deploy dir
// or the CNI bin dirs.
func assertNoStaging(t *testing.T, root, dst string) {
	t.Helper()
	entries, _ := os.ReadDir(dst)
	if len(entries) != 0 {
		t.Errorf("manifests dir should be untouched, got %d entries", len(entries))
	}
	for _, dir := range []string{"cni-bin-varlib", "cni-bin-opt"} {
		if _, err := os.Stat(filepath.Join(root, dir, "sriov")); err == nil {
			t.Errorf("sriov binary should not have been staged to %s", dir)
		}
	}
}

func TestReconcileSRIOVManifests_NoHardware(t *testing.T) {
	root, src, dst := redirectSRIOVPaths(t)
	seedSRIOVDevices(t, fakePCIDevice{bdf: "0000:03:00.0", class: classEthernet})

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("unexpected error on no-SR-IOV box: %v", err)
	}
	assertNoStaging(t, root, dst)
}

// TestInstallSRIOVManifests_NonNetworkDeviceIgnored is the bug this
// gate was fixed for.
//
// sriov_numvfs is exposed by any SR-IOV-capable PCI function, and on
// an RTX 5090 box the GPU (class 0x030000, sriov_totalvfs=1) was the
// only match. The bare glob therefore deployed the device plugin to a
// node with no SR-IOV NIC, where zedkube correctly published an empty
// resourceList and the plugin exited(1) on it — 256 restarts, and
// kube-init pinned out of StateRunning because one kube-system pod
// could never become Ready.
func TestReconcileSRIOVManifests_NonNetworkDeviceIgnored(t *testing.T) {
	root, src, dst := redirectSRIOVPaths(t)
	// numvfs deliberately non-zero: it is the class that must
	// disqualify this device, not the VF count.
	seedSRIOVDevices(t, fakePCIDevice{
		bdf: "0000:01:00.0", numvfs: "1\n", class: classVGA})

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNoStaging(t, root, dst)
}

// TestInstallSRIOVManifests_CapableButNoVFsIgnored covers the other
// half of the gate: an SR-IOV-capable NIC with no VFs created yet has
// no IoNetEthVF bundles in AssignableAdapters, so zedkube would build
// an empty resourceList and the plugin would crashloop just the same.
func TestReconcileSRIOVManifests_CapableButNoVFsIgnored(t *testing.T) {
	root, src, dst := redirectSRIOVPaths(t)
	seedSRIOVDevices(t, fakePCIDevice{
		bdf: "0000:03:00.0", numvfs: "0\n", class: classEthernet})

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNoStaging(t, root, dst)
}

// TestInstallSRIOVManifests_MissingClassIgnored pins the fail-closed
// behaviour: a device whose class attribute cannot be read is not
// assumed to be a NIC.
func TestReconcileSRIOVManifests_MissingClassIgnored(t *testing.T) {
	root, src, dst := redirectSRIOVPaths(t)
	seedSRIOVDevices(t, fakePCIDevice{bdf: "0000:03:00.0", numvfs: "4\n"})

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertNoStaging(t, root, dst)
}

// TestInstallSRIOVManifests_NICFoundBesideDisqualifiedDevices proves
// the walk does not stop at the first device that fails the gate —
// the GPU sorts before the NIC by BDF, which is exactly the layout on
// the box that surfaced the bug.
func TestReconcileSRIOVManifests_NICFoundBesideDisqualifiedDevices(t *testing.T) {
	_, src, dst := redirectSRIOVPaths(t)
	seedSRIOVDevices(t,
		fakePCIDevice{bdf: "0000:01:00.0", numvfs: "1\n", class: classVGA},
		fakePCIDevice{bdf: "0000:02:00.0", numvfs: "0\n", class: classEthernet},
		nicWithVFs(),
	)

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("reconcileSRIOVManifests: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "sriov-device-plugin.yaml")); err != nil {
		t.Errorf("manifest should have been staged: %v", err)
	}
}

func TestReconcileSRIOVManifests_HardwarePresent_StagesEverything(t *testing.T) {
	root, src, dst := redirectSRIOVPaths(t)
	seedSRIOVDevices(t, nicWithVFs())

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("reconcileSRIOVManifests: %v", err)
	}

	// Binary staged to both CNI bin dirs.
	for _, dir := range []string{
		filepath.Join(root, "cni-bin-varlib"),
		filepath.Join(root, "cni-bin-opt"),
	} {
		body, err := os.ReadFile(filepath.Join(dir, "sriov"))
		if err != nil {
			t.Fatalf("read staged binary in %s: %v", dir, err)
		}
		if string(body) != "FAKE_SRIOV_BINARY" {
			t.Errorf("binary content mismatch in %s: %q", dir, body)
		}
	}

	// Manifest staged to auto-deploy.
	manifest, err := os.ReadFile(
		filepath.Join(dst, "sriov-device-plugin.yaml"))
	if err != nil {
		t.Fatalf("read staged manifest: %v", err)
	}
	if string(manifest) != "apiVersion: v1\nkind: ConfigMap\n" {
		t.Errorf("manifest content mismatch: %q", manifest)
	}
}

func TestReconcileSRIOVManifests_Idempotent(t *testing.T) {
	root, src, dst := redirectSRIOVPaths(t)
	seedSRIOVDevices(t, nicWithVFs())

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Pin the dst inode times so we can detect any rewrite.
	binDst := filepath.Join(root, "cni-bin-varlib", "sriov")
	before, err := os.Stat(binDst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("second call: %v", err)
	}

	after, err := os.Stat(binDst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Same content + content-compare skip means the file should
	// not have been rewritten — mtime preserved.
	if !before.ModTime().Equal(after.ModTime()) {
		t.Errorf("idempotent call rewrote the binary; mtime changed %v -> %v",
			before.ModTime(), after.ModTime())
	}
}

func TestReconcileSRIOVManifests_ContentChange_Rewrites(t *testing.T) {
	root, src, dst := redirectSRIOVPaths(t)
	seedSRIOVDevices(t, nicWithVFs())

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Now change the source binary to simulate an EVE upgrade.
	if err := os.WriteFile(SRIOVBinSrc, []byte("NEW_SRIOV_BINARY"), 0o755); err != nil {
		t.Fatalf("rewrite source: %v", err)
	}

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("second call: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "cni-bin-varlib", "sriov"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "NEW_SRIOV_BINARY" {
		t.Errorf("dst not updated on source change: %q", got)
	}
}

func TestReconcileSRIOVManifests_NoK3sManifestsDir(t *testing.T) {
	_, src, dst := redirectSRIOVPaths(t)
	// Wipe the auto-deploy dir to simulate very-early-boot where
	// the k3s server hasn't created /var/lib/rancher/k3s/server/manifests
	// yet.
	if err := os.RemoveAll(dst); err != nil {
		t.Fatalf("rm: %v", err)
	}
	seedSRIOVDevices(t, nicWithVFs())

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("missing auto-deploy dir should be a no-op, got: %v", err)
	}
}

// TestInstallSRIOVManifests_RetractsStaleManifest is the remediation
// path for nodes the old capability-only gate already contaminated.
//
// The staged manifest outlives reboots and EVE upgrades, and k3s
// re-applies it from disk every boot, so tightening the gate alone
// would leave those nodes crashlooping forever. Dropping the file is
// what retracts the DaemonSet: k3s records the applied objects in the
// Addon's addon.k3s.cattle.io/gvks annotation and deletes them when the
// source file disappears.
func TestReconcileSRIOVManifests_RetractsStaleManifest(t *testing.T) {
	_, src, dst := redirectSRIOVPaths(t)
	staged := filepath.Join(dst, "sriov-device-plugin.yaml")
	if err := os.WriteFile(staged, []byte("stale\n"), 0o644); err != nil {
		t.Fatalf("seed stale manifest: %v", err)
	}
	// Only an SR-IOV-capable GPU, which is what fooled the old gate.
	seedSRIOVDevices(t, fakePCIDevice{
		bdf: "0000:01:00.0", numvfs: "1\n", class: classVGA})

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("reconcileSRIOVManifests: %v", err)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Errorf("stale manifest should have been retracted, stat err = %v", err)
	}
}

// TestInstallSRIOVManifests_RetractIsIdempotent covers the steady state
// on the overwhelming majority of nodes: no VFs, nothing staged, and
// the per-tick call must stay a silent no-op rather than erroring on
// the absent file.
func TestReconcileSRIOVManifests_RetractIsIdempotent(t *testing.T) {
	root, src, dst := redirectSRIOVPaths(t)
	seedSRIOVDevices(t, fakePCIDevice{bdf: "0000:03:00.0", class: classEthernet})

	for i := 0; i < 2; i++ {
		if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	assertNoStaging(t, root, dst)
}

// TestInstallSRIOVManifests_RetractSurvivesMissingDir pins the
// early-boot ordering: the gate can close before the k3s server has
// created its auto-deploy dir, and that must not surface as an error.
func TestReconcileSRIOVManifests_RetractSurvivesMissingDir(t *testing.T) {
	_, src, dst := redirectSRIOVPaths(t)
	if err := os.RemoveAll(dst); err != nil {
		t.Fatalf("rm: %v", err)
	}
	seedSRIOVDevices(t, fakePCIDevice{bdf: "0000:03:00.0", class: classEthernet})

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("missing auto-deploy dir should be a no-op, got: %v", err)
	}
}

// stubSRIOVWorkloadDelete replaces the API-backed workload delete with
// a counter and resets the package latch, so the reconcile is testable
// without an apiserver and tests cannot leak state into each other.
// Returns the call count.
func stubSRIOVWorkloadDelete(t *testing.T) *int {
	t.Helper()
	calls := 0
	oldFn, oldLatch := sriovDeleteWorkload, sriovWorkloadGone
	sriovDeleteWorkload = func(context.Context) error {
		calls++
		return nil
	}
	sriovWorkloadGone = false
	t.Cleanup(func() {
		sriovDeleteWorkload, sriovWorkloadGone = oldFn, oldLatch
	})
	return &calls
}

// TestReconcileSRIOVManifests_DeletesWorkloadOnRetract pins that EVE
// deletes the DaemonSet itself rather than leaving it to k3s's Addon
// GC. Relying on another component's cleanup would make the
// remediation silently dependent on k3s's version-specific behaviour.
func TestReconcileSRIOVManifests_DeletesWorkloadOnRetract(t *testing.T) {
	_, src, dst := redirectSRIOVPaths(t)
	calls := stubSRIOVWorkloadDelete(t)
	staged := filepath.Join(dst, "sriov-device-plugin.yaml")
	if err := os.WriteFile(staged, []byte("stale\n"), 0o644); err != nil {
		t.Fatalf("seed stale manifest: %v", err)
	}
	seedSRIOVDevices(t, fakePCIDevice{
		bdf: "0000:01:00.0", numvfs: "1\n", class: classVGA})

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("reconcileSRIOVManifests: %v", err)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Errorf("stale manifest should have been retracted, stat err = %v", err)
	}
	if *calls != 1 {
		t.Errorf("workload delete called %d times, want 1", *calls)
	}
}

// TestReconcileSRIOVManifests_RetractLatchesAfterSuccess keeps the
// steady state free: the vast majority of nodes have no SR-IOV NIC and
// nothing staged, and must not issue an API delete on every tick
// forever.
func TestReconcileSRIOVManifests_RetractLatchesAfterSuccess(t *testing.T) {
	_, src, dst := redirectSRIOVPaths(t)
	calls := stubSRIOVWorkloadDelete(t)
	seedSRIOVDevices(t, fakePCIDevice{bdf: "0000:03:00.0", class: classEthernet})

	for i := 0; i < 5; i++ {
		if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
	}
	if *calls != 1 {
		t.Errorf("workload delete called %d times across 5 ticks, want 1", *calls)
	}
}

// TestReconcileSRIOVManifests_RetractRetriesAfterFailure covers the
// early-boot ordering: the tick can run before the kube client exists,
// and a failed delete must not latch or the workload is never cleaned
// up on that boot.
func TestReconcileSRIOVManifests_RetractRetriesAfterFailure(t *testing.T) {
	_, src, dst := redirectSRIOVPaths(t)
	stubSRIOVWorkloadDelete(t)
	seedSRIOVDevices(t, fakePCIDevice{bdf: "0000:03:00.0", class: classEthernet})

	calls := 0
	sriovDeleteWorkload = func(context.Context) error {
		calls++
		if calls == 1 {
			return errors.New("kube client not initialised yet")
		}
		return nil
	}

	if err := reconcileSRIOVManifests(context.Background(), src, dst); err == nil {
		t.Error("first tick should surface the delete failure")
	}
	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Errorf("second tick should retry and succeed, got: %v", err)
	}
	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("third tick: %v", err)
	}
	if calls != 2 {
		t.Errorf("delete called %d times, want 2 (retry then latch)", calls)
	}
}

// TestReconcileSRIOVManifests_LatchDropsWhenVFsAppear covers a host
// gaining an SR-IOV PF after an earlier retraction latched: staging
// must resume, and a later retraction must delete again rather than
// trusting the stale latch.
func TestReconcileSRIOVManifests_LatchDropsWhenVFsAppear(t *testing.T) {
	_, src, dst := redirectSRIOVPaths(t)
	calls := stubSRIOVWorkloadDelete(t)

	// No VFs yet: retract and latch.
	seedSRIOVDevices(t, fakePCIDevice{bdf: "0000:03:00.0", class: classEthernet})
	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("retract tick: %v", err)
	}

	// VFs appear.
	seedSRIOVDevices(t, nicWithVFs())
	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("stage tick: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "sriov-device-plugin.yaml")); err != nil {
		t.Fatalf("manifest should have been staged: %v", err)
	}

	// VFs go away again: the latch must not suppress the delete.
	seedSRIOVDevices(t, fakePCIDevice{bdf: "0000:03:00.0", class: classEthernet})
	if err := reconcileSRIOVManifests(context.Background(), src, dst); err != nil {
		t.Fatalf("second retract tick: %v", err)
	}
	if *calls != 2 {
		t.Errorf("workload delete called %d times, want 2", *calls)
	}
}
