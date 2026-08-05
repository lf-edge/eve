// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"os"
	"path/filepath"
	"testing"
)

// redirectSRIOVPaths seeds source-side test fixtures and swaps the
// SRIOV* package-level vars (bin source, CNI bin dirs, glob).
// manifestsSrc/Dst are constants for the rest of the package so the
// test calls installSRIOVManifests directly with t.TempDir() paths
// instead of redirecting them.
func redirectSRIOVPaths(t *testing.T) (root, manifestsDir, manifestsAutoDeploy string) {
	t.Helper()
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
	oldGlob := SRIOVNumvfsGlob

	SRIOVBinSrc = binSrc
	SRIOVCNIBinDirs = []string{
		filepath.Join(root, "cni-bin-varlib"),
		filepath.Join(root, "cni-bin-opt"),
	}

	t.Cleanup(func() {
		SRIOVBinSrc = oldBin
		SRIOVCNIBinDirs = oldBinDirs
		SRIOVNumvfsGlob = oldGlob
	})
	return
}

// pointGlobAtTempfile sets SRIOVNumvfsGlob at a one-off file under
// t.TempDir() and returns whether to create the marker (so the
// caller can simulate "no SR-IOV present" by passing false).
func pointGlobAtTempfile(t *testing.T, present bool) {
	t.Helper()
	root := t.TempDir()
	marker := filepath.Join(root, "sriov_numvfs")
	if present {
		if err := os.WriteFile(marker, []byte("0\n"), 0o644); err != nil {
			t.Fatalf("seed marker: %v", err)
		}
	}
	old := SRIOVNumvfsGlob
	SRIOVNumvfsGlob = marker
	t.Cleanup(func() { SRIOVNumvfsGlob = old })
}

func TestInstallSRIOVManifests_NoHardware(t *testing.T) {
	_, src, dst := redirectSRIOVPaths(t)
	pointGlobAtTempfile(t, false)

	if err := installSRIOVManifests(src, dst); err != nil {
		t.Fatalf("unexpected error on no-SR-IOV box: %v", err)
	}
	entries, _ := os.ReadDir(dst)
	if len(entries) != 0 {
		t.Errorf("manifests dir should be untouched, got %d entries", len(entries))
	}
}

func TestInstallSRIOVManifests_HardwarePresent_StagesEverything(t *testing.T) {
	root, src, dst := redirectSRIOVPaths(t)
	pointGlobAtTempfile(t, true)

	if err := installSRIOVManifests(src, dst); err != nil {
		t.Fatalf("installSRIOVManifests: %v", err)
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

func TestInstallSRIOVManifests_Idempotent(t *testing.T) {
	root, src, dst := redirectSRIOVPaths(t)
	pointGlobAtTempfile(t, true)

	if err := installSRIOVManifests(src, dst); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Pin the dst inode times so we can detect any rewrite.
	binDst := filepath.Join(root, "cni-bin-varlib", "sriov")
	before, err := os.Stat(binDst)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if err := installSRIOVManifests(src, dst); err != nil {
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

func TestInstallSRIOVManifests_ContentChange_Rewrites(t *testing.T) {
	root, src, dst := redirectSRIOVPaths(t)
	pointGlobAtTempfile(t, true)

	if err := installSRIOVManifests(src, dst); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Now change the source binary to simulate an EVE upgrade.
	if err := os.WriteFile(SRIOVBinSrc, []byte("NEW_SRIOV_BINARY"), 0o755); err != nil {
		t.Fatalf("rewrite source: %v", err)
	}

	if err := installSRIOVManifests(src, dst); err != nil {
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

func TestInstallSRIOVManifests_NoK3sManifestsDir(t *testing.T) {
	_, src, dst := redirectSRIOVPaths(t)
	// Wipe the auto-deploy dir to simulate very-early-boot where
	// the k3s server hasn't created /var/lib/rancher/k3s/server/manifests
	// yet.
	if err := os.RemoveAll(dst); err != nil {
		t.Fatalf("rm: %v", err)
	}
	pointGlobAtTempfile(t, true)

	if err := installSRIOVManifests(src, dst); err != nil {
		t.Fatalf("missing auto-deploy dir should be a no-op, got: %v", err)
	}
}
