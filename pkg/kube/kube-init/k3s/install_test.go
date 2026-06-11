// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// linkInode returns the inode number of a symlink (or any path) via
// Lstat. Two values being equal across two calls is strong evidence
// that the on-disk entry was not removed + recreated between them —
// much sturdier than the mtime check we used before (symlink mtime
// resolution is coarse on some filesystems).
func linkInode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("Lstat.Sys is not *syscall.Stat_t on this platform: %T", info.Sys())
	}
	return st.Ino
}

func TestEnsureSymlinkCreatesNew(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("x"), 0644); err != nil {
		t.Fatalf("seed src: %v", err)
	}
	if err := ensureSymlink(src, dst); err != nil {
		t.Fatalf("ensureSymlink: %v", err)
	}
	target, err := os.Readlink(dst)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != src {
		t.Errorf("target = %q, want %q", target, src)
	}
}

func TestEnsureSymlinkIdempotent(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("x"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := ensureSymlink(src, dst); err != nil {
		t.Fatalf("first ensureSymlink: %v", err)
	}
	ino1 := linkInode(t, dst)
	if err := ensureSymlink(src, dst); err != nil {
		t.Fatalf("second ensureSymlink: %v", err)
	}
	if ino2 := linkInode(t, dst); ino1 != ino2 {
		t.Errorf("idempotent call recreated the symlink: inode %d -> %d", ino1, ino2)
	}
}

func TestEnsureSymlinkReplacesWrongTarget(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	wrongSrc := filepath.Join(dir, "wrong")
	dst := filepath.Join(dir, "dst")
	for _, p := range []string{src, wrongSrc} {
		if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	if err := os.Symlink(wrongSrc, dst); err != nil {
		t.Fatalf("pre-symlink: %v", err)
	}
	if err := ensureSymlink(src, dst); err != nil {
		t.Fatalf("ensureSymlink: %v", err)
	}
	target, err := os.Readlink(dst)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != src {
		t.Errorf("target = %q, want %q", target, src)
	}
}

func TestEnsureSymlinkReplacesRegularFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("x"), 0644); err != nil {
		t.Fatalf("seed src: %v", err)
	}
	if err := os.WriteFile(dst, []byte("stale"), 0644); err != nil {
		t.Fatalf("seed dst: %v", err)
	}
	if err := ensureSymlink(src, dst); err != nil {
		t.Fatalf("ensureSymlink: %v", err)
	}
	info, err := os.Lstat(dst)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("dst is not a symlink: mode=%v", info.Mode())
	}
}

func TestEnsureSymlinkCreatesParentDir(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "nested/dir/dst")
	if err := os.WriteFile(src, []byte("x"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := ensureSymlink(src, dst); err != nil {
		t.Fatalf("ensureSymlink: %v", err)
	}
	if _, err := os.Readlink(dst); err != nil {
		t.Errorf("readlink after parent-creation: %v", err)
	}
}

func TestSymlinkAllBinaries(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	for _, name := range []string{"k3s", "kubectl", "ctr"} {
		if err := os.WriteFile(filepath.Join(srcDir, name), []byte("bin"), 0755); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	if err := os.Mkdir(filepath.Join(srcDir, "subdir"), 0755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}

	if err := symlinkAllBinaries(srcDir, dstDir); err != nil {
		t.Fatalf("symlinkAllBinaries: %v", err)
	}
	for _, name := range []string{"k3s", "kubectl", "ctr"} {
		target, err := os.Readlink(filepath.Join(dstDir, name))
		if err != nil {
			t.Errorf("readlink %s: %v", name, err)
			continue
		}
		if target != filepath.Join(srcDir, name) {
			t.Errorf("link %s -> %s, want %s",
				name, target, filepath.Join(srcDir, name))
		}
	}
	if _, err := os.Lstat(filepath.Join(dstDir, "subdir")); !os.IsNotExist(err) {
		t.Errorf("directory was symlinked: stat err = %v", err)
	}
}

func TestSymlinkAllBinariesMissingSource(t *testing.T) {
	err := symlinkAllBinaries("/nonexistent/"+t.Name(), t.TempDir())
	if err == nil {
		t.Fatal("expected error for missing source, got nil")
	}
}

// TestSymlinkAllBinariesAuxFailureContinues seeds an aux (non-load-
// bearing) name whose dst-parent is read-only, so its symlink fails.
// The load-bearing entries must still get linked, and the function
// must return nil (auxiliary failures only warn).
func TestSymlinkAllBinariesAuxFailureContinues(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses dir-write perms")
	}
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// Make a read-only sub-dir inside dstDir, then point an aux file
	// (`aux1`) at it via a precreated stale symlink that's a directory
	// — easier: precreate `aux1` as a directory inside dstDir so the
	// "remove existing" branch in ensureSymlink hits EISDIR.
	if err := os.Mkdir(filepath.Join(dstDir, "aux1"), 0755); err != nil {
		t.Fatalf("seed aux1 dir: %v", err)
	}
	// Make that aux1 dir non-empty so os.Remove returns ENOTEMPTY.
	if err := os.WriteFile(filepath.Join(dstDir, "aux1", "blocker"),
		[]byte("x"), 0644); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}

	for _, name := range []string{"k3s", "aux1", "kubectl"} {
		if err := os.WriteFile(filepath.Join(srcDir, name), []byte("bin"), 0755); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	if err := symlinkAllBinaries(srcDir, dstDir); err != nil {
		t.Fatalf("symlinkAllBinaries: expected nil for aux failure, got %v", err)
	}
	for _, name := range []string{"k3s", "kubectl"} {
		if _, err := os.Readlink(filepath.Join(dstDir, name)); err != nil {
			t.Errorf("load-bearing %s should still be linked: %v", name, err)
		}
	}
}

// TestSymlinkAllBinariesLoadBearingFailureAborts forces a failure
// on a load-bearing name; the function must return a non-nil error.
func TestSymlinkAllBinariesLoadBearingFailureAborts(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses dir-write perms")
	}
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// Pre-seed dst/k3s as a non-empty directory so the remove fails.
	if err := os.Mkdir(filepath.Join(dstDir, "k3s"), 0755); err != nil {
		t.Fatalf("seed k3s dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dstDir, "k3s", "blocker"),
		[]byte("x"), 0644); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "k3s"), []byte("bin"), 0755); err != nil {
		t.Fatalf("seed src k3s: %v", err)
	}

	err := symlinkAllBinaries(srcDir, dstDir)
	if err == nil {
		t.Fatal("expected error for load-bearing failure, got nil")
	}
	if !strings.Contains(err.Error(), "k3s") {
		t.Errorf("error should mention which load-bearing name failed: %v", err)
	}
}

func TestLinkMultusAtSkipsWhenDataDirAbsent(t *testing.T) {
	parent := t.TempDir()
	dataBin := filepath.Join(parent, "not-yet-extracted")
	src := filepath.Join(parent, "multus")
	if err := os.WriteFile(src, []byte("x"), 0755); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := linkMultusAt(src, dataBin); err != nil {
		t.Errorf("expected silent no-op, got %v", err)
	}
	if _, err := os.Stat(dataBin); !os.IsNotExist(err) {
		t.Errorf("dataBinDir was created: stat err = %v", err)
	}
}

func TestLinkMultusAtSkipsAndPreservesStaleLinkWhenDataDirAbsent(t *testing.T) {
	// Specifically guards against the silent-failure-hunter finding:
	// the wrong-target removal must NOT fire when dataBinDir is
	// absent — otherwise we'd remove a stale link without recreating
	// it, leaving the system in a worse state than before.
	parent := t.TempDir()
	dataBin := filepath.Join(parent, "not-yet")
	src := filepath.Join(parent, "multus")
	if err := os.WriteFile(src, []byte("x"), 0755); err != nil {
		t.Fatalf("seed src: %v", err)
	}
	// linkMultusAt should see no dataBinDir and return nil before
	// touching anything.
	if err := linkMultusAt(src, dataBin); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLinkMultusAtCreatesNew(t *testing.T) {
	dataBin := t.TempDir()
	src := filepath.Join(t.TempDir(), "multus")
	if err := os.WriteFile(src, []byte("x"), 0755); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := linkMultusAt(src, dataBin); err != nil {
		t.Fatalf("linkMultusAt: %v", err)
	}
	target, err := os.Readlink(filepath.Join(dataBin, multusName))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != src {
		t.Errorf("target = %q, want %q", target, src)
	}
}

func TestLinkMultusAtIdempotent(t *testing.T) {
	dataBin := t.TempDir()
	src := filepath.Join(t.TempDir(), "multus")
	if err := os.WriteFile(src, []byte("x"), 0755); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := linkMultusAt(src, dataBin); err != nil {
		t.Fatalf("first call: %v", err)
	}
	dst := filepath.Join(dataBin, multusName)
	ino1 := linkInode(t, dst)
	if err := linkMultusAt(src, dataBin); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if ino2 := linkInode(t, dst); ino1 != ino2 {
		t.Errorf("idempotent call recreated the link: inode %d -> %d", ino1, ino2)
	}
}

func TestLinkMultusAtReplacesWrongTarget(t *testing.T) {
	dataBin := t.TempDir()
	src := filepath.Join(t.TempDir(), "multus")
	wrong := filepath.Join(t.TempDir(), "wrong")
	for _, p := range []string{src, wrong} {
		if err := os.WriteFile(p, []byte("x"), 0755); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	dst := filepath.Join(dataBin, multusName)
	if err := os.Symlink(wrong, dst); err != nil {
		t.Fatalf("pre-symlink: %v", err)
	}
	if err := linkMultusAt(src, dataBin); err != nil {
		t.Fatalf("linkMultusAt: %v", err)
	}
	target, err := os.Readlink(dst)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != src {
		t.Errorf("target = %q, want %q", target, src)
	}
}

func TestLinkMultusAtReplacesNonSymlink(t *testing.T) {
	// A regular file at dst must be replaced by a symlink — the
	// Lstat path in linkMultusAt is the only thing standing between
	// a stuck-with-regular-file dst and a confusing EEXIST symlink
	// error.
	dataBin := t.TempDir()
	src := filepath.Join(t.TempDir(), "multus")
	if err := os.WriteFile(src, []byte("x"), 0755); err != nil {
		t.Fatalf("seed: %v", err)
	}
	dst := filepath.Join(dataBin, multusName)
	if err := os.WriteFile(dst, []byte("stale-regular-file"), 0644); err != nil {
		t.Fatalf("seed stale: %v", err)
	}
	if err := linkMultusAt(src, dataBin); err != nil {
		t.Fatalf("linkMultusAt: %v", err)
	}
	info, err := os.Lstat(dst)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Errorf("dst is not a symlink after replace: mode=%v", info.Mode())
	}
}

func TestRebuildRuntimeSymlinksAtFirstBoot(t *testing.T) {
	binDir := t.TempDir()
	usrBin := t.TempDir()
	dataBin := filepath.Join(t.TempDir(), "not-yet-here")

	if err := os.WriteFile(filepath.Join(binDir, "k3s"), []byte("bin"), 0755); err != nil {
		t.Fatalf("seed binDir: %v", err)
	}

	origMulSrc := multusLinkSource
	multusLinkSource = filepath.Join(t.TempDir(), "multus")
	t.Cleanup(func() { multusLinkSource = origMulSrc })
	if err := os.WriteFile(multusLinkSource, []byte("x"), 0755); err != nil {
		t.Fatalf("seed multus src: %v", err)
	}

	if err := rebuildRuntimeSymlinksAt(binDir, usrBin, dataBin); err != nil {
		t.Fatalf("rebuildRuntimeSymlinksAt: %v", err)
	}
	target, err := os.Readlink(filepath.Join(usrBin, "k3s"))
	if err != nil {
		t.Fatalf("readlink /usr/bin/k3s: %v", err)
	}
	if target != filepath.Join(binDir, "k3s") {
		t.Errorf("/usr/bin/k3s -> %q, want %q", target, filepath.Join(binDir, "k3s"))
	}
	if _, err := os.Stat(dataBin); !os.IsNotExist(err) {
		t.Errorf("dataBin was created: stat err = %v", err)
	}
}

func TestRebuildRuntimeSymlinksAtPostExtract(t *testing.T) {
	binDir := t.TempDir()
	usrBin := t.TempDir()
	dataBin := t.TempDir()

	if err := os.WriteFile(filepath.Join(binDir, "k3s"), []byte("bin"), 0755); err != nil {
		t.Fatalf("seed binDir: %v", err)
	}
	for _, name := range []string{containerdShimName, runcName} {
		if err := os.WriteFile(filepath.Join(dataBin, name), []byte("bin"), 0755); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	origMulSrc := multusLinkSource
	multusLinkSource = filepath.Join(t.TempDir(), "multus")
	t.Cleanup(func() { multusLinkSource = origMulSrc })
	if err := os.WriteFile(multusLinkSource, []byte("x"), 0755); err != nil {
		t.Fatalf("seed multus src: %v", err)
	}

	if err := rebuildRuntimeSymlinksAt(binDir, usrBin, dataBin); err != nil {
		t.Fatalf("rebuildRuntimeSymlinksAt: %v", err)
	}
	for _, name := range []string{"k3s", containerdShimName, runcName} {
		if _, err := os.Readlink(filepath.Join(usrBin, name)); err != nil {
			t.Errorf("missing link for %s: %v", name, err)
		}
	}
	if _, err := os.Readlink(filepath.Join(dataBin, multusName)); err != nil {
		t.Errorf("multus link missing: %v", err)
	}
}

func TestGetInstalledVersionParsing(t *testing.T) {
	bin := makeStubK3sBinary(t, "k3s version v1.34.2+k3s1 (abc1234)\n", 0)

	orig := K3sBinaryPath
	K3sBinaryPath = bin
	t.Cleanup(func() { K3sBinaryPath = orig })

	got, err := GetInstalledVersion()
	if err != nil {
		t.Fatalf("GetInstalledVersion: %v", err)
	}
	if got != "v1.34.2+k3s1" {
		t.Errorf("version = %q, want %q", got, "v1.34.2+k3s1")
	}
}

func TestGetInstalledVersionUnparseable(t *testing.T) {
	bin := makeStubK3sBinary(t, "unexpected output\n", 0)

	orig := K3sBinaryPath
	K3sBinaryPath = bin
	t.Cleanup(func() { K3sBinaryPath = orig })

	_, err := GetInstalledVersion()
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
	if !strings.Contains(err.Error(), "could not parse") {
		t.Errorf("error not a parse error: %v", err)
	}
}

// TestGetInstalledVersionExecFails covers the path where the binary
// exists and is executable, but it exits non-zero. The wrapped error
// must surface the trimmed output for debuggability.
func TestGetInstalledVersionExecFails(t *testing.T) {
	bin := makeStubK3sBinary(t, "panic: corrupt binary\n", 17)

	orig := K3sBinaryPath
	K3sBinaryPath = bin
	t.Cleanup(func() { K3sBinaryPath = orig })

	_, err := GetInstalledVersion()
	if err == nil {
		t.Fatal("expected exec error, got nil")
	}
	if !strings.Contains(err.Error(), "panic: corrupt binary") {
		t.Errorf("error should surface stub stdout for debuggability: %v", err)
	}
}

func TestGetInstalledVersionMissingBinary(t *testing.T) {
	origBin := K3sBinaryPath
	origSym := K3sSymlink
	missing := filepath.Join(t.TempDir(), "no-such-k3s")
	K3sBinaryPath = missing
	K3sSymlink = missing
	t.Cleanup(func() {
		K3sBinaryPath = origBin
		K3sSymlink = origSym
	})
	_, err := GetInstalledVersion()
	if err == nil {
		t.Fatal("expected error when neither binary exists, got nil")
	}
}

// TestSelectK3sBinaryPrefersBinaryPath verifies the preference order
// is honoured: K3sBinaryPath wins when both exist. Important because
// a stale K3sSymlink during an in-place upgrade would shadow the
// freshly-unpacked binary if the order were reversed.
func TestSelectK3sBinaryPrefersBinaryPath(t *testing.T) {
	dir := t.TempDir()
	bp := filepath.Join(dir, "binary-path")
	sl := filepath.Join(dir, "symlink-path")
	for _, p := range []string{bp, sl} {
		if err := os.WriteFile(p, []byte("x"), 0755); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	origBin, origSym := K3sBinaryPath, K3sSymlink
	K3sBinaryPath, K3sSymlink = bp, sl
	t.Cleanup(func() {
		K3sBinaryPath, K3sSymlink = origBin, origSym
	})
	got, err := selectK3sBinary()
	if err != nil {
		t.Fatalf("selectK3sBinary: %v", err)
	}
	if got != bp {
		t.Errorf("preferred binary = %q, want %q (K3sBinaryPath)", got, bp)
	}
}

// makeStubK3sBinary writes a small shell script that prints body and
// exits with exitCode. Used to simulate `k3s --version` deterministically
// without invoking the real binary.
func makeStubK3sBinary(t *testing.T, body string, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "k3s")
	escaped := strings.ReplaceAll(body, "'", "'\\''")
	content := fmt.Sprintf("#!/bin/sh\nprintf %%s '%s'\n", escaped)
	if exitCode != 0 {
		content += fmt.Sprintf("exit %d\n", exitCode)
	}
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	return path
}
