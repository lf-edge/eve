// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stageShared points the shared and local binary paths at a temp tree.
func stageShared(t *testing.T) (localBin, sharedBin string) {
	t.Helper()
	root := t.TempDir()
	origLocal, origShared, origPoll := K3sBinaryPath, SharedBinaryPath, sharedPollInterval
	K3sBinaryPath = filepath.Join(root, "var", "k3s", "bin", "k3s")
	SharedBinaryPath = filepath.Join(root, "persist", "k3s-shared", "k3s")
	sharedPollInterval = time.Millisecond
	t.Cleanup(func() {
		K3sBinaryPath, SharedBinaryPath, sharedPollInterval = origLocal, origShared, origPoll
	})
	return K3sBinaryPath, SharedBinaryPath
}

func writeBin(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestPublishSharedBinary(t *testing.T) {
	local, shared := stageShared(t)
	writeBin(t, local, "k3s-v1")

	if err := PublishSharedBinary(); err != nil {
		t.Fatalf("PublishSharedBinary: %v", err)
	}
	got, err := os.ReadFile(shared)
	if err != nil {
		t.Fatalf("read published: %v", err)
	}
	if string(got) != "k3s-v1" {
		t.Errorf("published %q, want %q", got, "k3s-v1")
	}
	// The witness execs this, so it has to be executable.
	info, err := os.Stat(shared)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0111 == 0 {
		t.Errorf("published binary is not executable: %v", info.Mode())
	}

	// A different-sized binary replaces the published copy, which is
	// how a k3s version change propagates to the witness.
	writeBin(t, local, "k3s-version-two")
	if err := PublishSharedBinary(); err != nil {
		t.Fatalf("republish: %v", err)
	}
	if got, _ := os.ReadFile(shared); string(got) != "k3s-version-two" {
		t.Errorf("republished %q, want the new binary", got)
	}
}

// TestPublishHardLinksWhenPossible: on ext4 the kube role's /var/lib is
// a bind of /persist/vault/kube, the same filesystem as the shared
// path, so publishing costs no extra space. A temp dir is one
// filesystem, which is the case under test here.
func TestPublishHardLinksWhenPossible(t *testing.T) {
	local, shared := stageShared(t)
	writeBin(t, local, "k3s-v1")
	if err := PublishSharedBinary(); err != nil {
		t.Fatalf("PublishSharedBinary: %v", err)
	}
	li, err := os.Stat(local)
	if err != nil {
		t.Fatalf("stat local: %v", err)
	}
	si, err := os.Stat(shared)
	if err != nil {
		t.Fatalf("stat shared: %v", err)
	}
	if !os.SameFile(li, si) {
		t.Error("published copy is not the same inode; a link was possible here")
	}
}

// TestPublishSurvivesAnUpdateRename: update installs a new k3s through a
// rename, which replaces the directory entry. The published link must
// keep resolving, to the old binary, until the next publish replaces it.
func TestPublishSurvivesAnUpdateRename(t *testing.T) {
	local, shared := stageShared(t)
	writeBin(t, local, "k3s-v1")
	if err := PublishSharedBinary(); err != nil {
		t.Fatalf("publish: %v", err)
	}

	staged := local + ".new"
	writeBin(t, staged, "k3s-version-two")
	if err := os.Rename(staged, local); err != nil {
		t.Fatalf("simulate update rename: %v", err)
	}

	if got, err := os.ReadFile(shared); err != nil {
		t.Fatalf("published binary unreadable after an update: %v", err)
	} else if string(got) != "k3s-v1" {
		t.Errorf("published binary = %q, want the pre-update one", got)
	}
	if err := PublishSharedBinary(); err != nil {
		t.Fatalf("republish: %v", err)
	}
	if got, _ := os.ReadFile(shared); string(got) != "k3s-version-two" {
		t.Errorf("republish left %q, want the new binary", got)
	}
}

// TestPublishLeavesNoTempFile: a leftover .tmp would be a partially
// copied binary sitting next to the real one.
func TestPublishLeavesNoTempFile(t *testing.T) {
	local, shared := stageShared(t)
	writeBin(t, local, "k3s-v1")
	if err := PublishSharedBinary(); err != nil {
		t.Fatalf("PublishSharedBinary: %v", err)
	}
	if _, err := os.Stat(shared + ".tmp"); err == nil {
		t.Error("temp file left behind")
	}
}

func TestWaitSharedBinaryLinksWhenPublished(t *testing.T) {
	local, shared := stageShared(t)
	writeBin(t, shared, "k3s-v1")

	if err := WaitSharedBinary(context.Background()); err != nil {
		t.Fatalf("WaitSharedBinary: %v", err)
	}
	// EnsureInstalled stats K3sBinaryPath next, so the link has to
	// resolve to the published binary.
	got, err := os.ReadFile(local)
	if err != nil {
		t.Fatalf("read via link: %v", err)
	}
	if string(got) != "k3s-v1" {
		t.Errorf("link resolves to %q, want the published binary", got)
	}
}

// TestWaitSharedBinaryBlocksUntilPublished covers the first-boot order:
// the witness starts before the kube container has downloaded k3s.
func TestWaitSharedBinaryBlocksUntilPublished(t *testing.T) {
	_, shared := stageShared(t)

	done := make(chan error, 1)
	go func() { done <- WaitSharedBinary(context.Background()) }()

	select {
	case err := <-done:
		t.Fatalf("returned before the binary was published: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	writeBin(t, shared, "k3s-v1")
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitSharedBinary: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not notice the binary being published")
	}
}

func TestWaitSharedBinaryHonoursContext(t *testing.T) {
	stageShared(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := WaitSharedBinary(ctx); err == nil {
		t.Error("expected an error when the context expires")
	}
}
