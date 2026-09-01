// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheckBlockedDirs is a regression test for the edgeview cat/cp/tar
// directory-denylist bypass (CWE-22). Path traversal and the /hostfs host-mirror
// alias must not reach a blocked directory, while legitimate paths still pass.
// Inputs are absolute so the result is independent of the test's working
// directory (checkBlockedDirs resolves relative paths against the CWD, matching
// how the caller's os.Stat/read resolve them).
func TestCheckBlockedDirs(t *testing.T) {
	cases := []struct {
		path    string
		allowed bool
	}{
		// Legitimate paths are allowed.
		{"/persist/status/uuid", true},
		{"/config/device.cert.pem", true},
		{"/run/eve.id", true},
		{"/persist", true},
		{"/persist/vault-backup", true}, // sibling, not inside the blocked dir

		// Blocked directories (direct).
		{"/persist/vault", false},
		{"/persist/vault/protector/key", false},
		{"/persist/clear/x", false},
		{"/run/domainmgr/cloudinit/x", false},
		{"/run/.kube/k3s/x", false},

		// Traversal must not slip past the check.
		{"/persist/status/../vault/protector.key", false},
		{"/a/b/../../persist/vault", false},
		{"/persist/vault/../vault/key", false},

		// The /hostfs host-mirror alias must not reach blocked dirs.
		{"/hostfs/persist/vault/protector/key", false},
		{"/hostfs/run/.kube/k3s", false},
		{"/hostfs/hostfs/persist/vault", false},        // nested alias
		{"/hostfs/persist/status/../vault/key", false}, // alias + traversal
		{"/hostfs/etc/passwd", true},                   // non-secret via mirror, allowed
	}
	for _, c := range cases {
		if got := checkBlockedDirs(c.path); got != c.allowed {
			t.Errorf("checkBlockedDirs(%q) = %v, want %v", c.path, got, c.allowed)
		}
	}
}

// TestCheckBlockedDirsSymlink verifies that a symlink pointing into a blocked
// directory is caught (the lexical path alone would not reveal it). It points
// tarBlockDirs at a temp directory so the resolved paths actually exist on the
// test host. The temp root is symlink-resolved up front so the blocked entry is
// itself free of symlinks and matches the resolved targets.
func TestCheckBlockedDirsSymlink(t *testing.T) {
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(tmp, "vault")
	if err := os.MkdirAll(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(blocked, "key")
	if err := os.WriteFile(secret, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(tmp, "file-link") // -> blocked/key
	dirLink := filepath.Join(tmp, "dir-link")   // -> blocked
	if err := os.Symlink(secret, fileLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(blocked, dirLink); err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(tmp, "ok.txt")
	if err := os.WriteFile(allowed, []byte("y"), 0600); err != nil {
		t.Fatal(err)
	}

	old := tarBlockDirs
	tarBlockDirs = []string{blocked}
	defer func() { tarBlockDirs = old }()

	cases := []struct {
		path    string
		allowed bool
	}{
		{blocked, false},  // direct
		{secret, false},   // file inside blocked dir
		{fileLink, false}, // symlink to a file inside blocked dir
		{dirLink, false},  // symlink to the blocked dir itself
		{allowed, true},   // unrelated file
		{tmp, true},       // parent of the blocked dir
	}
	for _, c := range cases {
		if got := checkBlockedDirs(c.path); got != c.allowed {
			t.Errorf("checkBlockedDirs(%q) = %v, want %v", c.path, got, c.allowed)
		}
	}
}
