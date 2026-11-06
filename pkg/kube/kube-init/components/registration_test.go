// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	testRegistrationV1 = "apiVersion: v1\nkind: ConfigMap\ndata:\n  v: \"1\"\n"
	testRegistrationV2 = "apiVersion: v1\nkind: ConfigMap\ndata:\n  v: \"2\"\n"
)

// registrationTestPaths returns a source path under a fake /persist and
// a staged path under a fake k3s server-manifests dir; neither exists.
func registrationTestPaths(t *testing.T) (src, dst string) {
	t.Helper()
	root := t.TempDir()
	return filepath.Join(root, "persist", registrationYamlFileName),
		filepath.Join(root, "manifests", appliedRegistrationYamlFileName)
}

func writeRegistrationSource(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func expectStagedRegistration(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read staged manifest: %v", err)
	}
	if string(got) != want {
		t.Fatalf("staged manifest = %q, want %q", got, want)
	}
}

func TestRegistrationApplyIfReady_NoSource(t *testing.T) {
	src, dst := registrationTestPaths(t)
	if err := registrationApplyIfReady(false, src, dst); err != nil {
		t.Fatalf("registrationApplyIfReady: %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("nothing should be staged without a source, stat err = %v", err)
	}
}

func TestRegistrationApplyIfReady_StagesNewManifest(t *testing.T) {
	src, dst := registrationTestPaths(t)
	writeRegistrationSource(t, src, testRegistrationV1)
	if err := registrationApplyIfReady(false, src, dst); err != nil {
		t.Fatalf("registrationApplyIfReady: %v", err)
	}
	expectStagedRegistration(t, dst, testRegistrationV1)
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("staged manifest mode = %o, want 600", perm)
	}
}

// A replaced source manifest must be re-staged even though a staged
// copy already exists.
func TestRegistrationApplyIfReady_ContentChange_Restages(t *testing.T) {
	src, dst := registrationTestPaths(t)
	writeRegistrationSource(t, src, testRegistrationV1)
	if err := registrationApplyIfReady(false, src, dst); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	writeRegistrationSource(t, src, testRegistrationV2)
	if err := registrationApplyIfReady(false, src, dst); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	expectStagedRegistration(t, dst, testRegistrationV2)
}

func TestRegistrationApplyIfReady_Unchanged_NoRewrite(t *testing.T) {
	src, dst := registrationTestPaths(t)
	writeRegistrationSource(t, src, testRegistrationV1)
	if err := registrationApplyIfReady(false, src, dst); err != nil {
		t.Fatalf("first apply: %v", err)
	}
	before, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if err := registrationApplyIfReady(false, src, dst); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	after, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("unchanged manifest was rewritten")
	}
}
