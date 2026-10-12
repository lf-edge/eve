// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package cgrouptest builds fake cgroup trees for tests of code that uses
// utils/cgroup. It is for tests only: nothing outside a _test.go file may
// import it.
package cgrouptest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup"
)

// FakeTree points cgroup.Root at a temporary directory holding
// files[path] = content, paths relative to the root (e.g.
// "eve/memory.max"), and restores cgroup.Root when the test ends. It
// returns the root.
func FakeTree(tb testing.TB, files map[string]string) string {
	tb.Helper()
	root := tb.TempDir()
	orig := cgroup.Root
	cgroup.Root = root
	tb.Cleanup(func() { cgroup.Root = orig })
	for p, content := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			tb.Fatal(err)
		}
	}
	return root
}
