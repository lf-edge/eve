// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// mkFile creates a file whose mtime is `age` before now, so tests can control
// eviction order deterministically.
func mkFile(t *testing.T, dir, name string, age time.Duration) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(name), 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	mt := time.Now().Add(-age)
	if err := os.Chtimes(p, mt, mt); err != nil {
		t.Fatalf("chtimes %s: %v", name, err)
	}
	return p
}

func remaining(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// pruneToNewest keeps the n newest files matching the suffix and removes the
// rest (oldest-first), leaving files of other kinds untouched.
func TestPruneToNewestKeepsNewestOfKind(t *testing.T) {
	dir := t.TempDir()
	const suf = ".guestmem.elf.zst"
	mkFile(t, dir, "d.20260101-000001"+suf, 5*time.Hour) // oldest
	mkFile(t, dir, "d.20260101-000002"+suf, 4*time.Hour)
	mkFile(t, dir, "d.20260101-000003"+suf, 3*time.Hour)
	mkFile(t, dir, "d.20260101-000004"+suf, 2*time.Hour)
	mkFile(t, dir, "d.20260101-000005"+suf, 1*time.Hour) // newest
	mkFile(t, dir, "d.20260101-000006.qemu-core.zst", 30*time.Minute)
	mkFile(t, dir, "notes.txt", 10*time.Hour)

	if err := pruneToNewest(dir, suf, 2); err != nil {
		t.Fatalf("pruneToNewest: %v", err)
	}

	got := remaining(t, dir)
	want := []string{
		"d.20260101-000004" + suf,
		"d.20260101-000005" + suf,
		"d.20260101-000006.qemu-core.zst", // other kind untouched
		"notes.txt",                       // non-dump untouched
	}
	if len(got) != len(want) {
		t.Fatalf("remaining = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("remaining = %v, want %v", got, want)
		}
	}
}

// keep >= count is a no-op; keep 0 removes all of the kind.
func TestPruneToNewestEdgeCases(t *testing.T) {
	const suf = ".qemu-core.zst"

	dir := t.TempDir()
	mkFile(t, dir, "d.1"+suf, 2*time.Hour)
	mkFile(t, dir, "d.2"+suf, 1*time.Hour)
	if err := pruneToNewest(dir, suf, 5); err != nil {
		t.Fatalf("pruneToNewest keep>count: %v", err)
	}
	if got := remaining(t, dir); len(got) != 2 {
		t.Fatalf("keep>count removed files: %v", got)
	}

	dir2 := t.TempDir()
	mkFile(t, dir2, "d.1"+suf, 2*time.Hour)
	mkFile(t, dir2, "d.2"+suf, 1*time.Hour)
	if err := pruneToNewest(dir2, suf, 0); err != nil {
		t.Fatalf("pruneToNewest keep 0: %v", err)
	}
	if got := remaining(t, dir2); len(got) != 0 {
		t.Fatalf("keep 0 left files: %v", got)
	}
}

// A missing directory is not an error (nothing to prune yet).
func TestPruneToNewestMissingDir(t *testing.T) {
	if err := pruneToNewest(filepath.Join(t.TempDir(), "nope"), ".zst", 3); err != nil {
		t.Fatalf("pruneToNewest on missing dir: %v", err)
	}
}
