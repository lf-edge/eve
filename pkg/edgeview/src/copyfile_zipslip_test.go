// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"
)

type tarEntry struct {
	hdr  tar.Header
	data []byte
}

func writeTestTar(t *testing.T, path string, entries []tarEntry) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	for _, e := range entries {
		h := e.hdr
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestExtractTarContained is a regression test for the edgeview client-side untar
// Zip-Slip (CWE-22): a device-supplied archive must not write outside the
// destination directory via ".." members or a symlink a later member is written
// through, while a benign archive still extracts.
func TestExtractTarContained(t *testing.T) {
	// Benign archive extracts.
	t.Run("benign", func(t *testing.T) {
		dest := t.TempDir()
		tarPath := filepath.Join(t.TempDir(), "ok.tar")
		writeTestTar(t, tarPath, []tarEntry{
			{hdr: tar.Header{Name: "newlog", Typeflag: tar.TypeDir, Mode: 0755}},
			{hdr: tar.Header{Name: "newlog/dev.log.gz", Typeflag: tar.TypeReg, Mode: 0644}, data: []byte("hello")},
		})
		if err := extractTarContained(tarPath, dest); err != nil {
			t.Fatalf("benign extract failed: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(dest, "newlog", "dev.log.gz"))
		if err != nil || string(got) != "hello" {
			t.Fatalf("benign member not extracted: %v (%q)", err, got)
		}
	})

	// A ".." member is rejected and nothing is written outside dest.
	t.Run("traversal", func(t *testing.T) {
		dest := t.TempDir()
		tarPath := filepath.Join(t.TempDir(), "trav.tar")
		writeTestTar(t, tarPath, []tarEntry{
			{hdr: tar.Header{Name: "../evil.txt", Typeflag: tar.TypeReg, Mode: 0644}, data: []byte("pwned")},
		})
		if err := extractTarContained(tarPath, dest); err == nil {
			t.Fatal("expected error for traversal member, got nil")
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "evil.txt")); err == nil {
			t.Fatal("traversal member escaped the destination")
		}
	})

	// A symlink member pointing outside is skipped, so a later member written
	// "through" it stays contained and does not reach the outside target.
	t.Run("symlink-escape", func(t *testing.T) {
		dest := t.TempDir()
		outside := t.TempDir()
		tarPath := filepath.Join(t.TempDir(), "link.tar")
		writeTestTar(t, tarPath, []tarEntry{
			{hdr: tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: outside, Mode: 0777}},
			{hdr: tar.Header{Name: "link/pwned.txt", Typeflag: tar.TypeReg, Mode: 0644}, data: []byte("pwned")},
		})
		// Skipping the symlink and writing a contained "link" dir is fine; the
		// escape (writing into the outside target) must not happen.
		_ = extractTarContained(tarPath, dest)
		if _, err := os.Stat(filepath.Join(outside, "pwned.txt")); err == nil {
			t.Fatal("symlink member allowed a write outside the destination")
		}
	})
}
