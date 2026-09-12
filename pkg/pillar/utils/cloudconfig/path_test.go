// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cloudconfig_test

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/utils/cloudconfig"
)

// How a requested path is turned into a destination: normalization, relative
// paths, parent creation, and the paths that are refused outright. Symlink
// resolution is in symlink_test.go.

// TestWriteFilePathNormalization asserts a requested path is normalized before
// it is split into a parent and a file name. path.Base and path.Dir disagree
// about a trailing separator, so without normalizing, "/foo/" would create a
// directory foo and write foo/foo inside it, and "/foo/." would be rejected --
// where both name the file "/foo".
func TestWriteFilePathNormalization(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ requested, want string }{
		{requested: "/foo", want: "foo"},
		{requested: "/foo/", want: "foo"},
		{requested: "/foo/.", want: "foo"},
		{requested: "//a//b", want: "a/b"},
		{requested: "/a/./b", want: "a/b"},
		{requested: "/a/c/../b", want: "a/b"},
	} {
		t.Run(tc.requested, func(t *testing.T) {
			t.Parallel()

			rootPath := filepath.Join(t.TempDir(), "rootfs")
			if err := os.MkdirAll(rootPath, 0755); err != nil {
				t.Fatalf("failed to create rootfs: %v", err)
			}
			if err := cloudconfig.WriteFile(testLog(), cloudconfig.WritableFile{
				Path:        tc.requested,
				Content:     "normalized",
				Permissions: "0644",
			}, rootPath); err != nil {
				t.Fatalf("write of %q failed: %v", tc.requested, err)
			}

			want := filepath.Join(rootPath, tc.want)
			content, err := os.ReadFile(want)
			if err != nil {
				t.Fatalf("expected %q to be written to %s: %v", tc.requested, want, err)
			}
			if string(content) != "normalized" {
				t.Errorf("content of %s = %q, want %q", want, content, "normalized")
			}
		})
	}
}

// TestWriteFileRelativePath asserts a path without a leading separator is
// still resolved against the rootfs rather than the writing process's cwd.
// The controller is not required to send an absolute path.
func TestWriteFileRelativePath(t *testing.T) {
	t.Parallel()

	for _, requested := range []string{"etc/foo", "foo"} {
		t.Run(requested, func(t *testing.T) {
			t.Parallel()

			rootPath := newRoot(t)
			if err := write(rootPath, requested, "relative", "0644"); err != nil {
				t.Fatalf("write of %q failed: %v", requested, err)
			}
			want := filepath.Join(rootPath, requested)
			if content, err := os.ReadFile(want); err != nil {
				t.Fatalf("expected the file at %s: %v", want, err)
			} else if string(content) != "relative" {
				t.Errorf("content = %q, want %q", content, "relative")
			}
		})
	}
}

// TestWriteFileRejectsClimbOutOfRoot asserts a path whose ".." climbs above
// the root is rejected, including one that climbs out and re-enters through a
// component that happens to match the root's own name. Deciding containment by
// joining onto rootPath and comparing strings accepts that second form,
// because rootPath's trailing component absorbs the "..", and then writes it
// somewhere other than where the check looked.
func TestWriteFileRejectsClimbOutOfRoot(t *testing.T) {
	t.Parallel()

	for _, requested := range []string{
		"../../etc/passwd",
		"/../rootfs/foo",
		"/a/../../escape",
		"/",
		"/..",
	} {
		t.Run(requested, func(t *testing.T) {
			t.Parallel()

			baseDir := t.TempDir()
			// Named "rootfs" so "/../rootfs/foo" can re-enter through it.
			rootPath := filepath.Join(baseDir, "rootfs")
			if err := os.MkdirAll(rootPath, 0755); err != nil {
				t.Fatalf("failed to create rootfs: %v", err)
			}

			err := cloudconfig.WriteFile(testLog(), cloudconfig.WritableFile{
				Path:        requested,
				Content:     "escaped",
				Permissions: "0644",
			}, rootPath)
			if err == nil {
				t.Errorf("expected %q to be rejected", requested)
			}
			// The name this entry would have written, had it been accepted.
			if got := findFile(t, baseDir, path.Base(requested)); len(got) != 0 {
				t.Errorf("%q was written to %v", requested, got)
			}
		})
	}
}

// TestWriteFileCreatesMissingParents asserts every missing directory on the
// way to the file is created, not just the immediate parent.
func TestWriteFileCreatesMissingParents(t *testing.T) {
	t.Parallel()

	rootPath := newRoot(t)
	if err := write(rootPath, "/deep/ly/nested/secret", "s3cret", "0640"); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(rootPath, "deep", "ly", "nested", "secret"))
	if err != nil {
		t.Fatalf("expected the file: %v", err)
	}
	if string(content) != "s3cret" {
		t.Errorf("content = %q, want %q", content, "s3cret")
	}
}
