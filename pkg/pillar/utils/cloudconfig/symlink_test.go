// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cloudconfig_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/utils/cloudconfig"
)

// Symlink resolution. WriteFile resolves a write_files path as though rootPath
// were the filesystem root (openat2 with RESOLVE_IN_ROOT), so these cover both
// halves of that contract: a symlink can never carry the write out of
// rootPath, and one that stays inside is still followed.
//
// For a container application rootPath is the rootfs of the application's own
// container image, so every symlink here is content an image author chose.

// TestWriteFileSymlinkEscapeIsContained asserts that a symlinked directory
// component pointing out of rootPath cannot carry the write with it. Such a
// path is not rejected: the target is re-rooted at rootPath, so the write
// lands inside the application's own filesystem, which is what the path means
// from the guest's point of view.
//
// Both shapes of escape are covered, because they fail differently: an
// absolute target would otherwise be resolved against the writing process's
// root, while a relative one climbs out with "..".
func TestWriteFileSymlinkEscapeIsContained(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		// target of the "home/a" symlink planted inside the rootfs
		linkTarget func(rootPath, outside string) string
	}{
		{
			name:       "absolute symlink",
			linkTarget: func(_, outside string) string { return outside },
		},
		{
			name: "relative symlink",
			linkTarget: func(rootPath, outside string) string {
				rel, err := filepath.Rel(filepath.Join(rootPath, "home"), outside)
				if err != nil {
					t.Fatalf("failed to build relative link target: %v", err)
				}
				return rel
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			baseDir := t.TempDir()
			rootPath := filepath.Join(baseDir, "rootfs")
			outside := filepath.Join(baseDir, "outside")
			for _, dir := range []string{filepath.Join(rootPath, "home"), outside} {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatalf("failed to create %s: %v", dir, err)
				}
			}
			link := filepath.Join(rootPath, "home", "a")
			target := tc.linkTarget(rootPath, outside)
			if err := os.Symlink(target, link); err != nil {
				t.Fatalf("failed to create symlink: %v", err)
			}

			err := cloudconfig.WriteFile(testLog(), cloudconfig.WritableFile{
				Path:        "/home/a/b",
				Content:     "contained",
				Permissions: "0644",
			}, rootPath)
			if err != nil {
				t.Fatalf("write through a symlink out of rootPath failed: %v", err)
			}

			// The assertion that matters.
			if len(findFile(t, outside, "b")) != 0 {
				t.Errorf("containment escape: write to /home/a/b landed outside "+
					"rootPath (link %q -> %q)", link, target)
			}
			// Landing anywhere inside the root is containment; landing at the
			// re-rooted target with the right bytes is the intended behaviour.
			want := filepath.Join(rootPath, strings.TrimPrefix(outside, "/"), "b")
			if !filepath.IsAbs(target) {
				want = filepath.Join(rootPath, "outside", "b")
			}
			content, err := os.ReadFile(want)
			if err != nil {
				t.Fatalf("expected the write at %s: %v (files inside root: %v)",
					want, err, findFile(t, rootPath, "b"))
			}
			if string(content) != "contained" {
				t.Errorf("content of %s = %q, want %q", want, content, "contained")
			}
		})
	}
}

// TestWriteFileSymlinkedDirInsideRoot asserts a symlinked directory component
// that stays inside rootPath is still followed. Distro images use such links
// routinely (/etc -> usr/etc, /lib -> usr/lib), so refusing them would break
// legitimate write_files targets.
func TestWriteFileSymlinkedDirInsideRoot(t *testing.T) {
	t.Parallel()

	rootPath := filepath.Join(t.TempDir(), "rootfs")
	targetDir := filepath.Join(rootPath, "usr", "etc")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatalf("failed to create %s: %v", targetDir, err)
	}
	if err := os.Symlink("usr/etc", filepath.Join(rootPath, "etc")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	if err := cloudconfig.WriteFile(testLog(), cloudconfig.WritableFile{
		Path:        "/etc/contained.txt",
		Content:     "contained",
		Permissions: "0644",
	}, rootPath); err != nil {
		t.Fatalf("write through a symlink contained in rootPath was rejected: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(targetDir, "contained.txt"))
	if err != nil {
		t.Fatalf("expected the file under %s: %v", targetDir, err)
	}
	if string(content) != "contained" {
		t.Errorf("content = %q, want %q", content, "contained")
	}
}

// TestWriteFileAbsoluteSymlinkIsReRooted covers the shape every Debian-based
// image ships: /var/lock is an absolute symlink to /run/lock. The write
// belongs in the container's own /run/lock, so the target must be resolved
// against rootPath and not against the root of the process doing the write.
func TestWriteFileAbsoluteSymlinkIsReRooted(t *testing.T) {
	t.Parallel()

	rootPath := filepath.Join(t.TempDir(), "rootfs")
	for _, dir := range []string{
		filepath.Join(rootPath, "run", "lock"),
		filepath.Join(rootPath, "var"),
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create %s: %v", dir, err)
		}
	}
	if err := os.Symlink("/run/lock", filepath.Join(rootPath, "var", "lock")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	if err := cloudconfig.WriteFile(testLog(), cloudconfig.WritableFile{
		Path:        "/var/lock/app.lock",
		Content:     "locked",
		Permissions: "0644",
	}, rootPath); err != nil {
		t.Fatalf("write through /var/lock was rejected: %v", err)
	}

	written := filepath.Join(rootPath, "run", "lock", "app.lock")
	if content, err := os.ReadFile(written); err != nil {
		t.Fatalf("expected the file at %s: %v", written, err)
	} else if string(content) != "locked" {
		t.Errorf("content = %q, want %q", content, "locked")
	}
}

// TestWriteFileCreatesDirThroughDanglingSymlink covers the same shape when the
// symlink's target does not exist in the image yet. The directory cannot be
// created under the symlink's own name -- mkdir would fail on the link -- so
// its target has to be created instead. Before this was handled, such a path
// failed app activation with a bare "file exists".
func TestWriteFileCreatesDirThroughDanglingSymlink(t *testing.T) {
	t.Parallel()

	rootPath := filepath.Join(t.TempDir(), "rootfs")
	if err := os.MkdirAll(filepath.Join(rootPath, "var"), 0755); err != nil {
		t.Fatalf("failed to create rootfs: %v", err)
	}
	// Neither /run nor /run/lock exists inside the rootfs.
	if err := os.Symlink("/run/lock", filepath.Join(rootPath, "var", "lock")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	if err := cloudconfig.WriteFile(testLog(), cloudconfig.WritableFile{
		Path:        "/var/lock/app.lock",
		Content:     "locked",
		Permissions: "0644",
	}, rootPath); err != nil {
		t.Fatalf("write through a dangling /var/lock was rejected: %v", err)
	}

	written := filepath.Join(rootPath, "run", "lock", "app.lock")
	content, err := os.ReadFile(written)
	if err != nil {
		t.Fatalf("expected the file at %s: %v", written, err)
	}
	if string(content) != "locked" {
		t.Errorf("content of %s = %q, want %q", written, content, "locked")
	}
}

// TestWriteFileDanglingSymlinkWithDotDot covers a dangling symlink whose target
// is relative and climbs with "..", reached through a symlinked parent. The
// target has to be resolved against where the link actually points, not
// against the link's own lexical path: cleaning "/alias/../missing" would name
// /missing, which is the wrong directory and is not where the kernel then
// looks.
func TestWriteFileDanglingSymlinkWithDotDot(t *testing.T) {
	t.Parallel()

	rootPath := filepath.Join(t.TempDir(), "rootfs")
	if err := os.MkdirAll(filepath.Join(rootPath, "real", "deep"), 0755); err != nil {
		t.Fatalf("failed to create rootfs: %v", err)
	}
	if err := os.Symlink("real/deep", filepath.Join(rootPath, "alias")); err != nil {
		t.Fatalf("failed to create alias symlink: %v", err)
	}
	if err := os.Symlink("../missing",
		filepath.Join(rootPath, "real", "deep", "link")); err != nil {
		t.Fatalf("failed to create dangling symlink: %v", err)
	}

	if err := cloudconfig.WriteFile(testLog(), cloudconfig.WritableFile{
		Path:        "/alias/link/file",
		Content:     "resolved",
		Permissions: "0644",
	}, rootPath); err != nil {
		t.Fatalf("write through a dangling relative symlink was rejected: %v", err)
	}

	written := filepath.Join(rootPath, "real", "missing", "file")
	if content, err := os.ReadFile(written); err != nil {
		t.Fatalf("expected the file at %s: %v", written, err)
	} else if string(content) != "resolved" {
		t.Errorf("content = %q, want %q", content, "resolved")
	}
	// The lexically-cleaned target, which must not have been created.
	assertAbsent(t, filepath.Join(rootPath, "missing"),
		"created the lexical join of the link's path and target instead of "+
			"resolving the link first")
}

// TestWriteFileDotDotResolvedAfterSymlink asserts ".." is applied to where a
// preceding symlink actually points, not to the link's own lexical parent.
// With /alias a symlink to real/deep, "/alias/../file" names /real/file.
// Collapsing the ".." before resolving the symlink would name /file instead --
// still inside the root, but not the directory the path denotes.
func TestWriteFileDotDotResolvedAfterSymlink(t *testing.T) {
	t.Parallel()

	rootPath := filepath.Join(t.TempDir(), "rootfs")
	if err := os.MkdirAll(filepath.Join(rootPath, "real", "deep"), 0755); err != nil {
		t.Fatalf("failed to create rootfs: %v", err)
	}
	if err := os.Symlink("real/deep", filepath.Join(rootPath, "alias")); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	if err := cloudconfig.WriteFile(testLog(), cloudconfig.WritableFile{
		Path:        "/alias/../file",
		Content:     "resolved",
		Permissions: "0644",
	}, rootPath); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	want := filepath.Join(rootPath, "real", "file")
	if content, err := os.ReadFile(want); err != nil {
		t.Fatalf("expected the file at %s: %v", want, err)
	} else if string(content) != "resolved" {
		t.Errorf("content = %q, want %q", content, "resolved")
	}
	assertAbsent(t, filepath.Join(rootPath, "file"),
		"the \"..\" was collapsed before the symlink was resolved")
}

// TestWriteFileSymlinkDepthCap asserts the bound on following symlinks whose
// target directory does not exist yet. That recursion is the one place
// resolution happens outside the kernel, so it needs its own limit: eight
// links are followed, a ninth is refused.
func TestWriteFileSymlinkDepthCap(t *testing.T) {
	t.Parallel()

	// chain builds l0 -> /l1/sub, l1 -> /l2/sub, ... with the last target
	// missing, so writing through l0 must follow every link in turn.
	chain := func(t *testing.T, links int) string {
		rootPath := newRoot(t)
		for i := 0; i < links; i++ {
			if err := os.Symlink(fmt.Sprintf("/l%d/sub", i+1),
				filepath.Join(rootPath, fmt.Sprintf("l%d", i))); err != nil {
				t.Fatal(err)
			}
		}
		return rootPath
	}

	t.Run("at the limit", func(t *testing.T) {
		t.Parallel()
		rootPath := chain(t, 8)
		if err := write(rootPath, "/l0/f", "deep", "0644"); err != nil {
			t.Fatalf("a chain of 8 links was refused: %v", err)
		}
		if got := findFile(t, rootPath, "f"); len(got) != 1 {
			t.Errorf("expected exactly one file named f, got %v", got)
		}
	})

	t.Run("past the limit", func(t *testing.T) {
		t.Parallel()
		rootPath := chain(t, 9)
		err := write(rootPath, "/l0/f", "deep", "0644")
		if err == nil {
			t.Fatal("a chain of 9 links was followed")
		}
		if !strings.Contains(err.Error(), "too many symbolic links") {
			t.Errorf("error = %v, want one about too many symbolic links", err)
		}
	})
}
