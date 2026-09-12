// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cloudconfig_test

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// The write itself: what happens to whatever already occupies the destination,
// how a blocked path component is reported, how a permissions string is
// converted, and that no temporary file is left behind.

// TestWriteFileFinalComponent asserts what happens when the final component
// already exists. rename(2) replaces a symlink at its destination rather than
// following it, which is why only intermediate components need resolving; a
// directory cannot be replaced and must fail cleanly.
func TestWriteFileFinalComponent(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		// setup prepares "target" inside rootPath and returns the path whose
		// content must be left alone, if any.
		setup     func(t *testing.T, rootPath string) (untouched string)
		wantError bool
	}{
		{
			name: "regular file",
			setup: func(t *testing.T, rootPath string) string {
				if err := os.WriteFile(filepath.Join(rootPath, "target"),
					[]byte("stale and longer than the new content"), 0600); err != nil {
					t.Fatal(err)
				}
				return ""
			},
		},
		{
			name: "symlink to a file",
			setup: func(t *testing.T, rootPath string) string {
				pointee := filepath.Join(rootPath, "pointee")
				if err := os.WriteFile(pointee, []byte("pointee"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("pointee", filepath.Join(rootPath, "target")); err != nil {
					t.Fatal(err)
				}
				return pointee
			},
		},
		{
			name: "symlink to a directory",
			setup: func(t *testing.T, rootPath string) string {
				if err := os.MkdirAll(filepath.Join(rootPath, "pointee"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/pointee", filepath.Join(rootPath, "target")); err != nil {
					t.Fatal(err)
				}
				return ""
			},
		},
		{
			name: "dangling symlink",
			setup: func(t *testing.T, rootPath string) string {
				if err := os.Symlink("/nowhere", filepath.Join(rootPath, "target")); err != nil {
					t.Fatal(err)
				}
				return ""
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, rootPath string) string {
				if err := os.MkdirAll(filepath.Join(rootPath, "target"), 0755); err != nil {
					t.Fatal(err)
				}
				return ""
			},
			wantError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rootPath := newRoot(t)
			untouched := tc.setup(t, rootPath)
			target := filepath.Join(rootPath, "target")

			err := write(rootPath, "/target", "fresh", "0640")
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected an error writing over a %s", tc.name)
				}
				if fi, statErr := os.Lstat(target); statErr != nil || !fi.IsDir() {
					t.Errorf("the existing directory did not survive: %v", statErr)
				}
			} else {
				if err != nil {
					t.Fatalf("write over a %s failed: %v", tc.name, err)
				}
				fi, statErr := os.Lstat(target)
				if statErr != nil {
					t.Fatalf("expected the file at %s: %v", target, statErr)
				}
				if !fi.Mode().IsRegular() {
					t.Errorf("%s is a %v, want a regular file", target, fi.Mode().Type())
				}
				if content, readErr := os.ReadFile(target); readErr != nil {
					t.Fatalf("failed to read %s: %v", target, readErr)
				} else if string(content) != "fresh" {
					t.Errorf("content = %q, want %q", content, "fresh")
				}
				if fi.Mode().Perm() != 0640 {
					t.Errorf("mode = %v, want %v", fi.Mode().Perm(), os.FileMode(0640))
				}
			}
			// A symlink is replaced, so whatever it pointed at is untouched.
			if untouched != "" {
				if content, readErr := os.ReadFile(untouched); readErr != nil {
					t.Errorf("the symlink's target was disturbed: %v", readErr)
				} else if string(content) != "pointee" {
					t.Errorf("the symlink's target was overwritten with %q", content)
				}
			}
			if left := tempFiles(t, rootPath); len(left) != 0 {
				t.Errorf("temporary files left behind: %v", left)
			}
		})
	}
}

// TestWriteFileBlockedComponent asserts a lookup failure that is not "the
// directory is missing" is reported as itself. Only ENOENT may fall through to
// directory creation: treating every failure as absence turns a blocking
// regular file into a bare "file exists" from mkdir.
func TestWriteFileBlockedComponent(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, rootPath string)
		wantErr error
	}{
		{
			name: "regular file in the way",
			setup: func(t *testing.T, rootPath string) {
				if err := os.WriteFile(filepath.Join(rootPath, "blocked"),
					[]byte("x"), 0644); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: unix.ENOTDIR,
		},
		{
			name: "symlink loop",
			setup: func(t *testing.T, rootPath string) {
				if err := os.Symlink("blocked2", filepath.Join(rootPath, "blocked")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("blocked", filepath.Join(rootPath, "blocked2")); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: unix.ELOOP,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rootPath := newRoot(t)
			tc.setup(t, rootPath)

			err := write(rootPath, "/blocked/sub/file", "x", "0644")
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want one wrapping %v", err, tc.wantErr)
			}
			if got := findFile(t, rootPath, "file"); len(got) != 0 {
				t.Errorf("wrote the file anyway, at %v", got)
			}
		})
	}
}

// TestWriteFileSpecialModeBits pins how a permissions string is converted,
// which has to match what os.Chmod did before the write moved to a descriptor.
// Go's FileMode carries setuid/setgid/sticky in high bits of its own, not at
// octal 04000/02000/01000, so the two notations do not mean the same thing.
func TestWriteFileSpecialModeBits(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		permissions string
		wantPerm    os.FileMode
		wantSetuid  bool
	}{
		{permissions: "0640", wantPerm: 0640},
		// Go's own ModeSetuid bit, which os.Chmod mapped to S_ISUID.
		{
			permissions: strconv.FormatUint(uint64(os.ModeSetuid|0640), 8),
			wantPerm:    0640,
			wantSetuid:  true,
		},
		// Unix notation for setuid, which neither this code nor os.Chmod has
		// ever honoured: 04000 is not Go's ModeSetuid. Pinned so a change is
		// a deliberate one.
		{permissions: "4755", wantPerm: 0755},
	} {
		t.Run(tc.permissions, func(t *testing.T) {
			t.Parallel()

			rootPath := newRoot(t)
			if err := write(rootPath, "/f", "x", tc.permissions); err != nil {
				t.Fatalf("write with permissions %q failed: %v", tc.permissions, err)
			}
			fi, err := os.Stat(filepath.Join(rootPath, "f"))
			if err != nil {
				t.Fatalf("expected the file: %v", err)
			}
			if fi.Mode().Perm() != tc.wantPerm {
				t.Errorf("mode = %v, want %v", fi.Mode().Perm(), tc.wantPerm)
			}
			if setuid := fi.Mode()&os.ModeSetuid != 0; setuid != tc.wantSetuid {
				t.Errorf("setuid = %v, want %v", setuid, tc.wantSetuid)
			}
		})
	}
}

// TestWriteFileLeavesNoTemporaryFiles asserts the temporary file is cleaned up
// whether the write completes or not. Without it a failed entry would leave
// the content it could not publish sitting in the application's filesystem.
func TestWriteFileLeavesNoTemporaryFiles(t *testing.T) {
	t.Parallel()

	rootPath := newRoot(t)
	if err := write(rootPath, "/ok", "x", "0644"); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	// A directory at the destination fails at the rename, which is the latest
	// failure point that still has a temporary file to remove.
	if err := os.MkdirAll(filepath.Join(rootPath, "blocked"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := write(rootPath, "/blocked", "x", "0644"); err == nil {
		t.Fatal("expected writing over a directory to fail")
	}
	if left := tempFiles(t, rootPath); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}
