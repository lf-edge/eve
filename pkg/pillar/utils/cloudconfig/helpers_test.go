// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cloudconfig_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/utils/cloudconfig"
	"github.com/sirupsen/logrus"
)

// Fixtures and assertions shared by the WriteFile tests.

func testLog() *base.LogObject {
	return base.NewSourceLogObject(logrus.StandardLogger(), "cloudconfig", 0)
}

// newRoot returns an empty application rootfs.
func newRoot(t *testing.T) string {
	t.Helper()
	rootPath := filepath.Join(t.TempDir(), "rootfs")
	if err := os.MkdirAll(rootPath, 0755); err != nil {
		t.Fatalf("failed to create rootfs: %v", err)
	}
	return rootPath
}

func write(rootPath, filePath, content, permissions string) error {
	return cloudconfig.WriteFile(testLog(), cloudconfig.WritableFile{
		Path:        filePath,
		Content:     content,
		Permissions: permissions,
	}, rootPath)
}

// findFile returns the paths of the regular files under dir whose base name is
// name. Symlinks are excluded: a symlink named the same is not a written file.
func findFile(t *testing.T, dir, name string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() && d.Name() == name {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk %s: %v", dir, err)
	}
	return found
}

// assertAbsent fails unless path does not exist. Lstat, so a symlink counts as
// present, and only a not-exist error counts as absence -- any other error
// means the question was not answered.
func assertAbsent(t *testing.T, path, why string) {
	t.Helper()
	_, err := os.Lstat(path)
	if err == nil {
		t.Errorf("%s: %s exists", why, path)
		return
	}
	if !os.IsNotExist(err) {
		t.Fatalf("could not determine whether %s exists: %v", path, err)
	}
}

// tempFiles returns the leftover temporary files in dir.
func tempFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read %s: %v", dir, err)
	}
	var left []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".cloudinit-tmp") {
			left = append(left, entry.Name())
		}
	}
	return left
}
