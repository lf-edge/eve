// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// writeFile is a small helper that creates parent dirs and writes content.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestRestoreKvmVolumes_NoHoldingDir(t *testing.T) {
	initTestLog()
	root := t.TempDir()
	holding := filepath.Join(root, "vault", kvmVolumesHoldingDirName)
	target := filepath.Join(root, "vault", "volumes")
	// Neither directory exists — must be a clean no-op.
	assert.NoError(t, restoreKvmVolumes(holding, target, false))
	assert.NoDirExists(t, target)
}

func TestRestoreKvmVolumes_HappyPath(t *testing.T) {
	initTestLog()
	root := t.TempDir()
	holding := filepath.Join(root, "vault", kvmVolumesHoldingDirName)
	target := filepath.Join(root, "vault", "volumes")

	name := "11111111-1111-1111-1111-111111111111#0.qcow2"
	writeFile(t, filepath.Join(holding, name), "disk-bytes")

	assert.NoError(t, restoreKvmVolumes(holding, target, false))

	// File moved back to the target...
	got, err := os.ReadFile(filepath.Join(target, name))
	assert.NoError(t, err)
	assert.Equal(t, "disk-bytes", string(got))
	// ...and removed from the holding dir, which is gone once empty.
	assert.NoFileExists(t, filepath.Join(holding, name))
	assert.NoDirExists(t, holding)
}

func TestRestoreKvmVolumes_DoesNotClobberExisting(t *testing.T) {
	initTestLog()
	root := t.TempDir()
	holding := filepath.Join(root, "vault", kvmVolumesHoldingDirName)
	target := filepath.Join(root, "vault", "volumes")

	name := "22222222-2222-2222-2222-222222222222#0.qcow2"
	writeFile(t, filepath.Join(holding, name), "holding-copy")
	writeFile(t, filepath.Join(target, name), "live-copy")

	assert.NoError(t, restoreKvmVolumes(holding, target, false))

	// Live target copy is preserved; holding copy is left in place (not deleted).
	got, err := os.ReadFile(filepath.Join(target, name))
	assert.NoError(t, err)
	assert.Equal(t, "live-copy", string(got))
	assert.FileExists(t, filepath.Join(holding, name))
	assert.DirExists(t, holding)
}

func TestRestoreKvmVolumes_DryRun(t *testing.T) {
	initTestLog()
	root := t.TempDir()
	holding := filepath.Join(root, "vault", kvmVolumesHoldingDirName)
	target := filepath.Join(root, "vault", "volumes")

	name := "33333333-3333-3333-3333-333333333333#0.qcow2"
	writeFile(t, filepath.Join(holding, name), "disk-bytes")

	assert.NoError(t, restoreKvmVolumes(holding, target, true))

	// noFlag: nothing moved or removed.
	assert.FileExists(t, filepath.Join(holding, name))
	assert.NoFileExists(t, filepath.Join(target, name))
}
