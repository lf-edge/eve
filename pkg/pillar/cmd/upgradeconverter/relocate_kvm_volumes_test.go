// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/stretchr/testify/assert"
)

type stageDirs struct {
	volumes, holding, marker string
}

func newStageDirs(t *testing.T) stageDirs {
	initTestLog()
	root := t.TempDir()
	return stageDirs{
		volumes: filepath.Join(root, "vault", "volumes"),
		holding: filepath.Join(root, "vault", kvmVolumesHoldingDirName),
		marker:  filepath.Join(root, "status", types.KvmToKubePendingFilename),
	}
}

func TestStageKvmVolumes_HappyPath(t *testing.T) {
	d := newStageDirs(t)
	writeFile(t, d.marker, "")

	// A disk-volume file and a container-volume directory.
	disk := "11111111-1111-1111-1111-111111111111#0.qcow2"
	ctr := "22222222-2222-2222-2222-222222222222#0.container"
	writeFile(t, filepath.Join(d.volumes, disk), "disk-bytes")
	writeFile(t, filepath.Join(d.volumes, ctr, "rootfs", "f"), "ctr-bytes")

	assert.NoError(t, stageKvmVolumes(d.volumes, d.holding, d.marker, false))

	got, err := os.ReadFile(filepath.Join(d.holding, disk))
	assert.NoError(t, err)
	assert.Equal(t, "disk-bytes", string(got))
	assert.FileExists(t, filepath.Join(d.holding, ctr, "rootfs", "f"))
	assert.NoFileExists(t, filepath.Join(d.volumes, disk))
	assert.NoDirExists(t, filepath.Join(d.volumes, ctr))
	assert.DirExists(t, d.volumes)
	assert.NoFileExists(t, d.marker)
}

// Without the marker the directory is left alone whatever it holds: Longhorn's
// layout after an EVE-k to EVE-k upgrade, local-path PVCs on a K3S_BASE device.
func TestStageKvmVolumes_NoMarkerLeavesVolumesAlone(t *testing.T) {
	d := newStageDirs(t)
	entries := []string{
		"longhorn-disk.cfg",
		filepath.Join("replicas", "pvc-x", "volume-head-000.img"),
		filepath.Join("pvc-1234_default_data", "f"),
	}
	for _, e := range entries {
		writeFile(t, filepath.Join(d.volumes, e), "data")
	}

	assert.NoError(t, stageKvmVolumes(d.volumes, d.holding, d.marker, false))

	for _, e := range entries {
		assert.FileExists(t, filepath.Join(d.volumes, e))
	}
	assert.NoDirExists(t, d.holding)
}

func TestStageKvmVolumes_MarkerWithoutVolumes(t *testing.T) {
	d := newStageDirs(t)
	writeFile(t, d.marker, "")

	assert.NoError(t, stageKvmVolumes(d.volumes, d.holding, d.marker, false))

	assert.DirExists(t, d.volumes)
	assert.NoDirExists(t, d.holding)
	assert.NoFileExists(t, d.marker)
}

func TestStageKvmVolumes_DryRun(t *testing.T) {
	d := newStageDirs(t)
	writeFile(t, d.marker, "")
	disk := "33333333-3333-3333-3333-333333333333#0.qcow2"
	writeFile(t, filepath.Join(d.volumes, disk), "disk-bytes")

	assert.NoError(t, stageKvmVolumes(d.volumes, d.holding, d.marker, true))

	assert.FileExists(t, filepath.Join(d.volumes, disk))
	assert.NoDirExists(t, d.holding)
	assert.FileExists(t, d.marker)
}

// Relocate on EVE-k, fall back to EVE-kvm (restore), then retry the conversion:
// the retried update writes a fresh marker and the volumes are relocated again.
func TestStageRestoreRetryCycle(t *testing.T) {
	d := newStageDirs(t)
	disk := "44444444-4444-4444-4444-444444444444#0.qcow2"
	writeFile(t, filepath.Join(d.volumes, disk), "disk-bytes")

	for attempt := 1; attempt <= 2; attempt++ {
		writeFile(t, d.marker, "")
		assert.NoError(t, stageKvmVolumes(d.volumes, d.holding, d.marker, false))
		assert.FileExists(t, filepath.Join(d.holding, disk), "attempt %d", attempt)
		assert.NoFileExists(t, filepath.Join(d.volumes, disk), "attempt %d", attempt)
		assert.NoFileExists(t, d.marker, "attempt %d", attempt)

		assert.NoError(t, restoreKvmVolumes(d.holding, d.volumes, false))
		got, err := os.ReadFile(filepath.Join(d.volumes, disk))
		assert.NoError(t, err)
		assert.Equal(t, "disk-bytes", string(got))
		assert.NoDirExists(t, d.holding)
	}
}

// TestDropKvmToKubeMarker covers the ZFS side, where the kvm volumes stay as
// zvols: the marker goes, and the volumes directory is left alone.
func TestDropKvmToKubeMarker(t *testing.T) {
	d := newStageDirs(t)
	writeFile(t, d.marker, "")
	writeFile(t, filepath.Join(d.volumes, "a#1.raw"), "iso")

	assert.NoError(t, dropKvmToKubeMarker(d.marker, true))
	assert.FileExists(t, d.marker, "dryrun removed the marker")

	assert.NoError(t, dropKvmToKubeMarker(d.marker, false))
	assert.NoFileExists(t, d.marker)
	assert.FileExists(t, filepath.Join(d.volumes, "a#1.raw"))
	assert.NoDirExists(t, d.holding)

	assert.NoError(t, dropKvmToKubeMarker(d.marker, false), "a run without the marker failed")
}
