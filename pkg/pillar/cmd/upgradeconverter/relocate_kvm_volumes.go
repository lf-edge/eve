// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
)

// relocateKvmVolumesForKube moves carried-over EVE-kvm app volumes out of
// /persist/vault/volumes — which Longhorn must own on EVE-k (data path set in
// pkg/kube/longhorn-utils.sh) — into /persist/vault/volumes-kvm, leaving a clean
// empty /persist/vault/volumes for Longhorn. The relocated sources are later
// converted to Longhorn PVCs, lazily, by volumemgr once the cluster is up; the
// counterpart restoreKvmVolumesOnDowngrade moves them back if the device falls
// back to EVE-kvm.
//
// It runs only when the types.KvmToKubePendingFilename marker exists. EVE-kvm's
// baseosmgr writes it before starting a conversion to EVE-k, so on any other
// EVE-k boot — an EVE-k to EVE-k upgrade, a fresh install, a K3S_BASE device
// with local-path PVCs in the same directory — nothing is touched. This runs in
// the post-vault phase before k3s/Longhorn start, so when the marker is present
// the directory holds only kvm content. A retry after a fallback to EVE-kvm
// gets a fresh marker from the retried update.
//
// ext4 only. On ZFS /persist the EVE-kvm app volumes are zvols, not files in
// /persist/vault/volumes: the fs->zvol vault migration parks the kvm vault with
// its encrypted zvols at types.KvmParkedSealedDataset, the clear zvols stay
// under types.VolumeClearZFSDataset, and csihandler rolls PVCs out from them.
// Nothing needs moving, so on ZFS only the marker is removed.
func relocateKvmVolumesForKube(ctxPtr *ucContext) error {
	if !base.IsHVTypeKube() {
		log.Functionf("relocateKvmVolumesForKube: not EVE-k, skipping")
		return nil
	}
	markerPath := filepath.Join(ctxPtr.persistStatusDir, types.KvmToKubePendingFilename)
	if persist.ReadPersistType() == types.PersistZFS {
		return dropKvmToKubeMarker(markerPath, ctxPtr.noFlag)
	}
	return stageKvmVolumes(
		filepath.Clean(ctxPtr.volumesDir()),
		kvmVolumesHoldingDir(ctxPtr.persistDir),
		markerPath,
		ctxPtr.noFlag)
}

// dropKvmToKubeMarker removes markerPath if present.
func dropKvmToKubeMarker(markerPath string, noFlag bool) error {
	if !fileutils.FileExists(log, markerPath) {
		return nil
	}
	if noFlag {
		log.Noticef("dropKvmToKubeMarker: dryrun, would remove %s", markerPath)
		return nil
	}
	if err := os.Remove(markerPath); err != nil {
		return fmt.Errorf("dropKvmToKubeMarker: remove %s: %w", markerPath, err)
	}
	log.Noticef("dropKvmToKubeMarker: ZFS persist, the kvm volumes stay as zvols; removed %s", markerPath)
	return fileutils.DirSync(filepath.Dir(markerPath))
}

// stageKvmVolumes is the testable core. Without markerPath it is a no-op.
// Otherwise it moves every entry of volumesDir into holdingDir (creating
// holdingDir on demand, skipping any name already present there), ensures
// volumesDir exists and is empty for Longhorn, and removes the marker last so an
// interrupted run is redone on the next boot.
func stageKvmVolumes(volumesDir, holdingDir, markerPath string, noFlag bool) error {
	if !fileutils.FileExists(log, markerPath) {
		log.Functionf("stageKvmVolumes: no %s, nothing to relocate", markerPath)
		return nil
	}
	var entries []os.DirEntry
	if fileutils.DirExists(log, volumesDir) {
		var err error
		entries, err = os.ReadDir(volumesDir)
		if err != nil {
			return fmt.Errorf("stageKvmVolumes: read %s: %w", volumesDir, err)
		}
	}
	if noFlag {
		log.Noticef("stageKvmVolumes: dryrun, would relocate %d entry(ies) from %s to %s",
			len(entries), volumesDir, holdingDir)
		return nil
	}
	if len(entries) > 0 {
		if err := os.MkdirAll(holdingDir, 0700); err != nil {
			return fmt.Errorf("stageKvmVolumes: mkdir %s: %w", holdingDir, err)
		}
	}
	var moved, skipped int
	for _, e := range entries {
		oldPath := filepath.Join(volumesDir, e.Name())
		newPath := filepath.Join(holdingDir, e.Name())
		info, err := os.Stat(oldPath)
		if err != nil {
			log.Errorf("stageKvmVolumes: stat %s: %v", oldPath, err)
			continue
		}
		if _, err := os.Stat(newPath); err == nil {
			// Already staged (e.g. a re-run after an interrupted relocation) —
			// don't overwrite the holding copy.
			log.Warnf("stageKvmVolumes: %s already exists; not moving %s", newPath, oldPath)
			skipped++
			continue
		}
		// maybeMove handles the file/dir distinction, the fscrypt copy-vs-rename
		// nuance, and the container snapshot-id file.
		maybeMove(oldPath, info.ModTime(), newPath, noFlag)
		moved++
	}
	// Longhorn needs the directory to exist and be empty.
	if err := os.MkdirAll(volumesDir, 0700); err != nil {
		return fmt.Errorf("stageKvmVolumes: mkdir %s: %w", volumesDir, err)
	}
	log.Noticef("stageKvmVolumes: relocated %d, skipped %d, from %s to %s",
		moved, skipped, volumesDir, holdingDir)
	if err := os.Remove(markerPath); err != nil {
		return fmt.Errorf("stageKvmVolumes: remove %s: %w", markerPath, err)
	}
	return fileutils.DirSync(filepath.Dir(markerPath))
}
