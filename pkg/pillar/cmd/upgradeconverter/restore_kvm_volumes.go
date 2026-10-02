// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgradeconverter

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/lf-edge/eve/pkg/pillar/base"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

// kvmVolumesHoldingDirName is the directory (under /persist/vault) into which
// the EVE-k upgrade relocates the carried-over EVE-kvm app volumes so that
// Longhorn can take ownership of /persist/vault/volumes. The EVE-k staging
// handler (the writer) and this restore handler (the reader on rollback) must
// agree on the name.
const kvmVolumesHoldingDirName = "volumes-kvm"

// kvmVolumesHoldingDir returns /persist/vault/volumes-kvm.
func kvmVolumesHoldingDir(persistDir string) string {
	return filepath.Join(persistDir, "vault", kvmVolumesHoldingDirName)
}

// restoreKvmVolumesOnDowngrade undoes the EVE-k volume relocation when a device
// has fallen back to EVE-kvm, so the kvm volumemgr finds its app volumes where
// it expects them.
//
// Background. When a device upgrades EVE-kvm -> EVE-k, the encrypted app volumes
// in /persist/vault/volumes conflict with Longhorn, which owns that exact path
// on EVE-k (data path set in pkg/kube/longhorn-utils.sh). The EVE-k upgrade
// therefore relocates them to /persist/vault/volumes-kvm and gives Longhorn a
// fresh /persist/vault/volumes. If that EVE-k partition then fails its test
// window, the device automatically falls back to this (EVE-kvm) partition
// before the upgrade is committed (handleZbootTestComplete /
// MarkCurrentPartitionStateActive in baseosmgr). On that fallback boot, kvm's
// volumemgr scans /persist/vault/volumes and would find only Longhorn's empty
// layout. This handler moves the volumes back first.
//
// Because automatic fallback returns to the image the device upgraded *from*,
// this handler must ship in the EVE-kvm release that predates enabling kvm->k
// conversion — it is the forward-compatibility net that makes that later
// upgrade safely reversible.
//
// Filesystem scope. On ext4 /persist the vault is an fscrypt directory on both
// flavors, so the holding directory is directly reachable once the vault is
// unlocked and the restore is a simple move. On ZFS /persist nothing is
// relocated and this handler is a no-op: the kvm app volumes are zvols, and the
// vault recovery in vaultmgr puts the parked kvm vault back in place of the
// migrated zvol vault before this runs.
//
// Runs in the post-vault phase (the holding directory lives under the encrypted
// vault). No-op on EVE-k and whenever no holding directory is present.
// Idempotent.
func restoreKvmVolumesOnDowngrade(ctxPtr *ucContext) error {
	if base.IsHVTypeKube() {
		log.Functionf("restoreKvmVolumesOnDowngrade: running EVE-k, nothing to restore")
		return nil
	}
	return restoreKvmVolumes(
		kvmVolumesHoldingDir(ctxPtr.persistDir),
		filepath.Clean(ctxPtr.volumesDir()),
		ctxPtr.noFlag)
}

// restoreKvmVolumes is the testable core: move every entry from holdingDir into
// targetDir (skipping any name already present in targetDir so we never clobber
// live state), then remove holdingDir once it is empty. A missing holdingDir is
// the common case (no prior EVE-k relocation) and is treated as success.
func restoreKvmVolumes(holdingDir, targetDir string, noFlag bool) error {
	if !fileutils.DirExists(log, holdingDir) {
		log.Functionf("restoreKvmVolumes: %s absent; nothing to restore", holdingDir)
		return nil
	}
	entries, err := os.ReadDir(holdingDir)
	if err != nil {
		return fmt.Errorf("restoreKvmVolumes: read %s: %w", holdingDir, err)
	}
	if !noFlag {
		if err := os.MkdirAll(targetDir, 0700); err != nil {
			return fmt.Errorf("restoreKvmVolumes: mkdir %s: %w", targetDir, err)
		}
	}
	var restored, skipped int
	for _, e := range entries {
		oldPath := filepath.Join(holdingDir, e.Name())
		newPath := filepath.Join(targetDir, e.Name())
		info, err := os.Stat(oldPath)
		if err != nil {
			log.Errorf("restoreKvmVolumes: stat %s: %v", oldPath, err)
			continue
		}
		if _, err := os.Stat(newPath); err == nil {
			// Already present in the target (e.g. a re-run after a partial
			// restore) — leave the holding copy alone rather than overwrite.
			log.Warnf("restoreKvmVolumes: %s already exists; not restoring %s",
				newPath, oldPath)
			skipped++
			continue
		}
		// maybeMove handles the file/dir distinction, the fscrypt copy-vs-rename
		// nuance, and the container snapshot-id file.
		maybeMove(oldPath, info.ModTime(), newPath, noFlag)
		restored++
	}
	log.Noticef("restoreKvmVolumes: restored %d, skipped %d, from %s to %s",
		restored, skipped, holdingDir, targetDir)
	return removeDirIfEmpty(holdingDir, noFlag)
}

// removeDirIfEmpty removes dir only when it has no remaining entries. Failure to
// remove is logged but not fatal — a leftover empty holding directory is
// harmless and will be retried on the next boot.
func removeDirIfEmpty(dir string, noFlag bool) error {
	if noFlag {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Already gone or unreadable; nothing to clean up.
		return nil
	}
	if len(entries) != 0 {
		log.Functionf("removeDirIfEmpty: %s not empty (%d entries); leaving it",
			dir, len(entries))
		return nil
	}
	if err := os.Remove(dir); err != nil {
		log.Warnf("removeDirIfEmpty: %s: %v", dir, err)
	}
	return nil
}
