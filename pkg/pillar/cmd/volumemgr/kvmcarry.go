// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"os"
	"path/filepath"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/kubeapi"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

// kvmCarried is an EVE-kvm app volume carried over by a kvm-to-k conversion,
// which csihandler rolls into a PVC: a file (ext4 /persist) or a zvol dataset
// (ZFS /persist). name is its base name, matched against the name each
// VolumeStatus would have had on EVE-kvm.
type kvmCarried struct {
	location string
	name     string
	zvol     bool
}

// kvmCarryOps is the storage the drain touches, held in a variable so the
// sweep can be decided in a test without a pool or the real /persist.
type kvmCarryOps struct {
	partitionCommitted func() bool
	readDir            func(dir string) ([]os.DirEntry, error)
	removeAll          func(path string) error
	datasetExists      func(dataset string) bool
	listZvols          func(dataset string) ([]string, error)
	destroyDataset     func(dataset string) error
}

var kvmCarry = kvmCarryOps{
	partitionCommitted: zboot.IsCurrentPartitionStateActive,
	readDir:            os.ReadDir,
	removeAll:          os.RemoveAll,
	datasetExists:      func(dataset string) bool { return zfs.DatasetExist(log, dataset) },
	listZvols:          zfs.GetVolumesFromDataset,
	destroyDataset:     zfs.DestroyDataset,
}

// drainKvmCarriedVolumes removes the carried-over EVE-kvm app volumes an EVE-k
// device no longer needs, and the kvm vault the vault migration parked once it
// holds none of them. It runs off the gc tick, which starts only once config is
// in use, and does nothing until the EVE-k partition is committed: before that
// a reboot falls back to EVE-kvm, which needs the volumes back.
//
// A volume goes once the VolumeStatus it was carried for reached
// CREATED_VOLUME without error (its PVC holds the data), or once no
// VolumeStatus has claimed it for vdiskGCTime (the controller dropped it).
// A volume whose rollout failed is kept for the retry.
func drainKvmCarriedVolumes(ctx *volumemgrContext) {
	if !ctx.hvTypeKube || !kvmCarry.partitionCommitted() {
		return
	}
	candidates := listKvmCarried(ctx.persistType)
	var statuses []types.VolumeStatus
	for _, st := range ctx.pubVolumeStatus.GetAll() {
		statuses = append(statuses, st.(types.VolumeStatus))
	}
	if ctx.kvmCarryOrphanSince == nil {
		ctx.kvmCarryOrphanSince = make(map[string]time.Time)
	}
	grace := time.Duration(ctx.vdiskGCTime) * time.Second
	for _, c := range planKvmCarryDrain(candidates, statuses, ctx.kvmCarryOrphanSince, time.Now(), grace) {
		var err error
		if c.zvol {
			err = kvmCarry.destroyDataset(c.location)
		} else {
			err = kvmCarry.removeAll(c.location)
		}
		if err != nil {
			log.Errorf("drainKvmCarriedVolumes: remove %s: %v", c.location, err)
			continue
		}
		delete(ctx.kvmCarryOrphanSince, c.location)
		log.Noticef("drainKvmCarriedVolumes: removed carried-over EVE-kvm volume %s", c.location)
	}
	if ctx.persistType == types.PersistZFS {
		dropDrainedKvmVault()
	}
}

// listKvmCarried returns the carried-over EVE-kvm volumes present. Entries that
// do not parse as a volume name are left out, so other content in the clear
// volumes directory is never a candidate.
func listKvmCarried(persistType types.PersistType) []kvmCarried {
	var out []kvmCarried
	for _, dir := range []string{types.VolumeEncryptedDirName + "-kvm", types.VolumeClearDirName} {
		entries, err := kvmCarry.readDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if _, skip := kubeapi.VolumeDirInternalEntriesMap()[e.Name()]; skip {
				continue
			}
			location := filepath.Join(dir, e.Name())
			if _, err := getVolumeStatusByLocation(location); err != nil {
				continue
			}
			out = append(out, kvmCarried{location: location, name: e.Name()})
		}
	}
	if persistType != types.PersistZFS {
		return out
	}
	for _, dataset := range []string{types.KvmParkedVolumeEncryptedZFSDataset, types.VolumeClearZFSDataset} {
		if !kvmCarry.datasetExists(dataset) {
			continue
		}
		zvols, err := kvmCarry.listZvols(dataset)
		if err != nil {
			log.Errorf("listKvmCarried: list %s: %v", dataset, err)
			continue
		}
		for _, z := range zvols {
			out = append(out, kvmCarried{location: z, name: filepath.Base(z), zvol: true})
		}
	}
	return out
}

// planKvmCarryDrain returns the candidates to remove. orphanSince records when
// each unclaimed candidate was first seen unclaimed; it is updated in place.
func planKvmCarryDrain(candidates []kvmCarried, statuses []types.VolumeStatus,
	orphanSince map[string]time.Time, now time.Time, grace time.Duration) []kvmCarried {
	claimedBy := make(map[string]types.VolumeStatus)
	for _, st := range statuses {
		claimedBy[filepath.Base(st.PathName())] = st
		claimedBy[filepath.Base(st.ZVolName())] = st
	}
	present := make(map[string]bool)
	var remove []kvmCarried
	for _, c := range candidates {
		present[c.location] = true
		st, claimed := claimedBy[c.name]
		if claimed {
			delete(orphanSince, c.location)
			if st.State >= types.CREATED_VOLUME && !st.HasError() {
				remove = append(remove, c)
			}
			continue
		}
		since, seen := orphanSince[c.location]
		if !seen {
			orphanSince[c.location] = now
			continue
		}
		if now.Sub(since) >= grace {
			remove = append(remove, c)
		}
	}
	for location := range orphanSince {
		if !present[location] {
			delete(orphanSince, location)
		}
	}
	return remove
}

// dropDrainedKvmVault destroys the parked kvm vault once no app-volume zvol is
// left in it.
func dropDrainedKvmVault() {
	if !kvmCarry.datasetExists(types.KvmParkedSealedDataset) {
		return
	}
	if kvmCarry.datasetExists(types.KvmParkedVolumeEncryptedZFSDataset) {
		zvols, err := kvmCarry.listZvols(types.KvmParkedVolumeEncryptedZFSDataset)
		if err != nil {
			log.Errorf("dropDrainedKvmVault: list %s: %v", types.KvmParkedVolumeEncryptedZFSDataset, err)
			return
		}
		if len(zvols) > 0 {
			return
		}
	}
	if err := kvmCarry.destroyDataset(types.KvmParkedSealedDataset); err != nil {
		log.Errorf("dropDrainedKvmVault: destroy %s: %v", types.KvmParkedSealedDataset, err)
		return
	}
	log.Noticef("dropDrainedKvmVault: destroyed the drained kvm vault %s", types.KvmParkedSealedDataset)
}
