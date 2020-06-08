// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Returns changed
// XXX remove "done" boolean return?
func doUpdate(ctx *volumemgrContext, status *types.OldVolumeStatus) (bool, bool) {

	log.Infof("doUpdate(%s) name %s", status.Key(), status.DisplayName)
	status.WaitingForCerts = false

	// Anything to do?
	if status.State == types.CREATED_VOLUME {
		log.Infof("doUpdate(%s) name %s nothing to do",
			status.Key(), status.DisplayName)
		return false, true
	}
	changed := false
	if status.State < types.VERIFIED {
		// Check if Verified Status already exists.
		var vs *types.VerifyImageStatus
		vs, changed = lookForVerified(ctx, status)
		if vs != nil {
			log.Infof("doUpdate: Found %s based on VolumeID %s sha %s",
				status.DisplayName, status.VolumeID, status.BlobSha256)
			if status.State != vs.State {
				if vs.State == types.VERIFIED && !status.DownloadOrigin.HasPersistRef {
					log.Infof("doUpdate: Adding PersistImageStatus reference for VolumeStatus: %s", status.BlobSha256)
					AddOrRefCountPersistImageStatus(ctx, vs.Name, vs.ObjType, vs.FileLocation, vs.ImageSha256, vs.Size)
					status.DownloadOrigin.HasPersistRef = true
					changed = true
				}
				log.Infof("doUpdate: Update State of %s from %d to %d", status.BlobSha256, status.State, vs.State)
				status.State = vs.State
				changed = true
			}
			if vs.Pending() {
				log.Infof("doUpdate: lookupVerifyImageStatus %s Pending",
					status.VolumeID)
				return changed, false
			}
			if vs.HasError() {
				log.Errorf("doUpdate: Received error from verifier for %s: %s",
					status.VolumeID, vs.Error)
				status.SetErrorWithSource(vs.Error,
					types.VerifyImageStatus{}, vs.ErrorTime)
				changed = true
				return changed, false
			} else if status.IsErrorSource(types.VerifyImageStatus{}) {
				log.Infof("doUpdate: Clearing verifier error %s", status.Error)
				status.ClearErrorWithSource()
				changed = true
			}
			if status.FileLocation != vs.FileLocation {
				status.FileLocation = vs.FileLocation
				log.Infof("doUpdate: Update FileLocation for %s: %s",
					status.Key(), status.FileLocation)
				changed = true
			}
		} else if status.State <= types.DOWNLOADED {
			log.Infof("doUpdate: VerifyImageStatus %s for %s sha %s not found",
				status.DisplayName, status.VolumeID,
				status.BlobSha256)
			c := doDownload(ctx, status)
			if c {
				changed = true
			}
			return changed, false
		} else {
			log.Infof("doUpdate: VerifyImageStatus %s for %s sha %s not found; waiting for DOWNLOADED to VERIFIED",
				status.DisplayName, status.VolumeID,
				status.BlobSha256)
			return changed, false
		}
	}
	if status.State == types.VERIFIED && !status.VolumeCreated {
		status.State = types.CREATING_VOLUME
		changed = true
		// Asynch creation; ensure we have requested it
		MaybeAddWorkCreate(ctx, status)
	}
	// If maximum download size is 0 then we are updating the
	// downloaded size of an image in MaxSizeBytes
	if status.DownloadOrigin.MaxDownSize == 0 {

		info, err := os.Stat(status.FileLocation)
		if err != nil {
			errStr := fmt.Sprintf("Calculating size of container image failed: %v", err)
			log.Error(errStr)
		} else {
			status.DownloadOrigin.MaxDownSize = uint64(info.Size())
		}
	}
	if status.State == types.CREATING_VOLUME && !status.VolumeCreated {
		vr := lookupVolumeWorkResult(ctx, status.Key())
		if vr != nil {
			log.Infof("doUpdate: VolumeWorkResult(%s) location %s, created %t",
				status.Key(), vr.FileLocation, vr.VolumeCreated)
			deleteVolumeWorkResult(ctx, status.Key())
			if status.VolumeCreated != vr.VolumeCreated {
				log.Infof("From vr set VolumeCreated to %s for %s",
					vr.FileLocation, status.VolumeID)
				status.VolumeCreated = vr.VolumeCreated
				changed = true
			}
			if status.FileLocation != vr.FileLocation {
				log.Infof("doUpdate: From vr set FileLocation to %s for %s",
					vr.FileLocation, status.VolumeID)
				status.FileLocation = vr.FileLocation
				changed = true
			}
			if vr.Error != nil {
				status.SetErrorWithSource(vr.Error.Error(),
					types.OldVolumeStatus{}, vr.ErrorTime)
				changed = true
				return changed, false
			} else if status.IsErrorSource(types.OldVolumeStatus{}) {
				log.Infof("doUpdate: Clearing volume error %s", status.Error)
				status.ClearErrorWithSource()
				changed = true
			}
		} else {
			log.Infof("doUpdate: VolumeWorkResult(%s) not found", status.Key())
		}
	}
	if status.State == types.CREATING_VOLUME && status.VolumeCreated {
		if !status.HasError() {
			status.State = types.CREATED_VOLUME
		}
		changed = true
		// Work is done
		DeleteWorkCreate(ctx, status)
		return changed, true
	}
	return changed, false
}

// Returns changed
func doDownload(ctx *volumemgrContext, status *types.OldVolumeStatus) bool {

	changed := false
	// Make sure we kick the downloader and have a refcount
	if !status.DownloadOrigin.HasDownloaderRef {
		AddOrRefcountDownloaderConfig(ctx, *status)
		status.DownloadOrigin.HasDownloaderRef = true
		changed = true
	}
	// Check if we have a DownloadStatus if not put a DownloadConfig
	// in place
	ds := lookupDownloaderStatus(ctx, status.ObjType, status.BlobSha256)
	if ds == nil || ds.Expired || ds.RefCount == 0 {
		if ds == nil {
			log.Infof("downloadStatus not found. name: %s", status.VolumeID)
		} else if ds.Expired {
			log.Infof("downloadStatus Expired set. name: %s", status.VolumeID)
		} else {
			log.Infof("downloadStatus RefCount=0. name: %s", status.VolumeID)
		}
		status.State = types.DOWNLOADING
		changed = true
		return changed
	}
	if ds.Target != "" && status.FileLocation == "" {
		status.FileLocation = ds.Target
		changed = true
		log.Infof("From ds set FileLocation to %s for %s",
			ds.Target, status.VolumeID)
	}
	if status.State != ds.State {
		status.State = ds.State
		changed = true
	}
	if status.DownloadOrigin.MaxDownSize != ds.Size {
		status.DownloadOrigin.MaxDownSize = ds.Size
	}
	if ds.Progress != status.Progress {
		status.Progress = ds.Progress
		changed = true
	}
	if ds.Pending() {
		log.Infof("lookupDownloaderStatus %s Pending",
			status.VolumeID)
		return changed
	}
	if ds.HasError() {
		log.Errorf("Received error from downloader for %s: %s",
			status.VolumeID, ds.Error)
		status.SetErrorWithSource(ds.Error, types.DownloaderStatus{},
			ds.ErrorTime)
		changed = true
		return changed
	}
	if status.IsErrorSource(types.DownloaderStatus{}) {
		log.Infof("Clearing downloader error %s", status.Error)
		status.ClearErrorWithSource()
		changed = true
	}
	switch ds.State {
	case types.INITIAL:
		// Nothing to do
	case types.DOWNLOADING:
		// Nothing to do
	case types.DOWNLOADED:
		// Kick verifier to start if it hasn't already; add RefCount
		c := kickVerifier(ctx, status, true)
		if c {
			changed = true
		}
	}
	if status.WaitingForCerts {
		log.Infof("Waiting for certs for %s", status.Key())
		return changed
	}
	log.Infof("Waiting for download for %s", status.Key())
	return changed
}

// Returns changed
// Updates status with WaitingForCerts if checkCerts is set
func kickVerifier(ctx *volumemgrContext, status *types.OldVolumeStatus, checkCerts bool) bool {
	changed := false
	if !status.DownloadOrigin.HasVerifierRef {
		if status.State == types.DOWNLOADED {
			status.State = types.VERIFYING
			changed = true
		}
		done, errorAndTime := MaybeAddVerifyImageConfig(ctx, *status, checkCerts)
		if done {
			status.DownloadOrigin.HasVerifierRef = true
			changed = true
			return changed
		}
		// if errors, set the certError flag
		// otherwise, mark as waiting for certs
		if errorAndTime.HasError() {
			status.SetError(errorAndTime.Error, errorAndTime.ErrorTime)
			changed = true
		} else if !status.WaitingForCerts {
			status.WaitingForCerts = true
			changed = true
		}
	}
	return changed
}

// lookForVerified handles the split between PersistImageStatus and
// VerifyImageStatus. If it only finds the Persist it returns nil but
// sets up a VerifyImageConfig.
// Also returns changed=true if the VolumeStatus is changed
func lookForVerified(ctx *volumemgrContext, status *types.OldVolumeStatus) (*types.VerifyImageStatus, bool) {
	changed := false
	vs := lookupVerifyImageStatus(ctx, status.ObjType, status.BlobSha256)
	if vs == nil {
		ps := lookupPersistImageStatus(ctx, status.ObjType, status.BlobSha256)
		if ps == nil || ps.Expired {
			log.Infof("Verify/PersistImageStatus for %s sha %s not found",
				status.VolumeID, status.BlobSha256)
		} else {
			log.Infof("lookForVerified: Found PersistImageStatus: %s based on ImageSha256 %s VolumeID %s",
				status.DisplayName, status.BlobSha256, status.VolumeID)
			if !status.DownloadOrigin.HasPersistRef {
				log.Infof("lookForVerified: Adding PersistImageStatus reference for VolumeStatus: %s", status.BlobSha256)
				AddOrRefCountPersistImageStatus(ctx, ps.Name, ps.ObjType, ps.FileLocation, ps.ImageSha256, ps.Size)
				status.DownloadOrigin.HasPersistRef = true
				changed = true
			}
			//Marking the VolumeStatus state as VERIFIED as we already have a PersistImageStatus for the volume
			if status.State != types.VERIFIED {
				status.State = types.VERIFIED
				status.Progress = 100
				changed = true
			}
			if status.FileLocation != ps.FileLocation {
				status.FileLocation = ps.FileLocation
				log.Infof("lookForVerified: Update FileLocation for %s: %s",
					status.Key(), status.FileLocation)
				changed = true
			}
			// If we don't already have a RefCount add one
			if !status.DownloadOrigin.HasVerifierRef {
				log.Infof("!HasVerifierRef")
				// We don't need certs since Status already exists
				MaybeAddVerifyImageConfig(ctx, *status, false)
				status.DownloadOrigin.HasVerifierRef = true
				changed = true
			}
			//Wait for VerifyImageStatus to appear
			return nil, changed
		}
	} else {
		log.Infof("Found %s based on VolumeID %s sha %s",
			status.DisplayName, status.VolumeID, status.BlobSha256)
		// If we don't already have a RefCount add one
		// No need to checkCerts since we have a VerifyImageStatus
		c := kickVerifier(ctx, status, false)
		if c {
			changed = true
		}
		return vs, changed
	}
	return vs, changed
}

// Find all the VolumeStatus/ContentTreeStatus which refer to this Sha256
func updateStatus(ctx *volumemgrContext, objType, sha string, uuid uuid.UUID) {

	log.Infof("updateStatus(%s) objType %s", uuid, objType)
	found := false
	volPub := ctx.publication(types.OldVolumeStatus{}, objType)
	volItems := volPub.GetAll()
	for _, st := range volItems {
		status := st.(types.OldVolumeStatus)
		if status.BlobSha256 == sha {
			log.Infof("Found VolumeStatus %s", status.Key())
			found = true
			changed, _ := doUpdate(ctx, &status)
			if changed {
				publishOldVolumeStatus(ctx, &status)
			}
		}
	}
	ctPub := ctx.pubContentTreeStatus
	ctItems := ctPub.GetAll()
	for _, st := range ctItems {
		status := st.(types.ContentTreeStatus)
		if status.ContentSha256 == sha {
			log.Infof("Found ContentTreeStatus %s", status.Key())
			found = true
			changed, _ := doUpdateCT(ctx, &status)
			if changed {
				publishContentTreeStatus(ctx, &status)
			}
		}
	}
	if !found {
		log.Warnf("XXX updateStatus(%s) objType %s NOT FOUND",
			uuid, objType)
	}
}

// doDelete returns changed boolean
// XXX need return value?
func doDelete(ctx *volumemgrContext, status *types.OldVolumeStatus) bool {
	changed := false

	// XXX support other types
	if status.Origin == types.OriginTypeDownload {
		if status.DownloadOrigin.HasDownloaderRef {
			MaybeRemoveDownloaderConfig(ctx, status.ObjType,
				status.BlobSha256)
			status.DownloadOrigin.HasDownloaderRef = false
			changed = true
		}
		if status.DownloadOrigin.HasVerifierRef {
			MaybeRemoveVerifyImageConfig(ctx, status.ObjType,
				status.BlobSha256)
			status.DownloadOrigin.HasVerifierRef = false
			changed = true
		}
		if status.DownloadOrigin.HasPersistRef {
			ReduceRefCountPersistImageStatus(ctx, status.ObjType, status.BlobSha256)
			status.DownloadOrigin.HasPersistRef = false
			changed = true
		}
	}

	if status.VolumeCreated {
		// Asynch destruction; make sure we have a request for the work
		MaybeAddWorkDestroy(ctx, status)
		vr := lookupVolumeWorkResult(ctx, status.Key())
		if vr != nil {
			log.Infof("VolumeWorkResult(%s) location %s, created %t",
				status.Key(), vr.FileLocation, vr.VolumeCreated)
			deleteVolumeWorkResult(ctx, status.Key())
			// Compare to set changed?
			status.VolumeCreated = vr.VolumeCreated
			status.FileLocation = vr.FileLocation
			changed = true
			if vr.Error != nil {
				status.SetErrorWithSource(vr.Error.Error(),
					types.OldVolumeStatus{}, vr.ErrorTime)
				changed = true
				return changed
			} else if status.IsErrorSource(types.OldVolumeStatus{}) {
				log.Infof("Clearing volume error %s",
					status.Error)
				status.ClearErrorWithSource()
				changed = true
			}
			if !status.VolumeCreated {
				DeleteWorkDestroy(ctx, status)
			}
		} else {
			log.Infof("VolumeWorkResult(%s) not found", status.Key())
		}

	}
	return changed
}
