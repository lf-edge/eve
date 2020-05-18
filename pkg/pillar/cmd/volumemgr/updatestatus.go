// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"path"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Returns changed
// XXX remove "done" boolean return?
func doUpdate(ctx *volumemgrContext, status *types.VolumeStatus) (bool, bool) {

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
			log.Infof("Found %s based on VolumeID %s sha %s",
				status.DisplayName, status.VolumeID,
				status.BlobSha256)

			if status.State != vs.State {
				status.State = vs.State
				changed = true
			}
			if vs.Pending() {
				log.Infof("lookupVerifyImageStatus %s Pending",
					status.VolumeID)
				return changed, false
			}
			if vs.HasError() {
				log.Errorf("Received error from verifier for %s: %s",
					status.VolumeID, vs.Error)
				status.SetErrorWithSource(vs.Error,
					types.VerifyImageStatus{}, vs.ErrorTime)
				changed = true
				return changed, false
			} else if status.IsErrorSource(types.VerifyImageStatus{}) {
				log.Infof("Clearing verifier error %s", status.Error)
				status.ClearErrorWithSource()
				changed = true
			}
			if status.FileLocation != vs.FileLocation {
				status.FileLocation = vs.FileLocation
				log.Infof("Update FileLocation for %s: %s",
					status.Key(), status.FileLocation)
				changed = true
			}
		} else {
			log.Infof("VerifyImageStatus %s for %s sha %s not found",
				status.DisplayName, status.VolumeID,
				status.BlobSha256)
			c := doDownload(ctx, status)
			if c {
				changed = true
			}
			return changed, false
		}
	}
	if status.State == types.VERIFIED && !status.VolumeCreated {
		status.State = types.CREATING_VOLUME
		changed = true
		// Asynch creation; ensure we have requested it
		MaybeAddWorkCreate(ctx, status)
	}
	if status.State == types.CREATING_VOLUME && !status.VolumeCreated {
		vr := lookupVolumeWorkResult(ctx, status.Key())
		if vr != nil {
			log.Infof("VolumeWorkResult(%s) location %s, created %t",
				status.Key(), vr.FileLocation, vr.VolumeCreated)
			deleteVolumeWorkResult(ctx, status.Key())
			if status.VolumeCreated != vr.VolumeCreated {
				log.Infof("From vr set VolumeCreated to %s for %s",
					vr.FileLocation, status.VolumeID)
				status.VolumeCreated = vr.VolumeCreated
				changed = true
			}
			if status.FileLocation != vr.FileLocation {
				log.Infof("From vr set FileLocation to %s for %s",
					vr.FileLocation, status.VolumeID)
				status.FileLocation = vr.FileLocation
				changed = true
			}
			if vr.Error != nil {
				status.SetErrorWithSource(vr.Error.Error(),
					types.VolumeStatus{}, vr.ErrorTime)
				changed = true
				return changed, false
			} else if status.IsErrorSource(types.VolumeStatus{}) {
				log.Infof("Clearing volume error %s", status.Error)
				status.ClearErrorWithSource()
				changed = true
			}
		} else {
			log.Infof("VolumeWorkResult(%s) not found", status.Key())
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
func doDownload(ctx *volumemgrContext, status *types.VolumeStatus) bool {

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
		locDirname := path.Dir(ds.Target)
		status.FileLocation = locDirname
		changed = true
		log.Infof("From ds set FileLocation to %s for %s",
			locDirname, status.VolumeID)
	}
	if status.State != ds.State {
		status.State = ds.State
		changed = true
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
func kickVerifier(ctx *volumemgrContext, status *types.VolumeStatus, checkCerts bool) bool {
	changed := false
	if !status.DownloadOrigin.HasVerifierRef {
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
func lookForVerified(ctx *volumemgrContext, status *types.VolumeStatus) (*types.VerifyImageStatus, bool) {
	changed := false
	vs := lookupVerifyImageStatus(ctx, status.ObjType, status.BlobSha256)
	if vs == nil {
		ps := lookupPersistImageStatus(ctx, status.ObjType, status.BlobSha256)
		if ps == nil || ps.Expired {
			log.Infof("Verify/PersistImageStatus for %s sha %s not found",
				status.VolumeID, status.BlobSha256)
		} else {
			log.Infof("Found %s based on ImageSha256 %s VolumeID %s",
				status.DisplayName, status.BlobSha256, status.VolumeID)
			if status.State != types.DOWNLOADED {
				status.State = types.DOWNLOADED
				status.Progress = 100
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
			// Wait for VerifyImageStatus to appear
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

// Find all the VolumeStatus which refer to this BlobSha256
func updateVolumeStatus(ctx *volumemgrContext, objType, blobSha256 string, volumeID uuid.UUID) {

	log.Infof("updateVolumeStatus(%s) objType %s", volumeID, objType)
	found := false
	pub := ctx.publication(types.VolumeStatus{}, objType)
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.VolumeStatus)
		if status.BlobSha256 == blobSha256 {
			log.Infof("Found VolumeStatus %s", status.Key())
			found = true
			changed, _ := doUpdate(ctx, &status)
			if changed {
				publishVolumeStatus(ctx, &status)
			}
		}
	}
	if !found {
		log.Warnf("XXX updateVolumeStatus(%s) objType %s NOT FOUND",
			volumeID, objType)
	}
}

// doDelete returns changed boolean
// XXX need return value?
func doDelete(ctx *volumemgrContext, status *types.VolumeStatus) bool {
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
					types.VolumeStatus{}, vr.ErrorTime)
				changed = true
				return changed
			} else if status.IsErrorSource(types.VolumeStatus{}) {
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
