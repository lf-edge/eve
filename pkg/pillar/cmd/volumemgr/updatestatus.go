// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"os"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

// Returns changed
// XXX remove "done" boolean return?
func doUpdateContentTree(ctx *volumemgrContext, status *types.ContentTreeStatus) (bool, bool) {

	log.Infof("doUpdateContentTree(%s) name %s", status.Key(), status.DisplayName)
	status.WaitingForCerts = false

	changed := false
	if status.State < types.VERIFIED {
		if status.IsContainer() {
			maybeLatchContentTreeHash(ctx, status)
		}
		if status.IsContainer() && status.ContentSha256 == "" {
			rs := lookupResolveStatus(ctx, status.ResolveKey())
			if rs == nil {
				log.Infof("Resolve status not found for %s",
					status.ContentID)
				status.HasResolverRef = true
				MaybeAddResolveConfig(ctx, *status)
				status.State = types.RESOLVING_TAG
				changed = true
				return changed, false
			}
			log.Infof("Processing ResolveStatus for content tree (%v)", status.ContentID)
			status.State = types.RESOLVED_TAG
			changed = true
			if rs.HasError() {
				errStr := fmt.Sprintf("Received error from resolver for %s, SHA (%s): %s",
					status.ResolveKey(), rs.ImageSha256, rs.Error)
				log.Error(errStr)
				status.SetErrorWithSource(errStr, types.ResolveStatus{},
					rs.ErrorTime)
				changed = true
				return changed, false
			} else if rs.ImageSha256 == "" {
				errStr := fmt.Sprintf("Received empty SHA from resolver for %s, SHA (%s): %s",
					status.ResolveKey(), rs.ImageSha256, rs.Error)
				log.Error(errStr)
				status.SetErrorWithSource(errStr, types.ResolveStatus{},
					rs.ErrorTime)
				changed = true
				return changed, false
			} else if status.IsErrorSource(types.ResolveStatus{}) {
				log.Infof("Clearing resolver error %s", status.Error)
				status.ClearErrorWithSource()
				changed = true
			}
			log.Infof("Added Image SHA (%s) for content tree (%s)",
				rs.ImageSha256, status.ContentID)
			status.ContentSha256 = rs.ImageSha256
			status.HasResolverRef = false
			status.RelativeURL = maybeInsertSha(status.RelativeURL, status.ContentSha256)
			latchContentTreeHash(ctx, status.ContentID,
				status.ContentSha256, uint32(status.GenerationCounter))
			maybeLatchContentTreeHash(ctx, status)
			deleteResolveConfig(ctx, rs.Key())
			changed = true
		}
		// Check if Verified Status already exists.
		var vs *types.VerifyImageStatus
		vs, changed = lookForVerified(ctx, status)
		if vs != nil {
			log.Infof("doUpdateContentTree: Found %s based on ContentID %s sha %s",
				status.DisplayName, status.ContentID, status.ContentSha256)
			if status.State != vs.State {
				if vs.State == types.VERIFIED && !status.HasPersistRef {
					log.Infof("doUpdateContentTree: Adding PersistImageStatus reference for ContentTreeStatus: %s", status.ContentSha256)
					AddOrRefCountPersistImageStatus(ctx, vs.Name, vs.ObjType, vs.FileLocation, vs.ImageSha256, vs.Size)
					status.HasPersistRef = true
					changed = true
				}
				log.Infof("doUpdateContentTree: Update State of %s from %d to %d", status.ContentSha256, status.State, vs.State)
				status.State = vs.State
				changed = true
			}
			if vs.Pending() {
				log.Infof("doUpdateContentTree: lookupVerifyImageStatus %s Pending",
					status.ContentID)
				return changed, false
			}
			if vs.HasError() {
				log.Errorf("doUpdateContentTree: Received error from verifier for %s: %s",
					status.ContentID, vs.Error)
				status.SetErrorWithSource(vs.Error,
					types.VerifyImageStatus{}, vs.ErrorTime)
				changed = true
				return changed, false
			} else if status.IsErrorSource(types.VerifyImageStatus{}) {
				log.Infof("doUpdateContentTree: Clearing verifier error %s", status.Error)
				status.ClearErrorWithSource()
				changed = true
			}
			if status.FileLocation != vs.FileLocation {
				status.FileLocation = vs.FileLocation
				log.Infof("doUpdateContentTree: Update FileLocation for %s: %s",
					status.Key(), status.FileLocation)
				changed = true
			}
		} else if status.State <= types.DOWNLOADED {
			log.Infof("doUpdateContentTree: VerifyImageStatus %s for %s sha %s not found",
				status.DisplayName, status.ContentID,
				status.ContentSha256)
			c := doDownload(ctx, status)
			if c {
				changed = true
			}
			return changed, false
		} else {
			log.Infof("doUpdateContentTree: VerifyImageStatus %s for %s sha %s not found; waiting for DOWNLOADED to VERIFIED",
				status.DisplayName, status.ContentID,
				status.ContentSha256)
			return changed, false
		}
	}
	// If maximum download size is 0 then we are updating the
	// downloaded size of an image in MaxSizeBytes
	if status.MaxDownloadSize == 0 {

		info, err := os.Stat(status.FileLocation)
		if err != nil {
			errStr := fmt.Sprintf("Calculating size of container image failed: %v", err)
			log.Error(errStr)
		} else {
			status.MaxDownloadSize = uint64(info.Size())
		}
	}
	if status.State == types.VERIFIED {
		return changed, true
	}
	return changed, false
}

// Returns changed
// XXX remove "done" boolean return?
func doUpdateVol(ctx *volumemgrContext, status *types.VolumeStatus) (bool, bool) {

	log.Infof("doUpdateVol(%s) name %s", status.Key(), status.DisplayName)

	// Anything to do?
	if status.State == types.CREATED_VOLUME {
		log.Infof("doUpdateVol(%s) name %s nothing to do",
			status.Key(), status.DisplayName)
		return false, true
	}
	changed := false
	switch status.VolumeContentOriginType {
	case zconfig.VolumeContentOriginType_VCOT_BLANK:
		// XXX TBD
		errStr := fmt.Sprintf("doUpdateVol(%s) name %s: Volume content origin type %v is not implemeted yet.",
			status.Key(), status.DisplayName, status.VolumeContentOriginType)
		status.SetErrorWithSource(errStr,
			types.VolumeStatus{}, time.Now())
		changed = true
		return changed, false
	case zconfig.VolumeContentOriginType_VCOT_DOWNLOAD:
		ctStatus := lookupContentTreeStatus(ctx, status.ContentID.String())
		if ctStatus == nil {
			// Content tree not available
			log.Errorf("doUpdateVol(%s) name %s: waiting for content tree status %v",
				status.Key(), status.DisplayName, status.ContentID)
			errStr := fmt.Sprintf("ContentTreeStatus(%s) attached to volume %s is nil",
				status.ContentID.String(), status.DisplayName)
			status.SetErrorWithSource(errStr, types.ContentTreeStatus{}, time.Now())
			changed = true
			return changed, false
		} else if status.IsErrorSource(types.ContentTreeStatus{}) {
			log.Infof("doUpdate: Clearing volume error %s", status.Error)
			status.ClearErrorWithSource()
			changed = true
		}
		if status.Progress != ctStatus.Progress {
			status.Progress = ctStatus.Progress
			changed = true
		}
		if status.State != ctStatus.State {
			status.State = ctStatus.State
			changed = true
		}
		if ctStatus.State < types.VERIFIED {
			// Waiting for content tree to be processed
			if ctStatus.HasError() {
				log.Errorf("doUpdateVol(%s) name %s: content tree status has following error %v",
					status.Key(), status.DisplayName, ctStatus.Error)
				errStr := fmt.Sprintf("Found error in content tree %s attached to volume %s: %v",
					ctStatus.DisplayName, status.DisplayName, ctStatus.Error)
				status.SetErrorWithSource(errStr, types.ContentTreeStatus{}, time.Now())
				changed = true
				return changed, false
			}
			log.Infof("doUpdateVol(%s) name %s: waiting for content tree status %v to be verified",
				status.Key(), status.DisplayName, ctStatus.DisplayName)
			return changed, false
		}
		if ctStatus.State == types.VERIFIED &&
			status.State != types.CREATING_VOLUME &&
			!status.VolumeCreated {

			status.State = types.CREATING_VOLUME
			status.FileLocation = ctStatus.FileLocation
			status.ContentFormat = ctStatus.Format
			changed = true
			// Asynch creation; ensure we have requested it
			MaybeAddWorkCreate(ctx, status)
		}
		if status.IsErrorSource(types.ContentTreeStatus{}) {
			log.Infof("doUpdate: Clearing volume error %s", status.Error)
			status.ClearErrorWithSource()
			changed = true
		}
		if status.State == types.CREATING_VOLUME && !status.VolumeCreated {
			vr := lookupVolumeWorkResult(ctx, status.Key())
			if vr != nil {
				log.Infof("doUpdateVol: VolumeWorkResult(%s) location %s, created %t",
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
					log.Errorf("doUpdate: Error recieved from the volume worker %v",
						vr.Error)
					status.SetErrorWithSource(vr.Error.Error(),
						types.VolumeStatus{}, vr.ErrorTime)
					changed = true
					return changed, false
				} else if status.IsErrorSource(types.VolumeStatus{}) {
					log.Infof("doUpdate: Clearing volume error %s", status.Error)
					status.ClearErrorWithSource()
					changed = true
				}
			} else {
				log.Infof("doUpdateVol: VolumeWorkResult(%s) not found", status.Key())
			}
		}
		if status.State == types.CREATING_VOLUME && status.VolumeCreated {
			if !status.HasError() {
				status.State = types.CREATED_VOLUME
			}
			changed = true
			// Work is done
			DeleteWorkCreate(ctx, status)
			if status.MaxVolSize == 0 {
				var err error
				log.Infof("doUpdateVol: MaxVolSize is 0 for %s. Filling it up.",
					status.FileLocation)
				_, status.MaxVolSize, err = utils.GetVolumeSize(status.FileLocation)
				if err != nil {
					log.Error(err)
				}
			}
			return changed, true
		}
	default:
		// Unsupported volume content origin type
		errStr := fmt.Sprintf("doUpdateVol(%s) name %s: Volume content origin type %v not supported",
			status.Key(), status.DisplayName, status.VolumeContentOriginType)
		status.SetErrorWithSource(errStr,
			types.VolumeStatus{}, time.Now())
		changed = true
		return changed, false
	}
	return changed, false
}

// Returns changed
func doDownload(ctx *volumemgrContext, status *types.ContentTreeStatus) bool {

	changed := false
	// Make sure we kick the downloader and have a refcount
	if !status.HasDownloaderRef {
		AddOrRefcountDownloaderConfig(ctx, *status)
		status.HasDownloaderRef = true
		changed = true
	}
	// Check if we have a DownloadStatus if not put a DownloadConfig
	// in place
	ds := lookupDownloaderStatus(ctx, status.ObjType, status.ContentSha256)
	if ds == nil || ds.Expired || ds.RefCount == 0 {
		if ds == nil {
			log.Infof("downloadStatus not found. name: %s", status.ContentID)
		} else if ds.Expired {
			log.Infof("downloadStatus Expired set. name: %s", status.ContentID)
		} else {
			log.Infof("downloadStatus RefCount=0. name: %s", status.ContentID)
		}
		status.State = types.DOWNLOADING
		changed = true
		return changed
	}
	if ds.Target != "" && status.FileLocation == "" {
		status.FileLocation = ds.Target
		changed = true
		log.Infof("From ds set FileLocation to %s for %s",
			ds.Target, status.ContentID)
	}
	if status.State != ds.State {
		status.State = ds.State
		changed = true
	}
	if status.MaxDownloadSize != ds.Size {
		status.MaxDownloadSize = ds.Size
	}
	if ds.Progress != status.Progress {
		status.Progress = ds.Progress
		changed = true
	}
	if ds.Pending() {
		log.Infof("lookupDownloaderStatus %s Pending",
			status.ContentID)
		return changed
	}
	if ds.HasError() {
		log.Errorf("Received error from downloader for %s: %s",
			status.ContentID, ds.Error)
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
func kickVerifier(ctx *volumemgrContext, status *types.ContentTreeStatus, checkCerts bool) bool {
	changed := false
	if !status.HasVerifierRef {
		if status.State == types.DOWNLOADED {
			status.State = types.VERIFYING
			changed = true
		}
		done, errorAndTime := MaybeAddVerifyImageConfig(ctx, *status, checkCerts)
		if done {
			status.HasVerifierRef = true
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
func lookForVerified(ctx *volumemgrContext, status *types.ContentTreeStatus) (*types.VerifyImageStatus, bool) {
	changed := false
	vs := lookupVerifyImageStatus(ctx, status.ObjType, status.ContentSha256)
	if vs == nil || vs.Expired {
		ps := lookupPersistImageStatus(ctx, status.ObjType, status.ContentSha256)
		if ps == nil {
			log.Infof("Verify/PersistImageStatus for %s sha %s not found",
				status.ContentID, status.ContentSha256)
		} else {
			log.Infof("lookForVerified: Found PersistImageStatus: %s based on ImageSha256 %s ContentID %s",
				status.DisplayName, status.ContentSha256, status.ContentID)
			if !status.HasPersistRef {
				log.Infof("lookForVerified: Adding PersistImageStatus reference for ContentTreeStatus: %s", status.ContentSha256)
				AddOrRefCountPersistImageStatus(ctx, ps.Name, ps.ObjType, ps.FileLocation, ps.ImageSha256, ps.Size)
				status.HasPersistRef = true
				changed = true
			}
			//Marking the ContentTreeStatus state as VERIFIED as we already have a PersistImageStatus for the content tree
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
			if !status.HasVerifierRef {
				log.Infof("!HasVerifierRef")
				// We don't need certs since Status already exists
				MaybeAddVerifyImageConfig(ctx, *status, false)
				status.HasVerifierRef = true
				changed = true
			}
			//Wait for VerifyImageStatus to appear
			return nil, changed
		}
	} else {
		log.Infof("Found %s based on ContentID %s sha %s",
			status.DisplayName, status.ContentID, status.ContentSha256)
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
			changed, _ := doUpdateOld(ctx, &status)
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
			changed, _ := doUpdateContentTree(ctx, &status)
			if changed {
				publishContentTreeStatus(ctx, &status)
			}
			// Volume status referring to this content UUID needs to get updated
			updateVolumeStatusFromContentID(ctx, status.ContentID)
		}
	}
	if !found {
		log.Warnf("XXX updateStatus(%s) objType %s NOT FOUND",
			uuid, objType)
	}
}

func updateContentTreeStatus(ctx *volumemgrContext, contentSha256 string, contentID uuid.UUID) {

	log.Infof("updateContentTreeStatus(%s)", contentID)
	found := false
	pub := ctx.pubContentTreeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.ContentTreeStatus)
		if status.ContentSha256 == contentSha256 {
			log.Infof("Found ContentTreeStatus %s", status.Key())
			found = true
			changed, _ := doUpdateContentTree(ctx, &status)
			if changed {
				publishContentTreeStatus(ctx, &status)
			}
		}
	}
	if !found {
		log.Warnf("XXX updateContentTreeStatus(%s) NOT FOUND", contentID)
	}
}

// Find all the VolumeStatus which refer to this volume uuid
func updateVolumeStatus(ctx *volumemgrContext, volumeID uuid.UUID) {

	log.Infof("updateVolumeStatus for %s", volumeID)
	found := false
	pub := ctx.pubVolumeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.VolumeStatus)
		if status.VolumeID == volumeID {
			log.Infof("Found VolumeStatus %s: name %s",
				status.Key(), status.DisplayName)
			found = true
			changed, _ := doUpdateVol(ctx, &status)
			if changed {
				publishVolumeStatus(ctx, &status)
				updateVolumeRefStatus(ctx, &status)
			}
		}
	}
	if !found {
		log.Warnf("XXX updateVolumeStatus(%s) NOT FOUND", volumeID)
	}
}

// Find all the VolumeStatus which refer to this content uuid
func updateVolumeStatusFromContentID(ctx *volumemgrContext, contentID uuid.UUID) {

	log.Infof("updateVolumeStatusFromContentID for %s", contentID)
	found := false
	pub := ctx.pubVolumeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.VolumeStatus)
		if status.ContentID == contentID {
			log.Infof("Found VolumeStatus %s: name %s",
				status.Key(), status.DisplayName)
			found = true
			changed, _ := doUpdateVol(ctx, &status)
			if changed {
				publishVolumeStatus(ctx, &status)
				updateVolumeRefStatus(ctx, &status)
			}
		}
	}
	if !found {
		log.Warnf("XXX updateVolumeStatusFromContentID(%s) NOT FOUND", contentID)
	}
}
