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
func doUpdateCT(ctx *volumemgrContext, status *types.ContentTreeStatus) (bool, bool) {

	log.Infof("doUpdate(%s) name %s", status.Key(), status.DisplayName)
	status.WaitingForCerts = false

	changed := false
	if status.State < types.VERIFIED {
		if status.IsContainer {
			maybeLatchImageSha(ctx, status)
		}
		if status.IsContainer && status.ContentSha256 == "" {
			rs := lookupResolveStatus(ctx, status.ResolveKey())
			if rs == nil {
				log.Infof("Resolve status not found for %s",
					status.ContentID)
				status.HasResolverRef = true
				MaybeAddResolveConfig(ctx, status)
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
			addAppAndImageHash(ctx, status.ContentID,
				status.ContentSha256, uint32(status.GenerationCounter))
			maybeLatchImageSha(ctx, status)
			deleteResolveConfig(ctx, rs.Key())
			changed = true
		}
		// Check if Verified Status already exists.
		var vs *types.VerifyImageStatus
		vs, changed = lookForVerifiedCT(ctx, status)
		if vs != nil {
			log.Infof("doUpdate: Found %s based on ContentID %s sha %s",
				status.DisplayName, status.ContentID, status.ContentSha256)
			if status.State != vs.State {
				if vs.State == types.VERIFIED && !status.HasPersistRef {
					log.Infof("doUpdate: Adding PersistImageStatus reference for ContentTreeStatus: %s", status.ContentSha256)
					AddOrRefCountPersistImageStatus(ctx, vs.Name, vs.ObjType, vs.FileLocation, vs.ImageSha256, vs.Size)
					status.HasPersistRef = true
					changed = true
				}
				log.Infof("doUpdate: Update State of %s from %d to %d", status.ContentSha256, status.State, vs.State)
				status.State = vs.State
				changed = true
			}
			if vs.Pending() {
				log.Infof("doUpdate: lookupVerifyImageStatus %s Pending",
					status.ContentID)
				return changed, false
			}
			if vs.HasError() {
				log.Errorf("doUpdate: Received error from verifier for %s: %s",
					status.ContentID, vs.Error)
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
				status.DisplayName, status.ContentID,
				status.ContentSha256)
			c := doDownloadCT(ctx, status)
			if c {
				changed = true
			}
			return changed, false
		} else {
			log.Infof("doUpdate: VerifyImageStatus %s for %s sha %s not found; waiting for DOWNLOADED to VERIFIED",
				status.DisplayName, status.ContentID,
				status.ContentSha256)
			return changed, false
		}
	}
	// If maximum download size is 0 then we are updating the
	// downloaded size of an image in MaxSizeBytes
	if status.MaxDownSize == 0 {

		info, err := os.Stat(status.FileLocation)
		if err != nil {
			errStr := fmt.Sprintf("Calculating size of container image failed: %v", err)
			log.Error(errStr)
		} else {
			status.MaxDownSize = uint64(info.Size())
		}
	}
	if status.State == types.VERIFIED {
		return changed, true
	}
	return changed, false
}

// Returns changed
func doDownloadCT(ctx *volumemgrContext, status *types.ContentTreeStatus) bool {

	changed := false
	// Make sure we kick the downloader and have a refcount
	if !status.HasDownloaderRef {
		AddOrRefcountDownloaderConfigCT(ctx, *status)
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
	if status.MaxDownSize != ds.Size {
		status.MaxDownSize = ds.Size
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
		c := kickVerifierCT(ctx, status, true)
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
func kickVerifierCT(ctx *volumemgrContext, status *types.ContentTreeStatus, checkCerts bool) bool {
	changed := false
	if !status.HasVerifierRef {
		if status.State == types.DOWNLOADED {
			status.State = types.VERIFYING
			changed = true
		}
		done, errorAndTime := MaybeAddVerifyImageConfigCT(ctx, *status, checkCerts)
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
func lookForVerifiedCT(ctx *volumemgrContext, status *types.ContentTreeStatus) (*types.VerifyImageStatus, bool) {
	changed := false
	vs := lookupVerifyImageStatus(ctx, status.ObjType, status.ContentSha256)
	if vs == nil {
		ps := lookupPersistImageStatus(ctx, status.ObjType, status.ContentSha256)
		if ps == nil || ps.Expired {
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
				MaybeAddVerifyImageConfigCT(ctx, *status, false)
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
		c := kickVerifierCT(ctx, status, false)
		if c {
			changed = true
		}
		return vs, changed
	}
	return vs, changed
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
			changed, _ := doUpdateCT(ctx, &status)
			if changed {
				publishContentTreeStatus(ctx, &status)
			}
		}
	}
	if !found {
		log.Warnf("XXX updateContentTreeStatus(%s) NOT FOUND", contentID)
	}
}
