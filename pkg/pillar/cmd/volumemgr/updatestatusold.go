// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// Returns changed
// XXX remove "done" boolean return?
func doUpdateOld(ctx *volumemgrContext, status *types.OldVolumeStatus) (bool, bool) {

	log.Infof("doUpdateOld(%s) name %s", status.Key(), status.DisplayName)
	status.WaitingForCerts = false

	// Anything to do?
	if status.State == types.CREATED_VOLUME {
		log.Infof("doUpdateOld(%s) name %s nothing to do",
			status.Key(), status.DisplayName)
		return false, true
	}
	changed := false
	addedBlobs := false
	if status.State < types.VERIFIED {
		// at this point, we at least are downloading
		if status.State < types.DOWNLOADING {
			status.State = types.DOWNLOADING
			changed = true
		}

		// loop through each blob, see if it is downloaded and verified.
		// we set the OldVolumeStatus to verified when all of the blobs are verified
		leftToProcess := false
		sv := SignatureVerifier{
			Signature:        status.DownloadOrigin.ImageSignature,
			PublicKey:        status.DownloadOrigin.SignatureKey,
			CertificateChain: status.DownloadOrigin.CertificateChain,
		}

		var (
			currentSize, totalSize int64
			blobErrors             = []string{}
			blobErrorTime          time.Time
		)
		for _, blobSha := range status.Blobs {
			// get the actual blobStatus
			blob := lookupOrCreateBlobStatus(ctx, sv, status.ObjType, blobSha)
			if blob == nil {
				log.Errorf("doUpdateOld: could not find BlobStatus(%s)", blobSha)
				leftToProcess = true
				continue
			}
			totalSize += blob.TotalSize
			currentSize += blob.CurrentSize

			// now the type should not be unknown (unless it is in error state)
			// these calls might update Blob.State hence we check
			// sequentially
			if blob.State <= types.DOWNLOADING {
				// any state less than downloaded, we ask for download;
				// downloadBlob() is smart enough to look for existing references
				log.Infof("doUpdateOld: blob sha %s download state %v less than DOWNLOADED", blob.Sha256, blob.State)
				if downloadBlob(ctx, status.ObjType, sv, blob) {
					publishBlobStatus(ctx, blob)
					changed = true
				}
			}
			if blob.State == types.DOWNLOADED || blob.State == types.VERIFYING {
				// downloaded: kick off verifier for this blob
				log.Infof("doUpdateOld: blob sha %s download state %v less than VERIFIED", blob.Sha256, blob.State)
				if verifyBlob(ctx, status.ObjType, sv, blob) {
					publishBlobStatus(ctx, blob)
					changed = true
				}
			}
			if blob.State != types.VERIFIED {
				leftToProcess = true
				log.Errorf("doUpdateOld: left to process due to state '%s' for content blob %s",
					blob.State, blob.Sha256)
			} else {
				log.Infof("doUpdateOld: blob sha %s download state VERIFIED", blob.Sha256)
				// if verified, check for any children and start them off
				// resolve any unknown types and get manifests of index, or children of manifest
				blobType, err := resolveBlobType(blob)
				if blobType != blob.BlobType || err != nil {
					blob.BlobType = blobType
					publishBlobStatus(ctx, blob)
					changed = true
				}
				if err != nil {
					log.Infof("doUpdateOld(%s): error resolving blob type: %v", blob.Sha256, err)
					blob.SetError(err.Error(), time.Now())
					publishBlobStatus(ctx, blob)
					changed = true
				}
				blobChildren := blobsNotInList(getBlobChildren(blob), status.Blobs)
				if len(blobChildren) > 0 {
					log.Infof("doUpdateOld: adding %d children", len(blobChildren))
					addedBlobs = true
					// add all of the children
					for _, blob := range blobChildren {
						status.Blobs = append(status.Blobs, blob.Sha256)
					}
					// only publish those that do not already exist
					publishBlobStatus(ctx, blobsNotInStatusOrCreate(ctx, sv, status.ObjType, blobChildren)...)
				}
				if blob.BlobType == types.BlobManifest {
					size := resolveManifestSize(*blob)
					if size != status.TotalSize {
						status.TotalSize = size
						changed = true
					}
				}
			}
			// if any errors, catch them
			// Note that the downloadBlob above could have cleared
			// previous errors due to a retry hence we check for
			// errors here at the end
			if blob.HasError() {
				log.Errorf("doUpdateOld: BlobStatus(%s) has error: %s", blobSha, blob.Error)
				blobErrors = append(blobErrors, blob.Error)
				if blob.ErrorTime.After(blobErrorTime) {
					blobErrorTime = blob.ErrorTime
				}
				leftToProcess = true
			}
		}

		// Check if sizes changed before setting changed
		if status.CurrentSize != currentSize || status.TotalSize != totalSize {
			changed = true
			status.CurrentSize = currentSize
			status.TotalSize = totalSize
			if status.TotalSize > 0 {
				status.Progress = uint(status.CurrentSize / status.TotalSize * 100)
			}
			log.Infof("doUpdateOld: updating CurrentSize/TotalSize/Progress %d/%d/%d",
				currentSize, totalSize, status.Progress)
		}

		// update errors from blobs to status
		if len(blobErrors) != 0 {
			status.SetError(strings.Join(blobErrors, " / "), blobErrorTime)
			changed = true
		} else if status.HasError() {
			log.Infof("doUpdateOld(%s) clearing errors", status.Key())
			status.ClearErrorWithSource()
			changed = true
		}

		// if we added any blobs, we need to reprocess this
		if addedBlobs {
			log.Infof("doUpdateOld(%s) rerunning with added blobs: %v", status.Key(), addedBlobs)
			return doUpdateOld(ctx, status)
		}

		// if there are any left to process, do not do anything else
		// the rest of this flow should happen only when every part of the content tree
		// is downloaded and verified
		if leftToProcess {
			log.Infof("doUpdateOld(%s) leftToProcess=true, so returning `true,false`", status.Key())
			return true, false
		}

		// if we made it this far, the entire tree has been verified
		// before we mark it as verified, load it into the CAS store
		// for now, we only load containers into containerd
		// TODO: next stage, load disk images as well
		if status.Format == zconfig.Format_CONTAINER {
			if err := containerd.LoadBlobs(lookupBlobStatuses(ctx, status.Blobs...), status.DownloadOrigin.Name); err != nil {
				status.SetErrorWithSource(fmt.Sprintf("unable to load blobs into containerd: %v", err),
					types.OldVolumeStatus{}, time.Now())
				return changed, false
			}
		}
		status.State = types.VERIFIED
	}
	if status.State == types.VERIFIED && !status.VolumeCreated {
		status.State = types.CREATING_VOLUME
		changed = true
		// Asynch creation; ensure we have requested it
		MaybeAddWorkCreateOld(ctx, status)
	}
	if status.State == types.CREATING_VOLUME && !status.VolumeCreated {
		vr := lookupVolumeWorkResult(ctx, status.Key())
		if vr != nil {
			log.Infof("doUpdateOld: VolumeWorkResult(%s) location %s, created %t",
				status.Key(), vr.FileLocation, vr.VolumeCreated)
			deleteVolumeWorkResult(ctx, status.Key())
			if status.VolumeCreated != vr.VolumeCreated {
				log.Infof("From vr set VolumeCreated to %s for %s",
					vr.FileLocation, status.VolumeID)
				status.VolumeCreated = vr.VolumeCreated
				changed = true
			}
			if status.FileLocation != vr.FileLocation {
				log.Infof("doUpdateOld: From vr set FileLocation to %s for %s",
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
				log.Infof("doUpdateOld: Clearing volume error %s", status.Error)
				status.ClearErrorWithSource()
				changed = true
			}
		} else {
			log.Infof("doUpdateOld: VolumeWorkResult(%s) not found", status.Key())
		}
	}
	if status.State == types.CREATING_VOLUME && status.VolumeCreated {
		if !status.HasError() {
			status.State = types.CREATED_VOLUME
		}
		changed = true
		// Work is done
		DeleteWorkCreateOld(ctx, status)
		return changed, true
	}
	return changed, false
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
	}

	if status.VolumeCreated {
		// Asynch destruction; make sure we have a request for the work
		MaybeAddWorkDestroyOld(ctx, status)
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
				DeleteWorkDestroyOld(ctx, status)
			}
		} else {
			log.Infof("VolumeWorkResult(%s) not found", status.Key())
		}

	}
	return changed
}
