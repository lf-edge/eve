// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"strings"
	"time"

	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	uuid "github.com/satori/go.uuid"
)

// doUpdate handles any updates to a VolumeStatus, called by any event handlers
// that either capture a VolumeStatus change or create one and want it processed.
// Returns changed
// XXX remove "done" boolean return?
func doUpdateContentTree(ctx *volumemgrContext, status *types.ContentTreeStatus) (bool, bool) {

	log.Infof("doUpdateContentTree(%s) name %s state %s", status.Key(), status.DisplayName, status.State)

	changed := false
	addedBlobs := []string{}

	if status.State < types.VERIFIED {
		if status.DatastoreType == "" {
			log.Infof("contentTreeStatus(%s) does not have a datastore type yet, deferring", status.ContentID)
			return false, false
		}

		if status.IsOCIRegistry() {
			maybeLatchContentTreeHash(ctx, status)
			if status.ContentSha256 == "" {
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
				foundSha := strings.ToLower(rs.ImageSha256)
				log.Infof("Added Image SHA (%s) for content tree (%s)",
					foundSha, status.ContentID)
				status.ContentSha256 = foundSha
				status.HasResolverRef = false
				status.RelativeURL = maybeInsertSha(status.RelativeURL, status.ContentSha256)
				latchContentTreeHash(ctx, status.ContentID,
					status.ContentSha256, uint32(status.GenerationCounter))
				maybeLatchContentTreeHash(ctx, status)
				deleteResolveConfig(ctx, rs.Key())
				changed = true

			}

			// at this point, we have a resolved tag
			if status.State < types.RESOLVED_TAG {
				status.State = types.RESOLVED_TAG
				changed = true
			}

			// at this point, we will have the hash of the root blob as status.ContentSha256,
			// so we need to create the BlobStatus, if it does not exist already
			rootBlob := lookupOrCreateBlobStatus(ctx, status.ContentSha256)
			if rootBlob == nil {
				rootBlob = &types.BlobStatus{
					DatastoreID: status.DatastoreID,
					RelativeURL: status.RelativeURL,
					Sha256:      status.ContentSha256,
					Size:        status.MaxDownloadSize,
					State:       types.INITIAL,
				}
				log.Infof("doUpdateContentTree: publishing new root BlobStatus (%s) for content tree (%s)",
					status.ContentSha256, status.ContentID)
				publishBlobStatus(ctx, rootBlob)
			} else if rootBlob.State == types.LOADED {
				//Need to update DatastoreID and RelativeURL if the blob is already loaded into CAS,
				// because if any child blob is not downloaded, then we would need the below data.
				rootBlob.DatastoreID = status.DatastoreID
				rootBlob.RelativeURL = status.RelativeURL
				log.Infof("doUpdateContentTree: publishing loaded root BlobStatus (%s) for content tree (%s)",
					status.ContentSha256, status.ContentID)
				publishBlobStatus(ctx, rootBlob)
			}
			if len(status.Blobs) == 0 {
				AddBlobsToContentTreeStatus(ctx, status, rootBlob.Sha256)
			}
		}

		// at this point, we at least are downloading
		if status.State < types.DOWNLOADING {
			status.State = types.DOWNLOADING
			changed = true
		}

		// loop through each blob, see if it is downloaded and verified.
		// we set the contenttree to verified when all of the blobs are verified
		leftToProcess := false

		var (
			currentSize, totalSize int64
			blobErrors             = []string{}
			blobErrorTime          time.Time
		)
		for _, blobSha := range status.Blobs {
			// get the actual blobStatus
			blob := lookupOrCreateBlobStatus(ctx, blobSha)
			if blob == nil {
				log.Errorf("doUpdateContentTree: could not find BlobStatus(%s)", blobSha)
				leftToProcess = true
				continue
			}
			totalSize += blob.TotalSize
			currentSize += blob.CurrentSize

			// now the type should not be unknown (unless it is in error state)
			// these calls might update Blob.State hence we check
			// sequentially
			if blob.State <= types.DOWNLOADING {
				// any state less than downloaded, we ask for download, so that we have the refcount;
				// downloadBlob() is smart enough to look for existing references
				log.Debugf("doUpdateContentTree: blob sha %s download state %v less than DOWNLOADED", blob.Sha256, blob.State)
				if downloadBlob(ctx, status.ObjType, blob) {
					publishBlobStatus(ctx, blob)
					changed = true
				}
			}
			if blob.State == types.DOWNLOADED || blob.State == types.VERIFYING {
				// downloaded: kick off verifier for this blob
				log.Infof("doUpdateContentTree: blob sha %s download state %v less than VERIFIED", blob.Sha256, blob.State)
				if verifyBlob(ctx, blob) {
					publishBlobStatus(ctx, blob)
					changed = true
				}
			}
			if blob.State < types.VERIFIED {
				leftToProcess = true
				log.Debugf("doUpdateContentTree: left to process due to state '%s' for content blob %s",
					blob.State, blob.Sha256)
			} else {
				log.Debugf("doUpdateContentTree: blob sha %s download state VERIFIED", blob.Sha256)
				// if verified, check for any children and start them off
				blobChildren := blobsNotInList(getBlobChildren(ctx, blob), status.Blobs)
				if len(blobChildren) > 0 {
					log.Infof("doUpdateContentTree: adding %d children", len(blobChildren))
					// add all of the children
					for _, blob := range blobChildren {
						addedBlobs = append(addedBlobs, blob.Sha256)
					}
					// only publish those that do not already exist
					publishBlobStatus(ctx, blobsNotInStatusOrCreate(ctx, blobChildren)...)
					AddBlobsToContentTreeStatus(ctx, status, addedBlobs...)
				}
				if blob.IsManifest() {
					size := resolveManifestSize(ctx, *blob)
					if size != blob.TotalSize {
						blob.TotalSize = size
						publishBlobStatus(ctx, blob)
						changed = true
					}
				}
			}
			// if any errors, catch them
			// Note that the downloadBlob above could have cleared
			// previous errors due to a retry hence we check for
			// errors here at the end
			if blob.HasError() {
				log.Errorf("doUpdateContentTree: BlobStatus(%s) has error: %s", blobSha, blob.Error)
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
				status.Progress = uint(100 * status.CurrentSize / status.TotalSize)
			}
			log.Infof("doUpdateContentTree: updating CurrentSize/TotalSize/Progress %d/%d/%d",
				currentSize, totalSize, status.Progress)
		}

		rootBlob := lookupOrCreateBlobStatus(ctx, status.Blobs[0])
		if rootBlob == nil {
			log.Errorf("doUpdateContentTree(%s) name %s: could not find BlobStatus(%s)",
				status.Key(), status.DisplayName, status.Blobs[0])
			return changed, false
		}
		if status.FileLocation != rootBlob.Path {
			log.Infof("doUpdateContentTree(%s) name %s: updating file location to %s",
				status.Key(), status.DisplayName, rootBlob.Path)
			status.FileLocation = rootBlob.Path
			changed = true
		}

		// update errors from blobs to status
		if len(blobErrors) != 0 {
			status.SetError(strings.Join(blobErrors, " / "), blobErrorTime)
			log.Infof("doUpdateContentTree(%s) had errors: %v", status.Key(), status.Error)
			changed = true
		} else if status.HasError() {
			log.Infof("doUpdateContentTree(%s) clearing errors", status.Key())
			status.ClearErrorWithSource()
			changed = true
		}

		// if we added any blobs, we need to reprocess this
		if len(addedBlobs) > 0 {
			log.Infof("doUpdateContentTree(%s) rerunning with added blobs: %v", status.Key(), addedBlobs)
			return doUpdateContentTree(ctx, status)
		}

		// if there are any left to process, do not do anything else
		// the rest of this flow should happen only when every part of the content tree
		// is downloaded and verified
		if leftToProcess {
			log.Infof("doUpdateContentTree(%s) leftToProcess=true, so returning `true,false`", status.Key())
			return true, false
		}

		blobStatuses := lookupBlobStatuses(ctx, status.Blobs...)
		refID := status.ReferenceID()

		// if we just had an image pointing to a single blob that is not index or manifest, we need
		// to add a manifest to it.
		log.Infof("doUpdateContentTree(%s) checking if we need to add a manifest, have %d blobs", status.Key(), len(blobStatuses))
		if len(blobStatuses) == 1 && !blobStatuses[0].IsManifest() && !blobStatuses[0].IsIndex() {
			blobs, err := getManifestsForBareBlob(ctx, refID, blobStatuses[0].Sha256, int64(blobStatuses[0].Size))
			if err != nil {
				err = fmt.Errorf("doUpdateContentTree(%s): Exception while getting manifest and config for bare blob: %s",
					status.ContentID, err.Error())
				log.Errorf(err.Error())
				status.SetErrorWithSource(err.Error(), types.ContentTreeStatus{}, time.Now())
				return changed, false
			}
			// if we have any, append them
			if len(blobs) > 0 {
				publishBlobStatus(ctx, blobs...)
				// order is important; prepend to existing
				blobStatuses = append(blobs, blobStatuses...)

				// we changed it, so update the ContentTreeStatus
				blobHashes := []string{}
				for _, b := range blobStatuses {
					blobHashes = append(blobHashes, b.Sha256)
				}
				status.Blobs = blobHashes
				// Adding a blob to ContentTreeStatus and incrementing the refcount of that blob should be atomic as
				// we would depend on that while we remove a blob from ContentTreeStatus and decrement
				// the RefCount of that blob. In case if the blobs in a ContentTreeStatus in not in sync with the
				// corresponding Blob's Refcount, then that would lead to Fatal error.
				// If the same sha appears in multiple places in the ContentTree we intentionally add it twice to the list of
				// Blobs so that we can have two reference counts on that blob.
				// Add for the new ones
				for _, b := range blobs {
					AddRefToBlobStatus(ctx, b)
				}
			}
		}

		// if we made it this far, the entire tree has been verified
		// we can mark the tree as verified, but still have to load it into the CAS store
		log.Infof("doUpdateContentTree(%s): all blobs verified %v, setting ContentTree state to VERIFIED", status.Key(), status.Blobs)
		status.State = types.VERIFIED
		publishContentTreeStatus(ctx, status)
	}

	// at this point, the image is VERIFIED or higher
	if status.State == types.VERIFIED {
		log.Infof("doUpdateContentTree(%s): ContentTree state is VERIFIED, starting LOADING", status.Key())

		// now we start loading
		// it is a bit silly to publish twice, but it is important that we keep the audit
		// trail that the image was verified, and now is loading
		status.State = types.LOADING
		publishContentTreeStatus(ctx, status)

		MaybeAddWorkLoad(ctx, status)

		return changed, false
	}

	// if it is LOADING, check each blob until all are loaded
	if status.State == types.LOADING {
		log.Infof("doUpdateContentTree(%s): ContentTree status is LOADING", status.Key())
		// get the work result - see if it succeeded
		wres := lookupCasIngestWorkResult(ctx, status.Key())
		if wres != nil {
			log.Infof("doUpdateContentTree(%s): IngestWorkResult found", status.Key())
			DeleteWorkLoad(ctx, status.Key())
			if wres.Error != nil {
				err := fmt.Errorf("doUpdateContentTree(%s): IngestWorkResult error, exception while loading blobs into CAS: %v", status.Key(), wres.Error)
				log.Errorf(err.Error())
				status.SetErrorWithSource(err.Error(), types.ContentTreeStatus{}, wres.ErrorTime)
				changed = true
				return changed, false
			}
		}

		leftToProcess := 0
		blobStatuses := lookupBlobStatuses(ctx, status.Blobs...)
		for _, blob := range blobStatuses {
			// if the blob was not yet loaded, we ignore it
			if blob.State != types.LOADED {
				log.Infof("doUpdateContentTree(%s): blob %s not yet loaded", status.Key(), blob.Sha256)
				leftToProcess++
				continue
			}

			log.Infof("doUpdateContentTree(%s): Successfully loaded blob: %s", status.Key(), blob.Sha256)
			if blob.HasDownloaderRef {
				log.Infof("doUpdateContentTree(%s): removing downloaderRef from Blob %s",
					status.Key(), blob.Sha256)
				MaybeRemoveDownloaderConfig(ctx, blob.Sha256)
				blob.HasDownloaderRef = false
			}
			if blob.HasVerifierRef {
				log.Infof("doUpdateContentTree(%s): removing verifyRef from Blob %s",
					status.Key(), blob.Sha256)
				MaybeRemoveVerifyImageConfig(ctx, blob.Sha256)
				// Set the path to "" as we delete the verifier path
				blob.HasVerifierRef = false
				blob.Path = ""
			}
			publishBlobStatus(ctx, blob)
		}
		if leftToProcess > 0 {
			log.Infof("doUpdateContentTree(%s): Still have %d blobs left to load", status.Key(), leftToProcess)
			return changed, false
		}
		log.Infof("doUpdateContentTree(%s): all blobs LOADED", status.Key())

		// if we made it here, then all blobs were loaded
		log.Infof("doUpdateContentTree(%s) successfully loaded all blobs into CAS", status.Key())
		status.State = types.LOADED
		// ContentTreeStatus.FileLocation has no meaning once everything is loaded
		status.FileLocation = ""

		changed = true
	}

	return changed, status.State == types.LOADED
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
		ctStatus := lookupContentTreeStatusAny(ctx, status.ContentID.String())
		if ctStatus == nil {
			// Content tree not yet available
			log.Errorf("doUpdateVol(%s) name %s: waiting for content tree status %v",
				status.Key(), status.DisplayName, status.ContentID)
			return changed, false
		}
		if status.IsErrorSource(types.ContentTreeStatus{}) {
			log.Infof("doUpdate: Clearing volume error %s", status.Error)
			status.ClearErrorWithSource()
			changed = true
		}
		if status.Progress != ctStatus.Progress ||
			status.TotalSize != ctStatus.TotalSize ||
			status.CurrentSize != ctStatus.CurrentSize {
			status.Progress = ctStatus.Progress
			status.TotalSize = ctStatus.TotalSize
			status.CurrentSize = ctStatus.CurrentSize
			changed = true
		}
		if status.State != ctStatus.State {
			status.State = ctStatus.State
			changed = true
		}
		if ctStatus.State < types.LOADED {
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
			log.Infof("doUpdateVol(%s) name %s: waiting for content tree status %v to be LOADED",
				status.Key(), status.DisplayName, ctStatus.DisplayName)
			return changed, false
		}
		if ctStatus.State == types.LOADED &&
			status.State != types.CREATING_VOLUME &&
			!status.VolumeCreated {

			status.State = types.CREATING_VOLUME
			// first blob is always the root
			if len(ctStatus.Blobs) < 1 {
				log.Errorf("doUpdateVol(%s) name %s: content tree status has no blobs",
					status.Key(), status.DisplayName)
				return changed, false
			}
			status.ReferenceName = ctStatus.ReferenceID()
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
				if status.FileLocation != vr.FileLocation && vr.Error == nil {
					log.Infof("doUpdateContentTree: From vr set FileLocation to %s for %s",
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
					log.Infof("doUpdateContentTree: Clearing volume error %s", status.Error)
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
				_, maxVolSize, _, _, err := utils.GetVolumeSize(log, status.FileLocation)
				if err != nil {
					log.Error(err)
				} else if maxVolSize != status.MaxVolSize {
					log.Infof("doUpdateVol: MaxVolSize update from  %d to %d for %s",

						status.MaxVolSize, maxVolSize,
						status.FileLocation)
					status.MaxVolSize = maxVolSize
					changed = true
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

// Really a constant
var ctObjTypes = []string{types.AppImgObj, types.BaseOsObj}

// updateStatus updates all VolumeStatus/ContentTreeStatus which include a blob
// that has this Sha256
func updateStatusByBlob(ctx *volumemgrContext, sha string) {

	log.Infof("updateStatusByBlob(%s)", sha)
	found := false
	for _, objType := range ctObjTypes {
		pub := ctx.publication(types.ContentTreeStatus{}, objType)
		items := pub.GetAll()
		for _, st := range items {
			status := st.(types.ContentTreeStatus)
			var hasSha bool
			for _, blobSha := range status.Blobs {
				if blobSha == sha {
					log.Debugf("Found blob %s on ContentTreeStatus %s",
						sha, status.Key())
					hasSha = true
				}
			}
			if hasSha {
				found = true
				if changed, _ := doUpdateContentTree(ctx, &status); changed {
					log.Infof("updateStatusByBlob(%s) publishing ContentTreeStatus",
						status.Key())
					publishContentTreeStatus(ctx, &status)
				}
				// Volume status referring to this content UUID needs to get updated
				log.Infof("updateStatusByBlob(%s) updating volume status from content ID %v",
					status.Key(), status.ContentID)
				updateVolumeStatusFromContentID(ctx,
					status.ContentID)
			}
		}
	}
	if !found {
		log.Warnf("XXX updateStatusByBlob(%s) NOT FOUND", sha)
	}
}

// updateStatusByDatastore update any datastore missing status
func updateStatusByDatastore(ctx *volumemgrContext, datastore types.DatastoreConfig) {
	log.Infof("updateStatusByDatastore(%s)", datastore.UUID)
	for _, objType := range ctObjTypes {
		pub := ctx.publication(types.ContentTreeStatus{}, objType)
		items := pub.GetAll()
		for _, st := range items {
			status := st.(types.ContentTreeStatus)

			// if it does not match the UUID, or it already has the type, ignore it
			if status.DatastoreID != datastore.UUID || status.DatastoreType != "" {
				continue
			}
			// set the type
			log.Infof("Setting datastore type %s for datastore %s on ContentTreeStatus %s",
				datastore.DsType, datastore.UUID, status.Key())
			status.DatastoreType = datastore.DsType
			if changed, _ := doUpdateContentTree(ctx, &status); changed {
				log.Infof("updateStatusByDatastore(%s) publishing ContentTreeStatus",
					status.Key())
				publishContentTreeStatus(ctx, &status)
			}
			// Volume status referring to this content UUID needs to get updated
			log.Infof("updateStatusByDatastore(%s) updating volume status from content ID %v",
				status.Key(), status.ContentID)
			updateVolumeStatusFromContentID(ctx,
				status.ContentID)
		}
	}
}

func updateContentTreeStatus(ctx *volumemgrContext, contentSha256 string, contentID uuid.UUID) {

	log.Infof("updateContentTreeStatus(%s)", contentID)
	found := false
	for _, objType := range ctObjTypes {
		pub := ctx.publication(types.ContentTreeStatus{}, objType)
		items := pub.GetAll()
		for _, st := range items {
			status := st.(types.ContentTreeStatus)
			if status.ContentSha256 == contentSha256 {
				log.Infof("Found ContentTreeStatus %s",
					status.Key())
				found = true
				changed, _ := doUpdateContentTree(ctx, &status)
				if changed {
					publishContentTreeStatus(ctx, &status)
				}
				// Volume status referring to this content UUID needs to get updated
				log.Infof("updateContentTreeStatus(%s) updating volume status from content ID %v",
					status.Key(), status.ContentID)
				updateVolumeStatusFromContentID(ctx,
					status.ContentID)
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
			if err := createOrUpdateAppDiskMetrics(ctx, &status); err != nil {
				log.Errorf("updateVolumeStatus(%s): exception while publishing diskmetric. %s",
					status.Key(), err.Error())
			}
		}
	}
	if !found {
		log.Warnf("XXX updateVolumeStatus(%s) NOT FOUND", volumeID)
	}
}

// Find all the VolumeStatus which refer to this content uuid
func updateVolumeStatusFromContentID(ctx *volumemgrContext, contentID uuid.UUID) {

	log.Debugf("updateVolumeStatusFromContentID for %s", contentID)
	found := false
	pub := ctx.pubVolumeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.VolumeStatus)
		if status.ContentID == contentID {
			log.Debugf("Found VolumeStatus %s: name %s",
				status.Key(), status.DisplayName)
			found = true
			changed, _ := doUpdateVol(ctx, &status)
			if changed {
				publishVolumeStatus(ctx, &status)
				updateVolumeRefStatus(ctx, &status)
				if err := createOrUpdateAppDiskMetrics(ctx, &status); err != nil {
					log.Errorf("updateVolumeStatus(%s): exception while publishing diskmetric. %s",
						status.Key(), err.Error())
				}
			}
		}
	}
	if !found {
		log.Warnf("XXX updateVolumeStatusFromContentID(%s) NOT FOUND", contentID)
	}
}
