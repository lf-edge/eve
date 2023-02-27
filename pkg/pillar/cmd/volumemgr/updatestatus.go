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
	"github.com/lf-edge/eve/pkg/pillar/volumehandlers"
	uuid "github.com/satori/go.uuid"
)

// doUpdate handles any updates to a VolumeStatus, called by any event handlers
// that either capture a VolumeStatus change or create one and want it processed.
// Returns changed
// XXX remove "done" boolean return?
func doUpdateContentTree(ctx *volumemgrContext, status *types.ContentTreeStatus) (bool, bool) {

	log.Functionf("doUpdateContentTree(%s) name %s state %s", status.Key(), status.DisplayName, status.State)

	changed := false
	addedBlobs := []string{}

	if status.State < types.VERIFIED {
		if !status.AllDatastoresResolved {
			log.Functionf("contentTreeStatus(%s) does not have a datastore type yet, deferring", status.ContentID)
			return false, false
		}

		if status.IsOCIRegistry {
			if len(status.DatastoreIDList) > 1 {
				err := fmt.Sprintf("doUpdateContentTree(%s) name %s: OCI registry along with the fallback datastores list is not supported",
					status.Key(), status.DisplayName)
				log.Errorf(err)
				status.SetErrorDescription(types.ErrorDescription{Error: err})
				changed = true
				return changed, false
			}

			maybeLatchContentTreeHash(ctx, status)
			if status.ContentSha256 == "" {
				rs := lookupResolveStatus(ctx, status.ResolveKey())
				if rs == nil {
					log.Functionf("Resolve status not found for %s",
						status.ContentID)
					status.HasResolverRef = true
					MaybeAddResolveConfig(ctx, *status)
					status.State = types.RESOLVING_TAG
					changed = true
					return changed, false
				}
				log.Functionf("Processing ResolveStatus for content tree (%v)", status.ContentID)
				changed = true
				if rs.HasError() {
					errStr := fmt.Sprintf("Received error from resolver for %s, SHA (%s): %s",
						status.ResolveKey(), rs.ImageSha256, rs.Error)
					log.Error(errStr)
					status.SetErrorWithSourceAndDescription(rs.ErrorDescription, types.ResolveStatus{})
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
					log.Functionf("Clearing resolver error %s", status.Error)
					status.ClearErrorWithSource()
					changed = true
				}
				foundSha := strings.ToLower(rs.ImageSha256)
				log.Functionf("Added Image SHA (%s) for content tree (%s)",
					foundSha, status.ContentID)
				status.State = types.RESOLVED_TAG
				status.ContentSha256 = foundSha
				status.HasResolverRef = false
				status.RelativeURL = utils.MaybeInsertSha(status.RelativeURL, status.ContentSha256)
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
					DatastoreIDList:        status.DatastoreIDList,
					RelativeURL:            status.RelativeURL,
					Sha256:                 status.ContentSha256,
					Size:                   status.MaxDownloadSize,
					State:                  types.INITIAL,
					CreateTime:             time.Now(),
					LastRefCountChangeTime: time.Now(),
				}
				log.Functionf("doUpdateContentTree: publishing new root BlobStatus (%s) for content tree (%s)",
					status.ContentSha256, status.ContentID)
				publishBlobStatus(ctx, rootBlob)
			} else if rootBlob.State == types.LOADED {
				//Need to update DatastoreIDList and RelativeURL if the blob is already loaded into CAS,
				// because if any child blob is not downloaded, then we would need the below data.
				rootBlob.DatastoreIDList = status.DatastoreIDList
				rootBlob.RelativeURL = status.RelativeURL
				log.Functionf("doUpdateContentTree: publishing loaded root BlobStatus (%s) for content tree (%s)",
					status.ContentSha256, status.ContentID)
				publishBlobStatus(ctx, rootBlob)
			}
			if len(status.Blobs) == 0 {
				AddBlobsToContentTreeStatus(ctx, status, rootBlob.Sha256)
			}
		} else {
			// Not an OCI registry, thus must have a valid sha256
			if status.ContentSha256 == "" {
				err := fmt.Sprintf("doUpdateContentTree(%s) name %s: no content sha256 defined",
					status.Key(), status.DisplayName)
				log.Errorf(err)
				status.SetErrorDescription(types.ErrorDescription{Error: err})
				changed = true
				return changed, false
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
			currentSize, totalSize, manifestTotalSize int64
			blobErrors                                []string
			blobRetryCondition                        string //propagate only one
			blobErrorEntities                         []*types.ErrorEntity
			blobErrorSeverity                         types.ErrorSeverity
			blobErrorTime                             time.Time
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
				log.Tracef("doUpdateContentTree: blob sha %s download state %v less than DOWNLOADED", blob.Sha256, blob.State)
				if downloadBlob(ctx, blob) {
					publishBlobStatus(ctx, blob)
					changed = true
				}
			}
			if blob.State == types.DOWNLOADED || blob.State == types.VERIFYING {
				// downloaded: kick off verifier for this blob
				log.Functionf("doUpdateContentTree: blob sha %s download state %v less than VERIFIED", blob.Sha256, blob.State)
				if verifyBlob(ctx, blob) {
					publishBlobStatus(ctx, blob)
					changed = true
				}
			}
			if blob.State < types.VERIFIED {
				leftToProcess = true
				log.Tracef("doUpdateContentTree: left to process due to state '%s' for content blob %s",
					blob.State, blob.Sha256)
			} else {
				log.Tracef("doUpdateContentTree: blob sha %s download state VERIFIED", blob.Sha256)
				// if verified, check for any children and start them off
				blobChildren := blobsNotInList(getBlobChildren(ctx, blob), status.Blobs)
				if len(blobChildren) > 0 {
					log.Functionf("doUpdateContentTree: adding %d children", len(blobChildren))
					// add all of the children
					for _, blob := range blobChildren {
						addedBlobs = append(addedBlobs, blob.Sha256)
					}
					// only publish those that do not already exist
					publishBlobStatus(ctx, blobsNotInStatusOrCreate(ctx, blobChildren)...)
					AddBlobsToContentTreeStatus(ctx, status, addedBlobs...)
				}
				if blob.IsManifest() {
					manifestTotalSize = resolveManifestSize(ctx, *blob)
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
				if blob.ErrorSeverity > blobErrorSeverity {
					blobErrorSeverity = blob.ErrorSeverity
				}
				if blob.ErrorRetryCondition != "" {
					blobRetryCondition = blob.ErrorRetryCondition
				}
				blobErrorEntities = append(blobErrorEntities, &types.ErrorEntity{EntityID: blob.Sha256, EntityType: types.ErrorEntityContentBlob})

				leftToProcess = true
			}
		}

		// The manifestTotalSize does not include the size of the
		// manifest itself but we set it as an initial approximation
		if totalSize < manifestTotalSize {
			log.Functionf("doUpdateContentTree: manifestTotal %d total %d",
				manifestTotalSize, totalSize)
			totalSize = manifestTotalSize
		}
		// Check if sizes changed before setting changed
		if status.CurrentSize != currentSize || status.TotalSize != totalSize {
			changed = true
			status.CurrentSize = currentSize
			status.TotalSize = totalSize
			if status.TotalSize > 0 {
				status.Progress = uint(100 * status.CurrentSize / status.TotalSize)
			}
			log.Functionf("doUpdateContentTree: updating CurrentSize/TotalSize/Progress %d/%d/%d",
				currentSize, totalSize, status.Progress)
		}

		if len(status.Blobs) == 0 {
			log.Errorf("doUpdateContentTree(%s) name %s: blobs array is empty",
				status.Key(), status.DisplayName)
			return changed, false
		}
		rootBlob := lookupOrCreateBlobStatus(ctx, status.Blobs[0])
		if rootBlob == nil {
			log.Errorf("doUpdateContentTree(%s) name %s: could not find BlobStatus(%s)",
				status.Key(), status.DisplayName, status.Blobs[0])
			return changed, false
		}
		if status.FileLocation != rootBlob.Path {
			log.Functionf("doUpdateContentTree(%s) name %s: updating file location to %s",
				status.Key(), status.DisplayName, rootBlob.Path)
			status.FileLocation = rootBlob.Path
			changed = true
		}

		// update errors from blobs to status
		if len(blobErrors) != 0 {
			if blobRetryCondition == "" {
				// if we cannot find any retry condition, it is an error
				blobErrorSeverity = types.ErrorSeverityError
			}
			errDescription := types.ErrorDescription{
				Error:               strings.Join(blobErrors, " / "),
				ErrorRetryCondition: blobRetryCondition,
				ErrorSeverity:       blobErrorSeverity,
				ErrorEntities:       blobErrorEntities,
				ErrorTime:           blobErrorTime,
			}
			status.SetErrorDescription(errDescription)
			log.Functionf("doUpdateContentTree(%s) had errors: %v", status.Key(), status.Error)
			changed = true
		} else if status.HasError() {
			log.Functionf("doUpdateContentTree(%s) clearing errors", status.Key())
			status.ClearErrorWithSource()
			changed = true
		}

		// if we added any blobs, we need to reprocess this
		if len(addedBlobs) > 0 {
			log.Functionf("doUpdateContentTree(%s) rerunning with added blobs: %v", status.Key(), addedBlobs)
			return doUpdateContentTree(ctx, status)
		}

		// if there are any left to process, do not do anything else
		// the rest of this flow should happen only when every part of the content tree
		// is downloaded and verified
		if leftToProcess {
			log.Functionf("doUpdateContentTree(%s) leftToProcess=true, so returning `true,false`", status.Key())
			return true, false
		}

		blobStatuses := lookupBlobStatuses(ctx, status.Blobs...)
		refID := status.ReferenceID()

		// if we just had an image pointing to a single blob that is not index or manifest, we need
		// to add a manifest to it.
		log.Functionf("doUpdateContentTree(%s) checking if we need to add a manifest, have %d blobs", status.Key(), len(blobStatuses))
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
		log.Functionf("doUpdateContentTree(%s): all blobs verified %v, setting ContentTree state to VERIFIED", status.Key(), status.Blobs)
		status.State = types.VERIFIED
		publishContentTreeStatus(ctx, status)
	}

	// at this point, the image is VERIFIED or higher
	if status.State == types.VERIFIED {
		// we need to check root blob state to wait for another loading process if exists
		blobStatuses := lookupBlobStatuses(ctx, status.Blobs...)
		root := blobStatuses[0]
		if root.State == types.LOADING {
			log.Functionf("Found root blob %s in LOADING; defer", root.Key())
			return changed, false
		}
		for _, b := range blobStatuses {
			if b.State == types.VERIFIED {
				b.State = types.LOADING
				publishBlobStatus(ctx, b)
			}
		}

		log.Functionf("doUpdateContentTree(%s): ContentTree state is VERIFIED, starting LOADING", status.Key())

		// now we start loading
		// it is a bit silly to publish twice, but it is important that we keep the audit
		// trail that the image was verified, and now is loading
		status.State = types.LOADING
		publishContentTreeStatus(ctx, status)

		AddWorkLoad(ctx, status)

		return changed, false
	}

	// if it is LOADING, check each blob until all are loaded
	if status.State == types.LOADING {
		log.Functionf("doUpdateContentTree(%s): ContentTree status is LOADING", status.Key())
		// get the work result - see if it succeeded
		wres := popCasIngestWorkResult(ctx, status.Key())
		if wres != nil {
			log.Functionf("doUpdateContentTree(%s): IngestWorkResult found", status.Key())
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
				log.Functionf("doUpdateContentTree(%s): blob %s not yet loaded", status.Key(), blob.Sha256)
				leftToProcess++
				continue
			}

			log.Functionf("doUpdateContentTree(%s): Successfully loaded blob: %s", status.Key(), blob.Sha256)
			if blob.HasDownloaderRef {
				log.Functionf("doUpdateContentTree(%s): removing downloaderRef from Blob %s",
					status.Key(), blob.Sha256)
				MaybeRemoveDownloaderConfig(ctx, blob.Sha256)
				blob.HasDownloaderRef = false
			}
			if blob.HasVerifierRef {
				log.Functionf("doUpdateContentTree(%s): removing verifyRef from Blob %s",
					status.Key(), blob.Sha256)
				MaybeRemoveVerifyImageConfig(ctx, blob.Sha256)
				// Set the path to "" as we delete the verifier path
				blob.HasVerifierRef = false
				blob.Path = ""
			}
			publishBlobStatus(ctx, blob)
		}
		if leftToProcess > 0 {
			log.Functionf("doUpdateContentTree(%s): Still have %d blobs left to load", status.Key(), leftToProcess)
			return changed, false
		}

		// if we made it here, then all blobs were loaded
		log.Functionf("doUpdateContentTree(%s) successfully loaded all blobs into CAS", status.Key())

		// check if the image was created
		if !lookupImageCAS(status.ReferenceID(), ctx.casClient) {
			log.Functionf("doUpdateContentTree(%s): image does not yet exist in CAS", status.Key())
			return changed, false
		}
		log.Functionf("doUpdateContentTree(%s): image exists in CAS, Content Tree load is completely LOADED", status.Key())
		status.State = types.LOADED
		status.CreateTime = time.Now()
		// ContentTreeStatus.FileLocation has no meaning once everything is loaded
		status.FileLocation = ""

		changed = true
	}

	return changed, status.State == types.LOADED
}

// Returns changed
// XXX remove "done" boolean return?
func doUpdateVol(ctx *volumemgrContext, status *types.VolumeStatus) (bool, bool) {

	var changed bool

	log.Functionf("doUpdateVol(%s) name %s", status.Key(), status.DisplayName)

	// Anything to do?
	if status.State == types.CREATED_VOLUME {
		log.Functionf("doUpdateVol(%s) name %s nothing to do",
			status.Key(), status.DisplayName)
		return false, true
	}

	verifyOnly := false
	vrc := lookupVolumeRefConfig(ctx, status.Key())
	if vrc != nil {
		verifyOnly = vrc.VerifyOnly
	} else {
		vc := ctx.LookupVolumeConfig(status.Key())
		if vc != nil && !vc.HasNoAppReferences {
			log.Functionf("doUpdateVol(%s) name %s has app references but no VolumeRefConfig found",
				status.Key(), status.DisplayName)
			// we have no ref config, so no information about its intent
			verifyOnly = true
		}
	}

	// do not go into CREATING_VOLUME state if no space available
	// skip this check for verifyOnly to not block purging
	if !verifyOnly && status.State < types.CREATING_VOLUME && !ctx.globalConfig.GlobalValueBool(types.IgnoreDiskCheckForApps) {
		// Check disk usage
		remaining, err := getRemainingDiskSpace(ctx)
		if err != nil {
			description := types.ErrorDescription{}
			description.Error = fmt.Sprintf("getRemainingDiskSpace failed: %s\n", err)
			// do not touch time of the error with the same content
			if status.Error != description.Error {
				status.SetErrorWithSourceAndDescription(description, types.DiskMetric{})
			}
			changed = true
			return changed, false
		} else if remaining < status.MaxVolSize {
			description := types.ErrorDescription{}
			description.Error = fmt.Sprintf("Remaining disk space %d volume needs %d\n",
				remaining, status.MaxVolSize)
			description.ErrorRetryCondition = "Will retry when more space will be available"
			// do not touch time of the error with the same content
			if status.Error != description.Error {
				status.SetErrorWithSourceAndDescription(description, types.DiskMetric{})
			}
			changed = true
			return changed, false
		}
	}

	if status.IsErrorSource(types.DiskMetric{}) {
		log.Functionf("doUpdateVol: Clearing DiskMetric error %s", status.Error)
		status.ClearErrorWithSource()
		changed = true
	}

	switch status.VolumeContentOriginType {
	case zconfig.VolumeContentOriginType_VCOT_BLANK:
		if status.MaxVolSize == 0 {
			errorStr := fmt.Sprintf("doUpdateVol (%s): Cannot create volume with 0 size",
				status.Key())
			log.Error(errorStr)
			status.SetErrorWithSource(errorStr,
				types.VolumeStatus{}, time.Now())
			changed = true
			return changed, false
		}
		if status.State < types.CREATING_VOLUME &&
			status.SubState == types.VolumeSubStateInitial {
			// we should not verify empty volume
			if verifyOnly {
				if status.State != types.LOADED {
					status.State = types.LOADED
					changed = true
				}
				return changed, false
			}
			status.State = types.CREATING_VOLUME
			status.ReferenceName = "" //set empty for blank volume
			status.ContentFormat = blankVolumeFormat
			status.TotalSize = int64(status.MaxVolSize)
			status.CurrentSize = int64(status.MaxVolSize)
			changed = true
			// Asynch preparation; ensure we have requested it
			AddWorkPrepare(ctx, status)
			return changed, false
		}
	case zconfig.VolumeContentOriginType_VCOT_DOWNLOAD:
		ctStatus := ctx.LookupContentTreeStatus(status.ContentID.String())
		if ctStatus == nil {
			// Content tree not yet available
			log.Errorf("doUpdateVol(%s) name %s: waiting for content tree status %v",
				status.Key(), status.DisplayName, status.ContentID)
			return changed, false
		}
		if status.IsErrorSource(types.ContentTreeStatus{}) {
			log.Functionf("doUpdate: Clearing volume error %s", status.Error)
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
		if status.State != ctStatus.State && status.State < types.CREATING_VOLUME {
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
				description := ctStatus.ErrorDescription
				description.Error = errStr
				description.ErrorEntities = []*types.ErrorEntity{{EntityID: ctStatus.ContentID.String(), EntityType: types.ErrorEntityContentTree}}
				status.SetErrorWithSourceAndDescription(description, types.ContentTreeStatus{})
				changed = true
				return changed, false
			}
			log.Functionf("doUpdateVol(%s) name %s: waiting for content tree status %v to be LOADED",
				status.Key(), status.DisplayName, ctStatus.DisplayName)
			return changed, false
		}
		if ctStatus.State == types.LOADED &&
			status.State != types.CREATING_VOLUME &&
			status.SubState == types.VolumeSubStateInitial {

			_, err := ctx.casClient.GetImageHash(ctStatus.ReferenceID())
			if err != nil {
				log.Functionf("doUpdateVol(%s): waiting for image create: %s", status.Key(), err.Error())
				return changed, false
			}

			// we are done if verifyOnly set
			if verifyOnly {
				if status.State != types.LOADED {
					status.State = types.LOADED
					changed = true
				}
				return changed, false
			}

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
			// Asynch preparation; ensure we have requested it
			AddWorkPrepare(ctx, status)
			return changed, false
		}
		if status.IsErrorSource(types.ContentTreeStatus{}) {
			log.Functionf("doUpdate: Clearing volume error %s", status.Error)
			status.ClearErrorWithSource()
			changed = true
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
	if status.State == types.CREATING_VOLUME && status.SubState == types.VolumeSubStateInitial {
		vr := popVolumePrepareResult(ctx, status.Key())
		if vr != nil {
			log.Functionf("doUpdateVol: VolumePrepareResult(%s)", status.Key())
			if vr.Error != nil {
				log.Errorf("doUpdateVol: Error received from the volume prepare worker %v",
					vr.Error)
				status.SetErrorWithSource(vr.Error.Error(),
					types.VolumeStatus{}, vr.ErrorTime)
				changed = true
				return changed, false
			} else if status.IsErrorSource(types.VolumeStatus{}) {
				log.Functionf("doUpdateVol: Clearing volume error %s", status.Error)
				status.ClearErrorWithSource()
				changed = true
			}
			status.SubState = types.VolumeSubStatePreparing
			changed = true
		} else {
			log.Functionf("doUpdateVol: VolumePrepareResult(%s) not found", status.Key())
		}
	}
	if status.State == types.CREATING_VOLUME && status.SubState == types.VolumeSubStatePreparing {
		prepared, err := volumehandlers.GetVolumeHandler(log, ctx, status).HandlePrepared()
		if err != nil {
			log.Errorf("doUpdateVol(%s) name %s: %v",
				status.Key(), status.DisplayName, err)
			status.SetErrorWithSource(err.Error(), types.VolumeStatus{}, time.Now())
			changed = true
			return changed, false
		}
		if !prepared {
			return changed, false
		}
		status.SubState = types.VolumeSubStatePrepareDone
		changed = true
		//prepare work done
		DeleteWorkPrepare(ctx, status)
		// Asynch creation; ensure we have requested it
		AddWorkCreate(ctx, status)
		return changed, false
	}
	if status.State == types.CREATING_VOLUME && status.SubState == types.VolumeSubStatePrepareDone {
		vr := popVolumeWorkResult(ctx, status.Key())
		if vr != nil {
			log.Functionf("doUpdateVol: VolumeWorkResult(%s) location %s, created %t",
				status.Key(), vr.FileLocation, vr.VolumeCreated)
			if vr.VolumeCreated && status.SubState == types.VolumeSubStatePrepareDone {
				log.Functionf("From vr set VolumeCreated to %s for %s",
					vr.FileLocation, status.Key())
				status.SubState = types.VolumeSubStateCreated
				status.CreateTime = vr.CreateTime
				changed = true
			}
			if status.FileLocation != vr.FileLocation && vr.Error == nil {
				log.Functionf("doUpdateContentTree: From vr set FileLocation to %s for %s",
					vr.FileLocation, status.Key())
				status.FileLocation = vr.FileLocation
				changed = true
			}
			if vr.Error != nil {
				log.Errorf("doUpdate: Error received from the volume worker %v",
					vr.Error)
				status.SetErrorWithSource(vr.Error.Error(),
					types.VolumeStatus{}, vr.ErrorTime)
				changed = true
				return changed, false
			} else if status.IsErrorSource(types.VolumeStatus{}) {
				log.Functionf("doUpdateContentTree: Clearing volume error %s", status.Error)
				status.ClearErrorWithSource()
				changed = true
			}
		} else {
			log.Functionf("doUpdateVol: VolumeWorkResult(%s) not found", status.Key())
		}
	}
	if status.State == types.CREATING_VOLUME && status.SubState == types.VolumeSubStateCreated {
		created, err := volumehandlers.GetVolumeHandler(log, ctx, status).HandleCreated()
		if err != nil {
			log.Errorf("doUpdateVol(%s) name %s: %v",
				status.Key(), status.DisplayName, err)
			status.SetErrorWithSource(err.Error(), types.VolumeStatus{}, time.Now())
			changed = true
			return changed, false
		}
		if !created {
			return changed, false
		}
		if !status.HasError() {
			status.State = types.CREATED_VOLUME
			status.CreateTime = time.Now()
		}
		changed = true
		// Work is done
		DeleteWorkCreate(ctx, status)
	}
	return changed, false
}

// updateStatus updates all VolumeStatus/ContentTreeStatus which include a blob
// that has Sha256 from sha slice
func updateStatusByBlob(ctx *volumemgrContext, sha ...string) {

	log.Functionf("updateStatusByBlob(%s)", sha)
	found := false
	pub := ctx.pubContentTreeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.ContentTreeStatus)
		var hasSha bool
	blobLoop:
		for _, blobSha := range status.Blobs {
			for _, s := range sha {
				if blobSha == s {
					log.Tracef("Found blob %s on ContentTreeStatus %s",
						sha, status.Key())
					hasSha = true
					break blobLoop
				}
			}
		}
		if hasSha {
			found = true
			if changed, _ := doUpdateContentTree(ctx, &status); changed {
				log.Functionf("updateStatusByBlob(%s) publishing ContentTreeStatus",
					status.Key())
				publishContentTreeStatus(ctx, &status)
			}
			// Volume status referring to this content UUID needs to get updated
			log.Functionf("updateStatusByBlob(%s) updating volume status from content ID %v",
				status.Key(), status.ContentID)
			updateVolumeStatusFromContentID(ctx,
				status.ContentID)
		}
	}
	if !found {
		log.Warnf("XXX updateStatusByBlob(%s) NOT FOUND", sha)
	}
}

// setDatastoreTypeByID() - sets datastore type looking for a matching datastore by
//
//	an ID. Returns 'true' if status was changed
func setDatastoreTypeByID(ds types.DatastoreConfig, status *types.ContentTreeStatus) bool {
	nr := len(status.DatastoreIDList)
	found := false
	nrResolved := 0

	// Find datastore by an ID and count resolved datastores
	for i, dsid := range status.DatastoreIDList {
		tptr := &status.DatastoreTypesList[i]

		// Assign a type if datastores's ID matches
		if dsid == ds.UUID {
			found = true
			*tptr = ds.DsType

			// OCI registry is special, so mark the whole status if there is any
			if ds.DsType == zconfig.DsType_DsContainerRegistry.String() {
				status.IsOCIRegistry = true
			}

			log.Functionf("Setting datastore type %s for datastore %s on ContentTreeStatus %s",
				ds.DsType, ds.UUID, status.Key())
		}

		// Account resolved datastore
		if *tptr != "" {
			nrResolved++
		}
	}
	allResolved := (nrResolved == nr)
	changed := (found || status.AllDatastoresResolved != allResolved)
	status.AllDatastoresResolved = allResolved

	return changed
}

// updateStatusByDatastore update any datastore missing status
func updateStatusByDatastore(ctx *volumemgrContext, datastore types.DatastoreConfig) {
	log.Functionf("updateStatusByDatastore(%s)", datastore.UUID)
	pub := ctx.pubContentTreeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.ContentTreeStatus)

		changed := setDatastoreTypeByID(datastore, &status)
		if !changed {
			continue
		}
		doUpdateContentTree(ctx, &status)
		log.Errorf("updateStatusByDatastore(%s) publishing ContentTreeStatus",
			status.Key())
		publishContentTreeStatus(ctx, &status)

		// Volume status referring to this content UUID needs to get updated
		log.Functionf("updateStatusByDatastore(%s) updating volume status from content ID %v",
			status.Key(), status.ContentID)
		updateVolumeStatusFromContentID(ctx,
			status.ContentID)
	}
}

func updateContentTreeStatus(ctx *volumemgrContext, contentSha256 string, contentID uuid.UUID) {

	log.Functionf("updateContentTreeStatus(%s)", contentID)
	found := false
	pub := ctx.pubContentTreeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.ContentTreeStatus)
		if status.ContentSha256 == contentSha256 {
			log.Functionf("Found ContentTreeStatus %s",
				status.Key())
			found = true
			changed, _ := doUpdateContentTree(ctx, &status)
			if changed {
				publishContentTreeStatus(ctx, &status)
			}
			// Volume status referring to this content UUID needs to get updated
			log.Functionf("updateContentTreeStatus(%s) updating volume status from content ID %v",
				status.Key(), status.ContentID)
			updateVolumeStatusFromContentID(ctx,
				status.ContentID)
		}
	}
	if !found {
		log.Warnf("XXX updateContentTreeStatus(%s) NOT FOUND", contentID)
	}
}

// Find all the VolumeStatus which refer to this volume uuid
// returns false if not found any
func updateVolumeStatus(ctx *volumemgrContext, volumeID uuid.UUID) bool {

	log.Functionf("updateVolumeStatus for %s", volumeID)
	found := false
	pub := ctx.pubVolumeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.VolumeStatus)
		if status.VolumeID == volumeID {
			log.Functionf("Found VolumeStatus %s: name %s",
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
	return found
}

// Find all the VolumeStatus which refer to this content uuid
func updateVolumeStatusFromContentID(ctx *volumemgrContext, contentID uuid.UUID) {

	log.Tracef("updateVolumeStatusFromContentID for %s", contentID)
	found := false
	pub := ctx.pubVolumeStatus
	items := pub.GetAll()
	for _, st := range items {
		status := st.(types.VolumeStatus)
		if status.ContentID == contentID {
			log.Tracef("Found VolumeStatus %s: name %s",
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
