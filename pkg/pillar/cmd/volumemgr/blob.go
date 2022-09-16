// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// downloadBlob download a blob from a content tree
// returns whether or not the BlobStatus has changed
func downloadBlob(ctx *volumemgrContext, blob *types.BlobStatus) bool {

	changed := false
	// Make sure we kick the downloader and have a refcount
	if !blob.HasDownloaderRef {
		if !ctx.globalConfig.GlobalValueBool(types.IgnoreDiskCheckForApps) {
			// Check disk usage
			remaining, err := getRemainingDiskSpace(ctx)
			if err != nil {
				errStr := fmt.Sprintf("getRemainingDiskSpace failed: %s\n",
					err)
				blob.SetError(errStr, time.Now())
				return true
			} else if remaining < blob.Size {
				errStr := fmt.Sprintf("Remaining disk space %d blob needs %d\n",
					remaining, blob.Size)
				blob.SetError(errStr, time.Now())
				return true
			}
		}
		AddOrRefcountDownloaderConfig(ctx, *blob)
		blob.HasDownloaderRef = true
		changed = true
	}
	// Check if we have a DownloadStatus if not put a DownloadConfig
	// in place
	ds := lookupDownloaderStatus(ctx, blob.Sha256)

	// we do not have one, or it is expired or not referenced, then
	// the one we just created is it; set our State to DOWNLOADING and return
	if ds == nil || ds.Expired || ds.RefCount == 0 {
		if ds == nil {
			log.Tracef("downloadStatus not found for blob %s", blob.Sha256)
		} else if ds.Expired {
			log.Tracef("downloadStatus Expired set for blob %s", blob.Sha256)
		} else {
			log.Tracef("downloadStatus RefCount=0 for blob %s", blob.Sha256)
		}
		blob.State = types.DOWNLOADING
		return true
	}

	// we have a valid & non-expired & refcounted DownloadStatus
	// make sure the blob path matches the target path
	if ds.Target != "" && blob.Path == "" {
		blob.Path = ds.Target
		changed = true
		log.Functionf("From ds set FileLocation to %s for blob %s",
			ds.Target, blob.Sha256)
	}

	// make sure the blob state matches the actual state
	if blob.State != ds.State {
		blob.State = ds.State
		changed = true
	}
	if blob.TotalSize != ds.TotalSize ||
		blob.CurrentSize != ds.CurrentSize ||
		blob.Size != ds.Size {
		blob.Size = ds.Size
		blob.TotalSize = ds.TotalSize
		blob.CurrentSize = ds.CurrentSize
		if blob.TotalSize > 0 {
			blob.Progress = uint(100 * blob.CurrentSize / blob.TotalSize)
		}
		changed = true
	}
	if ds.Pending() {
		log.Tracef("lookupDownloaderStatus Pending for blob %s", blob.Sha256)
		return changed
	}
	if ds.HasError() {
		log.Errorf("Received error from downloader for blob %s: %s",
			blob.Sha256, ds.Error)
		blob.SetErrorWithSourceAndDescription(ds.ErrorDescription, types.DownloaderStatus{})
		changed = true
		return changed
	}
	if blob.IsErrorSource(types.DownloaderStatus{}) {
		log.Functionf("Clearing downloader error %s", blob.Error)
		blob.ClearErrorWithSource()
		changed = true
	}

	// At this point, we have a valid DownloadStatus, the BlobStatus state and path
	// are matched up to the DownloadStatus.
	// Process the actual state to move to the next stage.
	switch ds.State {
	case types.INITIAL:
		// Nothing to do
	case types.DOWNLOADING:
		// Nothing to do
	case types.DOWNLOADED:
		// signal verifier to start if it hasn't already; add RefCount
		if verifyBlob(ctx, blob) {
			changed = true
		}
	}
	log.Functionf("downloadBlob(%s) complete", blob.Sha256)
	return changed
}

//AddRefToBlobStatus adds the refObject as an reference to the blobs in the given blob list.
func AddRefToBlobStatus(ctx *volumemgrContext, blobStatus ...*types.BlobStatus) {
	for _, blob := range blobStatus {
		blob.RefCount++
		blob.LastRefCountChangeTime = time.Now()
		log.Functionf("AddRefToBlobStatus: RefCount to %d for Blob %s",
			blob.RefCount, blob.Sha256)
		publishBlobStatus(ctx, blob)
	}
}

//RemoveRefFromBlobStatus removes the reference from the blobs in the given blob list.
func RemoveRefFromBlobStatus(ctx *volumemgrContext, blobStatus ...*types.BlobStatus) {
	for _, blob := range blobStatus {
		if blob.RefCount == 0 {
			log.Fatalf("RemoveRefFromBlobStatus: Attempting to reduce 0 Refcount for blob %s ", blob.Sha256)
		}
		blob.RefCount--
		blob.LastRefCountChangeTime = time.Now()
		log.Functionf("RemoveRefFromBlobStatus: RefCount to %d for Blob %s",
			blob.RefCount, blob.Sha256)
		if blob.RefCount == 0 {
			log.Functionf("RemoveRefFromBlobStatus: unpublishing Blob %s since no object is referring it.",
				blob.Sha256)
			unpublishBlobStatus(ctx, blob)
			// blob potentially deleted
			continue
		}
		publishBlobStatus(ctx, blob)
	}
}

// updateBlobFromVerifyImageStatus updates a BlobStatus from a VerifyImageStatus.
// Returns whether or not the BlobStatus was changed
func updateBlobFromVerifyImageStatus(vs *types.VerifyImageStatus, blob *types.BlobStatus) bool {
	changed := false
	// blob State must be at least the VerifyImageStatus state
	if blob.State < vs.State {
		blob.State = vs.State
		changed = true
	}

	// check for errors on the VerifyImageStatus
	if vs.HasError() {
		log.Errorf("updateBlobFromVerifyImageStatus(%s): VerifyImageStatus had error %v", blob.Sha256, vs.Error)
		blob.SetErrorWithSource(vs.Error, types.VerifyImageStatus{}, vs.ErrorTime)
		return true
	} else if blob.IsErrorSource(types.VerifyImageStatus{}) {
		log.Functionf("updateBlobFromVerifyImageStatus(%s): Clearing verifier error %s", blob.Sha256, blob.Error)
		blob.ClearErrorWithSource()
		changed = true
	}

	if vs.Pending() {
		log.Functionf("updateBlobFromVerifyImageStatus(%s): VerifyImageStatus pending", blob.Sha256)
		return changed
	}
	if blob.Path != vs.FileLocation {
		blob.Path = vs.FileLocation
		log.Functionf("updateBlobFromVerifyImageStatus(%s): updating Path to %s", blob.Sha256, blob.Path)
		changed = true
	}

	return changed
}

// verifyBlob verify a blob, or latch onto an existing VerifyImageStatus.
// First, check if a VerifyImageStatus exists. If so, check HasVerifierRef,
// potentially incrementing creating or incrementing the refcount on a
// VerifyImageConfig to trigger the generation of a VerifyImageStatus.
// returns if the BlobStatus was changed, and thus would require publishing
func verifyBlob(ctx *volumemgrContext, blob *types.BlobStatus) bool {
	changed := false

	// save the blob type if needed
	if blob.MediaType == "" {
		ds := lookupDownloaderStatus(ctx, blob.Sha256)
		if ds != nil && setBlobTypeFromContentType(blob, ds.ContentType) {
			changed = true
		}
	}

	// A: try to use an existing VerifyImageStatus
	vs := lookupVerifyImageStatus(ctx, blob.Sha256)
	if vs != nil && !vs.Expired {
		log.Functionf("verifyBlob(%s): found VerifyImageStatus", blob.Sha256)
		changed = updateBlobFromVerifyImageStatus(vs, blob)

		// if we do not reference it, increment the refcount
		if startBlobVerification(ctx, blob) {
			changed = true
		}

		return changed
	}

	// B: No VerifyImageStatus so just create it
	if blob.State < types.VERIFYING {
		blob.State = types.VERIFYING
		changed = true
	}
	if startBlobVerification(ctx, blob) {
		changed = true
	}
	return changed
}

// startBlobVerification kick off verification of a blob, or increment the refcount.
// Used only in verifyBlob, but repetitive, so a separate utility function
func startBlobVerification(ctx *volumemgrContext, blob *types.BlobStatus) bool {
	changed := false
	if blob.HasVerifierRef {
		return false
	}
	done, errorAndTime := MaybeAddVerifyImageConfigBlob(ctx, *blob)
	if done {
		blob.HasVerifierRef = true
		return true
	}
	// if errors, set the certError flag
	// otherwise, mark as waiting for certs
	if errorAndTime.HasError() {
		blob.SetError(errorAndTime.Error, errorAndTime.ErrorTime)
		changed = true
	}
	return changed
}

// getBlobChildren get the children of a blob
func getBlobChildren(ctx *volumemgrContext, blob *types.BlobStatus) []*types.BlobStatus {
	log.Tracef("getBlobChildren(%s)", blob.Sha256)
	if blob.State < types.VERIFIED {
		return nil
	}
	log.Tracef("getBlobChildren(%s): VERIFIED", blob.Sha256)
	// if verified, check for any children and start them off
	switch {
	case blob.IsIndex():
		log.Functionf("getBlobChildren(%s): is an index, looking for manifest", blob.Sha256)
		// resolve to our platform-specific one
		manifest, err := resolveIndex(ctx, blob)
		if err != nil {
			log.Errorf("getBlobChildren(%s): error resolving index to manifest: %v", blob.Sha256, err)
			blob.SetError(err.Error(), time.Now())
			return nil
		}
		if manifest == nil {
			log.Errorf("getBlobChildren(%s): has no manifest", blob.Sha256)
			blob.SetError("no manifest found for this platform", time.Now())
			return nil
		}
		log.Functionf("getBlobChildren(%s): adding manifest %s", blob.Sha256, manifest.Digest.Hex)
		childHash := strings.ToLower(manifest.Digest.Hex)
		//Check if childBlob already exists
		existingChild := lookupOrCreateBlobStatus(ctx, childHash)
		if existingChild == nil {
			return []*types.BlobStatus{
				{
					DatastoreID:            blob.DatastoreID,
					RelativeURL:            replaceSha(blob.RelativeURL, manifest.Digest),
					Sha256:                 strings.ToLower(manifest.Digest.Hex),
					Size:                   uint64(manifest.Size),
					LastRefCountChangeTime: time.Now(),
					State:                  types.INITIAL,
				},
			}
		} else if existingChild.State == types.LOADED {
			// Need to update DatastoreID and RelativeURL if the blob is already loaded into CAS,
			// because if any child blob is not downloaded already, then we would need the below data.
			existingChild.DatastoreID = blob.DatastoreID
			existingChild.RelativeURL = replaceSha(blob.RelativeURL, manifest.Digest)
		}
		log.Functionf("getBlobChildren(%s): manifest %s already exists.", blob.Sha256, childHash)
		return []*types.BlobStatus{existingChild}

	case blob.IsManifest():
		log.Functionf("getBlobChildren(%s): is a manifest, adding children", blob.Sha256)
		// get all of the parts
		_, children, err := resolveManifestChildren(ctx, blob)
		if err != nil {
			blob.SetError(err.Error(), time.Now())
			return nil
		}
		var blobChildren []*types.BlobStatus
		if len(children) > 0 {
			blobChildren = make([]*types.BlobStatus, 0)
			for _, child := range children {
				childHash := strings.ToLower(child.Digest.Hex)
				//Check if childBlob already exists
				existingChild := lookupOrCreateBlobStatus(ctx, childHash)
				if existingChild != nil {
					log.Tracef("getBlobChildren(%s): child blob %s already exists.", blob.Sha256, childHash)
					blobChildren = append(blobChildren, existingChild)
				} else {
					log.Functionf("getBlobChildren(%s): creating a new BlobStatus for child %s", blob.Sha256, childHash)
					blobChildren = append(blobChildren, &types.BlobStatus{
						DatastoreID:            blob.DatastoreID,
						RelativeURL:            replaceSha(blob.RelativeURL, child.Digest),
						Sha256:                 childHash,
						Size:                   uint64(child.Size),
						State:                  types.INITIAL,
						MediaType:              string(child.MediaType),
						LastRefCountChangeTime: time.Now(),
					})
				}
			}
		}
		return blobChildren
	default:
		return nil
	}
}

// blobsNotInList find any in the first argument slice that are not in the second argument slice
// uses BlobStatus.Sha256 to determine uniqueness
func blobsNotInList(a []*types.BlobStatus, b []string) []*types.BlobStatus {
	if len(a) < 1 || len(b) < 1 {
		return a
	}
	ret := make([]*types.BlobStatus, 0)
	m := map[string]bool{}
	for _, item := range b {
		m[item] = true
	}
	for _, item := range a {
		if _, ok := m[item.Sha256]; !ok {
			ret = append(ret, item)
		}
	}
	return ret
}

// blobsNotInStatusOrCreate find any in the slice that do not already have a BlobStatus,
// but first check if the BlobStatus can be recreated from VerifyImageStatus
func blobsNotInStatusOrCreate(ctx *volumemgrContext, a []*types.BlobStatus) []*types.BlobStatus {
	// if we have none, return none
	if len(a) < 1 {
		return a
	}

	// to hold our return value
	ret := make([]*types.BlobStatus, 0)
	// go through each one, and try to find or create it
	for _, blob := range a {
		found := lookupOrCreateBlobStatus(ctx, blob.Sha256)
		if found == nil {
			ret = append(ret, blob)
		}
	}
	return ret
}

// resolveManifestSize resolve the size of total image for a manifest.
// If the blob is not of type Manifest, return existing size
func resolveManifestSize(ctx *volumemgrContext, blob types.BlobStatus) int64 {
	if !blob.IsManifest() {
		return blob.TotalSize
	}

	size, _, err := resolveManifestChildren(ctx, &blob)
	if err != nil {
		return blob.TotalSize
	}
	return size
}

// lookupBlobStatus look for a BlobStatus. Does not attempt to recreate one
// from VerifyImageStatus
func lookupBlobStatus(ctx *volumemgrContext, blobSha string) *types.BlobStatus {

	if blobSha == "" {
		return nil
	}
	pub := ctx.pubBlobStatus
	s, _ := pub.Get(blobSha)
	if s == nil {
		log.Tracef("lookupBlobStatus(%s) not found", blobSha)
		return nil
	}
	status := s.(types.BlobStatus)
	return &status
}

// lookupOrCreateBlobStatus tries to lookup a BlobStatus. If one is not found,
// and a VerifyImageStatus exists, use that to create the BlobStatus.
func lookupOrCreateBlobStatus(ctx *volumemgrContext, blobSha string) *types.BlobStatus {
	log.Tracef("lookupOrCreateBlobStatus(%s)", blobSha)
	if blobSha == "" {
		return nil
	}
	// Does it already exist?
	blob := lookupBlobStatus(ctx, blobSha)
	if blob != nil {
		return blob
	}
	// need to look for VerifyImageStatus that matches
	log.Functionf("lookupOrCreateBlobStatus(%s) not found, trying VerifyImageStatus",
		blobSha)

	// first see if a VerifyImageStatus exists
	// if it does, then create a BlobStatus with State up to the level of the VerifyImageStatus
	vs := lookupVerifyImageStatus(ctx, blobSha)
	if vs != nil && !vs.Expired {
		log.Functionf("lookupOrCreateBlobStatus(%s) VerifyImageStatus found, creating and publishing BlobStatus", blobSha)
		blob := &types.BlobStatus{
			Sha256:                 blobSha,
			State:                  vs.State,
			Path:                   vs.FileLocation,
			Size:                   uint64(vs.Size),
			CurrentSize:            vs.Size,
			TotalSize:              vs.Size,
			Progress:               100,
			CreateTime:             time.Now(),
			LastRefCountChangeTime: time.Now(),
		}
		updateBlobFromVerifyImageStatus(vs, blob)
		startBlobVerification(ctx, blob)
		publishBlobStatus(ctx, blob)
		return blob
	}
	return nil
}

// lookupBlobStatuses returns a list of pointers.
// It takes care to return the same pointer in the case that a sha is repeated
func lookupBlobStatuses(ctx *volumemgrContext, shas ...string) []*types.BlobStatus {
	ret := []*types.BlobStatus{}
	all := ctx.pubBlobStatus.GetAll()
	// Get BlobStatus pointers for all we care about
	blobPtrs := make(map[string]*types.BlobStatus)
	for _, blobInt := range all {
		blob := blobInt.(types.BlobStatus)
		for _, sha := range shas {
			if sha == blob.Sha256 {
				blobPtrs[blob.Sha256] = &blob
				break
			}
		}
	}
	// Return in order of the input shas
	for _, sha := range shas {
		if blobPtr, ok := blobPtrs[sha]; ok {
			ret = append(ret, blobPtr)
		}
	}
	return ret
}

func publishBlobStatus(ctx *volumemgrContext, blobs ...*types.BlobStatus) {
	for _, blob := range blobs {
		key := blob.Sha256
		log.Tracef("publishBlobStatus(%s)", key)
		ctx.pubBlobStatus.Publish(key, *blob)
	}
}

// unpublishBlobStatus removes any outbound refcounts on Downloader and Verifier
// and gets rid of the blobStatus. Thus the callers must not reuse the blobs
func unpublishBlobStatus(ctx *volumemgrContext, blobs ...*types.BlobStatus) {
	errs := []error{}
	for _, blob := range blobs {
		key := blob.Sha256
		log.Functionf("unpublishBlobStatus(%s)", key)

		// Drop references. Note that we never publish the resulting
		// BlobStatus since we unpublish it below.
		// But the BlobStatus pointer might appear several times in
		// the list hence we better clear the Has*Ref
		if blob.HasDownloaderRef {
			MaybeRemoveDownloaderConfig(ctx, blob.Sha256)
			blob.HasDownloaderRef = false
		}
		if blob.HasVerifierRef {
			MaybeRemoveVerifyImageConfig(ctx, blob.Sha256)
			blob.HasVerifierRef = false
		}
		//If blob is loaded, then remove it from CAS
		if blob.State == types.LOADED {
			if err := ctx.casClient.RemoveBlob(checkAndCorrectBlobHash(blob.Sha256)); err != nil {
				err := fmt.Errorf("unpublishBlobStatus: Exception while removing loaded blob %s: %s",
					blob.Sha256, err.Error())
				log.Errorf(err.Error())
			}
		}

		pub := ctx.pubBlobStatus
		st, _ := pub.Get(key)
		if st == nil {
			errs = append(errs, fmt.Errorf("unpublishBlobStatus(%s) not found", key))
			continue
		}

		pub.Unpublish(key)
	}
	for _, err := range errs {
		log.Errorf("%v", err)
	}
}

//populateInitBlobStatus fetches all blob present in CAS and publishes a BlobStatus for them
func populateInitBlobStatus(ctx *volumemgrContext) {
	blobInfoList, err := ctx.casClient.ListBlobInfo()
	if err != nil {
		log.Errorf("populateInitBlobStatus: exception while fetching existing blobs from CAS: %v", err)
		return
	}
	log.Noticef("populateInitBlobStatus got %d from CAS",
		len(blobInfoList))
	mediaMap, err := ctx.casClient.ListBlobsMediaTypes()
	if err != nil {
		log.Errorf("populateInitBlobStatus: exception while fetching existing media types from CAS: %v", err)
		return
	}
	newBlobStatus := make([]*types.BlobStatus, 0)
	for _, blobInfo := range blobInfoList {
		mediaType, ok := mediaMap[blobInfo.Digest]
		if !ok {
			// if we could not find the media type, we do not know what this blob is, so we ignore it
			log.Functionf("populateInitBlobStatus: blob %s in CAS could not get mediaType", blobInfo.Digest)
			continue
		}
		if lookupBlobStatus(ctx, blobInfo.Digest) == nil {
			log.Functionf("populateInitBlobStatus: Found blob %s in CAS", blobInfo.Digest)
			blobStatus := &types.BlobStatus{
				Sha256:                 strings.TrimPrefix(blobInfo.Digest, "sha256:"),
				Size:                   uint64(blobInfo.Size),
				State:                  types.LOADED,
				MediaType:              mediaType,
				TotalSize:              blobInfo.Size,
				CurrentSize:            blobInfo.Size,
				Progress:               100,
				LastRefCountChangeTime: time.Now(),
				CreateTime:             time.Now(),
			}
			newBlobStatus = append(newBlobStatus, blobStatus)
		} else {
			log.Functionf("populateInitBlobStatus: Found existing blob %s in CAS", blobInfo.Digest)
		}
	}
	if len(newBlobStatus) > 0 {
		publishBlobStatus(ctx, newBlobStatus...)
	}
}

// setBlobTypeFromContentType set the blob type from the given content string
func setBlobTypeFromContentType(blob *types.BlobStatus, contentType string) bool {
	if blob.MediaType != "" {
		// unchanged; we only override for unknown types
		return false
	}
	blob.MediaType = contentType
	return true
}

//gcBlobStatus gc all blob object which doesn't have any reference
func gcBlobStatus(ctx *volumemgrContext) {
	log.Functionf("gcBlobStatus")
	pub := ctx.pubBlobStatus
	for _, blobStatusInt := range pub.GetAll() {
		blobStatus := blobStatusInt.(types.BlobStatus)
		if blobStatus.State == types.LOADED && blobStatus.RefCount == 0 {
			log.Functionf("gcBlobStatus: removing blob %s which has no refObjects", blobStatus.Sha256)
			unpublishBlobStatus(ctx, &blobStatus)
		}
	}
}

//gcImagesFromCAS gc all unused images from CAS
func gcImagesFromCAS(ctx *volumemgrContext) {
	log.Functionf("gcImagesFromCAS")
	contentIDAndContentTreeStatus := getAllContentTreeStatus(ctx)
	referenceMap := make(map[string]interface{})
	for _, contentTreeStatus := range contentIDAndContentTreeStatus {
		referenceMap[contentTreeStatus.ReferenceID()] = true
	}

	casImages, err := ctx.casClient.ListImages()
	if err != nil {
		log.Errorf("gcImagesFromCAS: Exception while getting image list from CAS. %s", err)
		return
	}

	for _, image := range casImages {
		if _, ok := referenceMap[image]; !ok {
			log.Functionf("gcImagesFromCAS: removing image %s from CAS since no ContentTreeStatus ref found", image)
			if err := ctx.casClient.RemoveImage(image); err != nil {
				log.Errorf("gcImagesFromCAS: Exception while removing image from CAS. %s", err)
			}
		}
	}
}

//checkAndCorrectBlobHash checks if the blobHash has hash algo sha256 as prefix. If not then it'll prepend it.
func checkAndCorrectBlobHash(blobHash string) string {
	return fmt.Sprintf("sha256:%s", strings.TrimPrefix(blobHash, "sha256:"))
}

// lookupImageCAS check if an image reference exists
func lookupImageCAS(reference string, client cas.CAS) bool {
	hash, err := client.GetImageHash(reference)
	return err == nil && hash != ""
}
