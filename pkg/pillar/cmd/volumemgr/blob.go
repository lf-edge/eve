// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"strings"
	"time"

	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// downloadBlob download a blob from a content tree
// returns whether or not the BlobStatus has changed
// The objType is only used to check the free vs. non-free policy for downloads
func downloadBlob(ctx *volumemgrContext, objType string, sv SignatureVerifier, blob *types.BlobStatus) bool {

	changed := false
	// Make sure we kick the downloader and have a refcount
	if !blob.HasDownloaderRef {
		AddOrRefcountDownloaderConfig(ctx, objType, *blob)
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
			log.Debugf("downloadStatus not found for blob %s", blob.Sha256)
		} else if ds.Expired {
			log.Debugf("downloadStatus Expired set for blob %s", blob.Sha256)
		} else {
			log.Debugf("downloadStatus RefCount=0 for blob %s", blob.Sha256)
		}
		blob.State = types.DOWNLOADING
		return true
	}

	// we have a valid & non-expired & refcounted DownloadStatus
	// make sure the blob path matches the target path
	if ds.Target != "" && blob.Path == "" {
		blob.Path = ds.Target
		changed = true
		log.Infof("From ds set FileLocation to %s for blob %s",
			ds.Target, blob.Sha256)
	}

	// make sure the blob state matches the actual state
	if blob.State != ds.State {
		blob.State = ds.State
		changed = true
	}
	if blob.TotalSize != ds.TotalSize || blob.CurrentSize != ds.CurrentSize {
		blob.TotalSize = ds.TotalSize
		blob.CurrentSize = ds.CurrentSize
		if blob.TotalSize > 0 {
			blob.Progress = uint(blob.CurrentSize / blob.TotalSize * 100)
		}
		changed = true
	}
	if ds.Pending() {
		log.Debugf("lookupDownloaderStatus Pending for blob %s", blob.Sha256)
		return changed
	}
	if ds.HasError() {
		log.Errorf("Received error from downloader for blob %s: %s",
			blob.Sha256, ds.Error)
		blob.SetErrorWithSource(ds.Error, types.DownloaderStatus{},
			ds.ErrorTime)
		changed = true
		return changed
	}
	if blob.IsErrorSource(types.DownloaderStatus{}) {
		log.Infof("Clearing downloader error %s", blob.Error)
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
		// save the blob type
		if setBlobTypeFromContentType(blob, ds.ContentType) {
			changed = true
		}
		// signal verifier to start if it hasn't already; add RefCount
		if verifyBlob(ctx, sv, blob) {
			changed = true
		}
	}
	log.Infof("downloadBlob(%s) complete", blob.Sha256)
	return changed
}

//AddRefToBlobStatus adds the refObject as an reference to the blobs in the given blob list.
func AddRefToBlobStatus(ctx *volumemgrContext, blobStatus ...*types.BlobStatus) {
	for _, blob := range blobStatus {
		blob.RefCount++
		log.Infof("AddRefToBlobStatus: RefCount to %d for Blob %s",
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
		log.Infof("RemoveRefFromBlobStatus: RefCount to %d for Blob %s",
			blob.RefCount, blob.Sha256)
		if blob.RefCount == 0 {
			log.Infof("RemoveRefFromBlobStatus: unpublishing Blob %s since no object is referring it.",
				blob.Sha256)
			unpublishBlobStatus(ctx, blob)
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
		log.Infof("updateBlobFromVerifyImageStatus(%s): Clearing verifier error %s", blob.Sha256, blob.Error)
		blob.ClearErrorWithSource()
		changed = true
	}

	if vs.Pending() {
		log.Infof("updateBlobFromVerifyImageStatus(%s): VerifyImageStatus pending", blob.Sha256)
		return changed
	}
	if blob.Path != vs.FileLocation {
		blob.Path = vs.FileLocation
		log.Infof("updateBlobFromVerifyImageStatus(%s): updating Path to %s", blob.Sha256, blob.Path)
		changed = true
	}

	return changed
}

// verifyBlob verify a blob, or latch onto an existing VerifyImageStatus.
// First, check if a VerifyImageStatus exists. If so, check HasVerifierRef,
// potentially incrementing creating or incrementing the refcount on a
// VerifyImageConfig to trigger the generation of a VerifyImageStatus.
// returns if the BlobStatus was changed, and thus woudl require publishing
func verifyBlob(ctx *volumemgrContext, sv SignatureVerifier, blob *types.BlobStatus) bool {
	changed := false

	// A: try to use an existing VerifyImageStatus
	vs := lookupVerifyImageStatus(ctx, blob.Sha256)
	if vs != nil && !vs.Expired {
		log.Infof("verifyBlob(%s): found VerifyImageStatus", blob.Sha256)
		changed = updateBlobFromVerifyImageStatus(vs, blob)

		// if we do not reference it, increment the refcount
		if startBlobVerification(ctx, sv, blob) {
			changed = true
		}

		return changed
	}

	// B: No VerifyImageStatus so just create it
	if blob.State < types.VERIFYING {
		blob.State = types.VERIFYING
		changed = true
	}
	if startBlobVerification(ctx, sv, blob) {
		changed = true
	}
	return changed
}

// startBlobVerification kick off verification of a blob, or increment the refcount.
// Used only in verifyBlob, but repetitive, so a separate utility function
func startBlobVerification(ctx *volumemgrContext, sv SignatureVerifier, blob *types.BlobStatus) bool {
	changed := false
	if blob.HasVerifierRef {
		return false
	}
	done, errorAndTime := MaybeAddVerifyImageConfigBlob(ctx, *blob, sv)
	if done {
		blob.HasVerifierRef = true
		return true
	}
	// if errors, set the certError flag
	// otherwise, mark as waiting for certs
	if errorAndTime.HasError() {
		blob.SetError(errorAndTime.Error, errorAndTime.ErrorTime)
		changed = true
	} else if !blob.WaitingForCerts {
		blob.WaitingForCerts = true
		changed = true
	}
	return changed
}

// getBlobChildren get the children of a blob
func getBlobChildren(ctx *volumemgrContext, sv SignatureVerifier, blob *types.BlobStatus) []*types.BlobStatus {
	log.Debugf("getBlobChildren(%s)", blob.Sha256)
	if blob.State < types.VERIFIED {
		return nil
	}
	log.Debugf("getBlobChildren(%s): VERIFIED", blob.Sha256)
	// if verified, check for any children and start them off
	switch blob.BlobType {
	case types.BlobIndex:
		log.Infof("getBlobChildren(%s): is an index, looking for manifest", blob.Sha256)
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
		log.Infof("getBlobChildren(%s): adding manifest %s", blob.Sha256, manifest.Digest.Hex)
		childHash := strings.ToLower(manifest.Digest.Hex)
		//Check if childBlob already exists
		existingChild := lookupOrCreateBlobStatus(ctx, sv, childHash)
		if existingChild == nil {
			return []*types.BlobStatus{
				{
					DatastoreID: blob.DatastoreID,
					RelativeURL: replaceSha(blob.RelativeURL, manifest.Digest),
					Sha256:      strings.ToLower(manifest.Digest.Hex),
					Size:        uint64(manifest.Size),
					State:       types.INITIAL,
					BlobType:    types.BlobManifest,
				},
			}
		} else if existingChild.State == types.LOADED {
			// Need to update DatastoreID and RelativeURL if the blob is already loaded into CAS,
			// because if any child blob is not downloaded already, then we would need the below data.
			existingChild.DatastoreID = blob.DatastoreID
			existingChild.RelativeURL = replaceSha(blob.RelativeURL, manifest.Digest)
		}
		log.Infof("getBlobChildren(%s): manifest %s already exists.", blob.Sha256, childHash)
		return []*types.BlobStatus{existingChild}

	case types.BlobManifest:
		log.Infof("getBlobChildren(%s): is a manifest, adding children", blob.Sha256)
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
				existingChild := lookupOrCreateBlobStatus(ctx, sv, childHash)
				if existingChild != nil {
					log.Debugf("getBlobChildren(%s): child blob %s already exists.", blob.Sha256, childHash)
					blobChildren = append(blobChildren, existingChild)
				} else {
					log.Infof("getBlobChildren(%s): creating a new BlobStatus for child %s", blob.Sha256, childHash)
					blobChildren = append(blobChildren, &types.BlobStatus{
						DatastoreID: blob.DatastoreID,
						RelativeURL: replaceSha(blob.RelativeURL, child.Digest),
						Sha256:      childHash,
						Size:        uint64(child.Size),
						State:       types.INITIAL,
						BlobType:    resolveMediaType(child.MediaType),
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
func blobsNotInStatusOrCreate(ctx *volumemgrContext, sv SignatureVerifier, a []*types.BlobStatus) []*types.BlobStatus {
	// if we have none, return none
	if len(a) < 1 {
		return a
	}

	// to hold our return value
	ret := make([]*types.BlobStatus, 0)
	// go through each one, and try to find or create it
	for _, blob := range a {
		found := lookupOrCreateBlobStatus(ctx, sv, blob.Sha256)
		if found == nil {
			ret = append(ret, blob)
		}
	}
	return ret
}

// resolveManifestSize resolve the size of total image for a manifest.
// If the blob is not of type Manifest, return existing size
func resolveManifestSize(ctx *volumemgrContext, blob types.BlobStatus) int64 {
	if blob.BlobType != types.BlobManifest {
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
		log.Debugf("lookupBlobStatus(%s) not found", blobSha)
		return nil
	}
	status := s.(types.BlobStatus)
	return &status
}

// lookupOrCreateBlobStatus tries to lookup a BlobStatus. If one is not found,
// and a VerifyImageStatus exists, use that to create the BlobStatus.
func lookupOrCreateBlobStatus(ctx *volumemgrContext, sv SignatureVerifier, blobSha string) *types.BlobStatus {
	log.Debugf("lookupOrCreateBlobStatus(%s)", blobSha)
	if blobSha == "" {
		return nil
	}
	// Does it already exist?
	blob := lookupBlobStatus(ctx, blobSha)
	if blob != nil {
		return blob
	}
	// need to look for VerifyImageStatus that matches
	log.Infof("lookupOrCreateBlobStatus(%s) not found, trying VerifyImageStatus",
		blobSha)

	// first see if a VerifyImageStatus exists
	// if it does, then create a BlobStatus with State up to the level of the VerifyImageStatus
	vs := lookupVerifyImageStatus(ctx, blobSha)
	if vs != nil && !vs.Expired {
		log.Infof("lookupOrCreateBlobStatus(%s) VerifyImageStatus found, creating and publishing BlobStatus", blobSha)
		blob := &types.BlobStatus{
			BlobType:    types.BlobUnknown,
			Sha256:      blobSha,
			State:       vs.State,
			Path:        vs.FileLocation,
			Size:        uint64(vs.Size),
			CurrentSize: vs.Size,
			TotalSize:   vs.Size,
			Progress:    100,
		}
		updateBlobFromVerifyImageStatus(vs, blob)
		startBlobVerification(ctx, sv, blob)
		publishBlobStatus(ctx, blob)
		return blob
	}
	return nil
}

func lookupBlobStatuses(ctx *volumemgrContext, shas ...string) []*types.BlobStatus {
	ret := []*types.BlobStatus{}
	all := ctx.pubBlobStatus.GetAll()
	for _, sha := range shas {
		if blobInt, ok := all[sha]; ok {
			blob := blobInt.(types.BlobStatus)
			ret = append(ret, &blob)
		}
	}
	return ret
}

func publishBlobStatus(ctx *volumemgrContext, blobs ...*types.BlobStatus) {
	for _, blob := range blobs {
		key := blob.Sha256
		log.Debugf("publishBlobStatus(%s)", key)
		ctx.pubBlobStatus.Publish(key, *blob)
	}
}

func unpublishBlobStatus(ctx *volumemgrContext, blobs ...*types.BlobStatus) {
	errs := []error{}
	for _, blob := range blobs {
		key := blob.Sha256
		log.Infof("unpublishBlobStatus(%s)", key)

		// drop references
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
		log.Errorf("populateInitBlobStatus: exception while fetching existing blobs from CAS")
		return
	}
	mediaMap, err := ctx.casClient.ListBlobsMediaTypes()
	if err != nil {
		log.Errorf("populateInitBlobStatus: exception while fetching existing media types from CAS")
		return
	}
	newBlobStatus := make([]*types.BlobStatus, 0)
	for _, blobInfo := range blobInfoList {
		blobType := resolveMediaType(v1types.MediaType(mediaMap[blobInfo.Digest]))
		if lookupBlobStatus(ctx, blobInfo.Digest) == nil {
			log.Infof("populateInitBlobStatus: Found blob %s in CAS", blobInfo.Digest)
			blobStatus := &types.BlobStatus{
				Sha256:      strings.TrimPrefix(blobInfo.Digest, "sha256:"),
				Size:        uint64(blobInfo.Size),
				State:       types.LOADED,
				BlobType:    blobType,
				TotalSize:   blobInfo.Size,
				CurrentSize: blobInfo.Size,
				Progress:    100,
			}
			newBlobStatus = append(newBlobStatus, blobStatus)
		}
	}
	if len(newBlobStatus) > 0 {
		publishBlobStatus(ctx, newBlobStatus...)
	}
}

// resolveMediaType convert the string of a mediaType into our enumerated types
func resolveMediaType(contentType v1types.MediaType) types.BlobType {
	var blobType types.BlobType
	switch contentType {
	case v1types.OCIImageIndex, v1types.DockerManifestList:
		blobType = types.BlobIndex
	case v1types.OCIManifestSchema1, v1types.DockerManifestSchema1, v1types.DockerManifestSchema2, v1types.DockerManifestSchema1Signed:
		blobType = types.BlobManifest
	default:
		blobType = types.BlobBinary
	}
	return blobType
}

// setBlobTypeFromContentType set the blob type from the given content string
func setBlobTypeFromContentType(blob *types.BlobStatus, contentType string) bool {
	if blob.BlobType != types.BlobUnknown {
		// unchanged; we only override for unknown types
		return false
	}

	blob.BlobType = resolveMediaType(v1types.MediaType(contentType))
	return true
}

//gcBlobStatus gc all blob object which doesn't have any reference
func gcBlobStatus(ctx *volumemgrContext) {
	log.Infof("gcBlobStatus")
	pub := ctx.pubBlobStatus
	for _, blobStatusInt := range pub.GetAll() {
		blobStatus := blobStatusInt.(types.BlobStatus)
		if blobStatus.State == types.LOADED && blobStatus.RefCount == 0 {
			log.Infof("gcBlobStatus: removing blob %s which has no refObjects", blobStatus.Sha256)
			unpublishBlobStatus(ctx, &blobStatus)
		}
	}
}

//checkAndCorrectBlobHash checks if the blobHash has hash algo sha256 as prefix. If not then it'll prepend it.
func checkAndCorrectBlobHash(blobHash string) string {
	return fmt.Sprintf("sha256:%s", strings.TrimPrefix(blobHash, "sha256:"))
}
