// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// downloadBlob download a blob from a content tree
// returns whether or not the BlobStatus has changed
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
			log.Infof("downloadStatus not found for blob %s", blob.Sha256)
		} else if ds.Expired {
			log.Infof("downloadStatus Expired set for blob %s", blob.Sha256)
		} else {
			log.Infof("downloadStatus RefCount=0 for blob %s", blob.Sha256)
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
		log.Infof("lookupDownloaderStatus Pending for blob %s", blob.Sha256)
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
		// signal verifier to start if it hasn't already; add RefCount
		if verifyBlob(ctx, objType, sv, blob) {
			changed = true
		}
	}
	log.Infof("downloadBlob(%s) complete", blob.Sha256)
	return changed
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
func verifyBlob(ctx *volumemgrContext, objType string, sv SignatureVerifier, blob *types.BlobStatus) bool {
	changed := false

	// A: try to use an existing VerifyImageStatus
	vs := lookupVerifyImageStatus(ctx, blob.Sha256)
	if vs != nil && !vs.Expired {
		log.Infof("verifyBlob(%s): found VerifyImageStatus", blob.Sha256)
		changed = updateBlobFromVerifyImageStatus(vs, blob)

		// if we do not reference it, increment the refcount
		if startBlobVerification(ctx, objType, sv, blob) {
			changed = true
		}

		return changed
	}

	// B: No VerifyImageStatus so just create it
	if blob.State < types.VERIFYING {
		blob.State = types.VERIFYING
		changed = true
	}
	if startBlobVerification(ctx, objType, sv, blob) {
		changed = true
	}
	return changed
}

// startBlobVerification kick off verification of a blob, or increment the refcount.
// Used only in verifyBlob, but repetitive, so a separate utility function
func startBlobVerification(ctx *volumemgrContext, objType string, sv SignatureVerifier, blob *types.BlobStatus) bool {
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
func getBlobChildren(blob *types.BlobStatus) []*types.BlobStatus {
	log.Infof("getBlobChildren(%s)", blob.Sha256)
	if blob.State < types.VERIFIED {
		return nil
	}
	log.Infof("getBlobChildren(%s): VERIFIED", blob.Sha256)
	// if verified, check for any children and start them off
	switch blob.BlobType {
	case types.BlobIndex:
		log.Infof("getBlobChildren(%s): is an index, looking for manifest", blob.Sha256)
		// resolve to our platform-specific one
		manifest, err := resolveIndex(blob.Path)
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
		return []*types.BlobStatus{
			{
				DatastoreID: blob.DatastoreID,
				RelativeURL: replaceSha(blob.RelativeURL, manifest.Digest),
				Sha256:      strings.ToLower(manifest.Digest.Hex),
				Size:        uint64(manifest.Size),
				State:       types.INITIAL,
				BlobType:    types.BlobManifest,
				ObjType:     blob.ObjType,
			},
		}
	case types.BlobManifest:
		log.Infof("getBlobChildren(%s): is a manifest, adding children", blob.Sha256)
		// get all of the parts
		_, children, err := resolveManifestChildren(blob.Path)
		if err != nil {
			blob.SetError(err.Error(), time.Now())
			return nil
		}
		var blobChildren []*types.BlobStatus
		if len(children) > 0 {
			blobChildren = make([]*types.BlobStatus, 0)
			for _, child := range children {
				blobChildren = append(blobChildren, &types.BlobStatus{
					DatastoreID: blob.DatastoreID,
					RelativeURL: replaceSha(blob.RelativeURL, child.Digest),
					Sha256:      strings.ToLower(child.Digest.Hex),
					Size:        uint64(child.Size),
					State:       types.INITIAL,
					ObjType:     blob.ObjType,
				})
			}
		}
		return blobChildren
	default:
		return nil
	}
}

// resolveBlobType resolves what type of blob this is
// returns if it updated it, including error
func resolveBlobType(blob *types.BlobStatus) (types.BlobType, error) {
	if blob.BlobType != types.BlobUnknown {
		return blob.BlobType, nil
	}
	log.Infof("resolveBlobType(%s): is unknown, resolving type", blob.Sha256)
	// figure out if it is anything we can process

	// try it as an index and as a straight manifest
	r, err := os.Open(blob.Path)
	if err != nil {
		return blob.BlobType, err
	}
	defer r.Close()

	// we do not need to really parse it, just get the media type
	desc, err := v1.ParseManifest(r)
	if err != nil {
		if err != io.EOF {
			return types.BlobBinary, nil
		}
		return blob.BlobType, err
	}

	var blobType types.BlobType

	switch desc.MediaType {
	case v1types.OCIImageIndex, v1types.DockerManifestList:
		blobType = types.BlobIndex
	case v1types.OCIManifestSchema1, v1types.DockerManifestSchema1, v1types.DockerManifestSchema2, v1types.DockerManifestSchema1Signed:
		blobType = types.BlobManifest
	default:
		blobType = types.BlobBinary
	}

	return blobType, nil
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

// blobsNotInStatus find any in the slice that do not already have a BlobStatus
func blobsNotInStatus(ctx *volumemgrContext, a []*types.BlobStatus) []*types.BlobStatus {
	// if we have none, return none
	if len(a) < 1 {
		return a
	}

	// get a slice of just the hashes
	shas := []string{}
	for _, blob := range a {
		shas = append(shas, blob.Sha256)
	}

	// look up all of the shas of the list we were passed
	blobs := lookupBlobStatuses(ctx, shas...)
	// save a map of the hashes
	m := map[string]bool{}
	for _, item := range blobs {
		m[item.Sha256] = true
	}

	// to hold our return value
	ret := make([]*types.BlobStatus, 0)
	// only add those that we did not find
	for _, item := range a {
		if _, ok := m[item.Sha256]; !ok {
			ret = append(ret, item)
		}
	}
	return ret
}

// blobsNotInStatusOrCreate find any in the slice that do not already have a BlobStatus,
// but first check if the BlobStatus can be recreated from VerifyImageStatus
func blobsNotInStatusOrCreate(ctx *volumemgrContext, sv SignatureVerifier, objType string, a []*types.BlobStatus) []*types.BlobStatus {
	// if we have none, return none
	if len(a) < 1 {
		return a
	}

	// to hold our return value
	ret := make([]*types.BlobStatus, 0)
	// go through each one, and try to find or create it
	for _, blob := range a {
		found := lookupOrCreateBlobStatus(ctx, sv, objType, blob.Sha256)
		if found == nil {
			ret = append(ret, blob)
		}
	}
	return ret
}

// resolveManifestSize resolve the size of total image for a manifest.
// If the blob is not of type Manifest, return existing size
func resolveManifestSize(blob types.BlobStatus) int64 {
	if blob.BlobType != types.BlobManifest {
		return blob.TotalSize
	}

	size, _, err := resolveManifestChildren(blob.Path)
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
		log.Infof("lookupBlobStatus(%s) not found", blobSha)
		return nil
	}
	status := s.(types.BlobStatus)
	return &status
}

// lookupOrCreateBlobStatus tries to lookup a BlobStatus. If one is not found,
// and a VerifyImageStatus exists, use that to create the BlobStatus.
func lookupOrCreateBlobStatus(ctx *volumemgrContext, sv SignatureVerifier, objType, blobSha string) *types.BlobStatus {
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
			BlobType:       types.BlobUnknown,
			Sha256:         blobSha,
			State:          vs.State,
			Path:           vs.FileLocation,
			HasVerifierRef: true,
			ObjType:        objType,
			Size:           uint64(vs.Size),
			CurrentSize:    vs.Size,
			TotalSize:      vs.Size,
			Progress:       100,
		}
		updateBlobFromVerifyImageStatus(vs, blob)
		startBlobVerification(ctx, objType, sv, blob)
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

func blobStatusGetAll(ctx *volumemgrContext) map[string]*types.BlobStatus {
	pub := ctx.pubBlobStatus
	blobShaAndBlobStatus := make(map[string]*types.BlobStatus)
	for blobSha, blobStatusInt := range pub.GetAll() {
		blobStatus := blobStatusInt.(types.BlobStatus)
		blobShaAndBlobStatus[blobSha] = &blobStatus
	}
	return blobShaAndBlobStatus
}

func publishBlobStatus(ctx *volumemgrContext, blobs ...*types.BlobStatus) {
	for _, blob := range blobs {
		key := blob.Sha256
		log.Infof("publishBlobStatus(%s)", key)
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
