// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/ocilayout"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Content that is not pulled from a registry arrives as one file. Normally
// that file is the artifact itself and gets wrapped in a manifest of its own
// (see getManifestsForBareBlob). If it is an OCI image-layout tar archive, it
// holds a whole image instead: the ingest worker loads that image into the
// CAS, and the content tree then swaps the archive blob for the blobs of the
// image. The archive is not kept.

// isOCIArchive reports whether a verified blob is an OCI image-layout archive.
func isOCIArchive(blob *types.BlobStatus) bool {
	return blob.Path != "" && ocilayout.IsLayoutTar(blob.Path)
}

// isArchiveTree reports whether the content tree still consists of just an
// OCI archive. Any other single-blob tree was given a manifest before it
// could reach the ingest worker.
func isArchiveTree(status *types.ContentTreeStatus, root *types.BlobStatus) bool {
	return len(status.Blobs) == 1 && !root.IsManifest() && !root.IsIndex()
}

// adoptArchiveBlobs makes the content tree of a finished archive ingest
// reference the blobs of the loaded image instead of the archive. It returns
// the hashes of the image blobs.
func adoptArchiveBlobs(ctx *volumemgrContext, d casIngestWorkDescription) []string {
	key := d.status.Key()
	status := ctx.LookupContentTreeStatus(key)
	if status == nil || len(status.Blobs) != 1 || len(d.status.Blobs) != 1 ||
		status.Blobs[0] != d.status.Blobs[0] {
		// Deleted or replaced while the ingest ran. As with any ingest that
		// outlives its content tree, the image stays until the next GC.
		log.Warnf("adoptArchiveBlobs(%s): content tree changed during ingest, not adopting", key)
		return nil
	}
	for i := range d.archiveBlobs {
		sha := d.archiveBlobs[i].Sha256
		if !ctx.casClient.CheckBlobExists(cas.CheckAndCorrectBlobHash(sha)) {
			// The ingest held no reference on a blob it shares with another
			// content tree, and that tree was deleted meanwhile. Drop the
			// result, so that the tree is seen as LOADING with no ingest
			// and loads the archive again.
			log.Warnf("adoptArchiveBlobs(%s): blob %s left the CAS during ingest, reloading", key, sha)
			ctx.worker.Pop(key)
			return nil
		}
	}
	archive := ctx.LookupBlobStatus(status.Blobs[0])

	shas := make([]string, 0, len(d.archiveBlobs))
	for i := range d.archiveBlobs {
		blob := &d.archiveBlobs[i]
		if existing := ctx.LookupBlobStatus(blob.Sha256); existing != nil {
			if existing.State != types.LOADED {
				existing.State = types.LOADED
				publishBlobStatus(ctx, existing)
			}
		} else {
			publishBlobStatus(ctx, blob)
		}
		shas = append(shas, blob.Sha256)
	}

	// Reference the image blobs before releasing the archive, so the tree
	// never holds a blob without a refcount on it.
	status.Blobs = []string{}
	if err := AddBlobsToContentTreeStatus(ctx, status, shas...); err != nil {
		log.Errorf("adoptArchiveBlobs(%s): %v", key, err)
	}
	if archive != nil {
		// Drops the downloader and verifier references, which deletes the
		// archive file.
		RemoveRefFromBlobStatus(ctx, archive)
	}
	publishContentTreeStatus(ctx, status)
	return shas
}
