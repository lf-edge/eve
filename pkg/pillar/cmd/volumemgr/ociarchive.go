// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"errors"
	"runtime"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/ocilayout"
	"github.com/lf-edge/eve/pkg/pillar/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// The single file of content that is not pulled from a registry may be an OCI
// image-layout tar archive instead of the artifact itself. The content tree
// then takes the blobs of the image in the archive as its own, as it does
// with the children of a manifest from a registry, and the ingest worker
// loads them from the archive, which is dropped afterwards.

// addArchiveImage replaces the one blob of a content tree by the blobs of the
// image it holds, the manifest first, if that blob is an OCI archive, and
// reports whether it is. The tree keeps its reference on the archive, now
// through OCIArchiveBlob, until the image is loaded (see releaseArchive).
func addArchiveImage(ctx *volumemgrContext, status *types.ContentTreeStatus, archive *types.BlobStatus) (bool, error) {
	if archive.Path == "" {
		return false, nil
	}
	a, err := ocilayout.Open(archive.Path)
	if errors.Is(err, ocilayout.ErrNotLayout) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer a.Close()
	img, err := a.Image(runtime.GOARCH)
	if err != nil {
		return false, err
	}

	descs := append([]ocispec.Descriptor{img.Manifest, img.Config}, img.Layers...)
	shas := make([]string, 0, len(descs))
	for _, desc := range descs {
		sha := desc.Digest.Encoded()
		if lookupOrCreateBlobStatus(ctx, sha) == nil {
			// INITIAL, as the blob has no file of its own that a content
			// tree without the archive could load it from.
			publishBlobStatus(ctx, &types.BlobStatus{
				Sha256:                 sha,
				Size:                   uint64(desc.Size),
				MediaType:              desc.MediaType,
				State:                  types.INITIAL,
				TotalSize:              desc.Size,
				LastRefCountChangeTime: time.Now(),
			})
		}
		shas = append(shas, sha)
	}

	status.OCIArchiveBlob = archive.Sha256
	status.Blobs = []string{}
	return true, AddBlobsToContentTreeStatus(ctx, status, shas...)
}

// releaseArchive drops the content tree's reference on its archive, if it
// still holds one. With the last reference gone, the archive file is deleted.
func releaseArchive(ctx *volumemgrContext, status *types.ContentTreeStatus) {
	if status.OCIArchiveBlob == "" {
		return
	}
	if archive := ctx.LookupBlobStatus(status.OCIArchiveBlob); archive != nil {
		RemoveRefFromBlobStatus(ctx, archive)
	} else {
		log.Warnf("releaseArchive(%s): no BlobStatus for archive %s",
			status.Key(), status.OCIArchiveBlob)
	}
	status.OCIArchiveBlob = ""
}
