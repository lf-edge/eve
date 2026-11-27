// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/ocilayout"
	"github.com/lf-edge/eve/pkg/pillar/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// The single file of content that is not pulled from a registry may be an OCI
// image-layout tar archive instead of the artifact itself. The content tree
// then takes the blobs of the image in the archive as its own, as it does
// with the children of a manifest from a registry, and the ingest worker
// loads them from the archive, which is dropped afterwards. A content tree
// created later for the same archive starts from the loaded image (see
// loadedArchiveManifest).

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

// loadedArchiveManifest returns the manifest hash of the image that was
// loaded earlier from the OCI archive this content tree refers to, or "" if
// there is no such image or it is not complete.
func loadedArchiveManifest(ctx *volumemgrContext, status *types.ContentTreeStatus) string {
	if status.IsOCIRegistry {
		return ""
	}
	reference := status.ReferenceID()
	manifestHash, err := ctx.casClient.GetImageHash(reference)
	if err != nil || manifestHash == "" {
		return ""
	}
	labels, err := ctx.casClient.GetImageLabels(reference)
	if err != nil {
		log.Warnf("loadedArchiveManifest(%s): labels of %s: %v", status.Key(), reference, err)
		return ""
	}
	// The manifest label catches an image whose target was replaced by other
	// content while it kept its labels.
	if status.ContentSha256 == "" ||
		labels[types.EVEOCIArchiveLabel] != strings.ToLower(status.ContentSha256) ||
		labels[types.EVEOCIArchiveManifestLabel] != manifestHash {
		return ""
	}
	manifest := ctx.LookupBlobStatus(strings.TrimPrefix(manifestHash, "sha256:"))
	if manifest == nil || manifest.State != types.LOADED || !manifest.IsManifest() {
		return ""
	}
	children, err := ctx.casClient.Children(manifestHash)
	if err != nil || len(children) == 0 {
		log.Warnf("loadedArchiveManifest(%s): children of %s: %v", status.Key(), manifestHash, err)
		return ""
	}
	for _, child := range children {
		blob := ctx.LookupBlobStatus(strings.TrimPrefix(child, "sha256:"))
		if blob == nil || blob.State != types.LOADED {
			return ""
		}
	}
	return manifest.Sha256
}
