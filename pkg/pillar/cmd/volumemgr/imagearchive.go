// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// imageArchiveKind classifies a downloaded file that turned out to be a
// packaged container image rather than a raw disk image.
type imageArchiveKind int

const (
	notImageArchive  imageArchiveKind = iota
	ociLayoutArchive                  // tar containing oci-layout + index.json
	dockerArchive                     // tar containing manifest.json (docker save format)
)

// detectImageArchive peeks at a downloaded file to determine whether it is
// actually a packaged container image (an OCI image-layout or docker-save
// archive) rather than a raw disk image. It transparently handles gzip and
// scans only the leading (small) tar entries, so it is cheap even for a
// multi-gigabyte artifact. Returns notImageArchive if the file is not such an
// archive or cannot be read.
func detectImageArchive(filePath string) imageArchiveKind {
	if filePath == "" {
		return notImageArchive
	}
	f, err := os.Open(filePath)
	if err != nil {
		return notImageArchive
	}
	defer f.Close()

	br := bufio.NewReader(f)
	var r io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return notImageArchive
		}
		defer zr.Close()
		r = zr
	}

	tr := tar.NewReader(r)
	var haveLayout, haveIndex bool
	// The OCI layout metadata files appear before the large blobs, so scanning a
	// bounded number of entries is enough to classify the archive.
	for i := 0; i < 64; i++ {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		switch strings.TrimPrefix(filepath.Clean(hdr.Name), "./") {
		case "oci-layout":
			haveLayout = true
		case "index.json":
			haveIndex = true
		case "manifest.json":
			return dockerArchive
		}
		if haveLayout && haveIndex {
			return ociLayoutArchive
		}
	}
	return notImageArchive
}

// contentTreeIsImageArchive reports whether the content tree currently consists
// of a single "bare" blob that is actually a packaged container image (an OCI
// image-layout or docker-save archive served as one file by a non-OCI
// datastore such as HTTP, AWS S3, Azure Blob Storage, Google Cloud Storage or
// SFTP). Such a content tree is imported into the CAS via the import worker so
// the proper multi-layer manifest is used, instead of being wrapped as a single
// raw disk-root layer (see getManifestsForBareBlob).
//
// It re-derives the answer from the downloaded file rather than caching it, so
// it stays correct across volumemgr restarts and is the single routing point
// shared by the VERIFIED and LOADING state-machine branches. The check is cheap
// (a bounded peek of the archive's leading tar headers).
func contentTreeIsImageArchive(ctx *volumemgrContext, status *types.ContentTreeStatus) bool {
	blobStatuses := lookupBlobStatuses(ctx, status.Blobs...)
	if len(blobStatuses) != 1 {
		return false
	}
	b := blobStatuses[0]
	if b.IsManifest() || b.IsIndex() {
		return false
	}
	return detectImageArchive(b.Path) != notImageArchive
}

// finalizeImageArchive replaces the content tree's single bare archive blob with
// the index/manifest/config/layer blobs produced by a completed CAS import
// (indexDigest, as returned by the import worker). The blocking import itself
// already ran in the worker goroutine; this only updates pubsub state and runs
// on the main loop. The caller's LOADING state machine then marks the content
// tree LOADED once all blobs and the image reference are confirmed in the CAS.
//
// This handles a packaged image (e.g. a split-rootfs image of Core + Extension)
// served by a non-OCI datastore as a single file. Without it, the whole archive
// would be wrapped as one raw disk-root layer, which is both structurally wrong
// and far larger than the target partition.
func finalizeImageArchive(ctx *volumemgrContext, status *types.ContentTreeStatus,
	rootBlob *types.BlobStatus, indexDigest string) error {

	indexSha := strings.TrimPrefix(indexDigest, "sha256:")

	// The import wrote the index and all its descendants (manifest, config,
	// layers) into the CAS. Build LOADED BlobStatuses for them and make the
	// content tree reference the index instead of the bare archive blob.
	newBlobs, err := buildLoadedBlobStatuses(ctx.casClient, indexSha)
	if err != nil {
		return err
	}
	publishBlobStatus(ctx, newBlobs...)
	AddRefToBlobStatus(ctx, newBlobs...)

	blobHashes := make([]string, 0, len(newBlobs))
	for _, b := range newBlobs {
		blobHashes = append(blobHashes, b.Sha256)
	}
	status.Blobs = blobHashes

	// Drop the original "bare" archive blob: release its downloader/verifier
	// references and its content-tree reference. It was never loaded into the
	// CAS as a usable layer, so there is nothing to remove from the blob store
	// itself.
	MaybeRemoveDownloaderConfig(ctx, rootBlob)
	MaybeRemoveVerifyImageConfig(ctx, rootBlob)
	RemoveRefFromBlobStatus(ctx, rootBlob)
	return nil
}

// buildLoadedBlobStatuses enumerates the index blob and all its descendants
// (manifest, config, layers) already present in the CAS and returns LOADED
// BlobStatuses for them, index first. It has no side effects, which makes the
// CAS-content-to-BlobStatus mapping unit-testable with a fake CAS.
func buildLoadedBlobStatuses(casClient cas.CAS, indexSha string) ([]*types.BlobStatus, error) {
	hashes, err := collectImageBlobTree(casClient, indexSha)
	if err != nil {
		return nil, err
	}
	mediaMap, err := casClient.ListBlobsMediaTypes()
	if err != nil {
		return nil, fmt.Errorf("buildLoadedBlobStatuses: cannot list CAS media types: %v", err)
	}
	blobs := make([]*types.BlobStatus, 0, len(hashes))
	for _, h := range hashes {
		full := "sha256:" + h
		var size int64
		if info, err := casClient.GetBlobInfo(full); err == nil {
			size = info.Size
		}
		blobs = append(blobs, &types.BlobStatus{
			Sha256:                 h,
			State:                  types.LOADED,
			MediaType:              mediaMap[full],
			Size:                   uint64(size),
			CurrentSize:            size,
			TotalSize:              size,
			Progress:               100,
			CreateTime:             time.Now(),
			LastRefCountChangeTime: time.Now(),
		})
	}
	return blobs, nil
}

// collectImageBlobTree returns the index blob and all of its descendant blob
// hashes (manifest, config, layers) by walking CAS children breadth-first.
// Hashes are returned without the "sha256:" prefix, index first.
//
// It recurses only into index and manifest blobs. Config and layer blobs are
// leaves: CAS.Children mis-parses them (it speculatively parses any blob as a
// manifest, so a config blob yields a bogus empty Config.Digest), which would
// otherwise inject an empty "sha256:" digest into the walk and fail it. The
// blob's media type (from the image just imported) tells us whether recursing
// is meaningful.
func collectImageBlobTree(casClient cas.CAS, indexSha string) ([]string, error) {
	mediaMap, err := casClient.ListBlobsMediaTypes()
	if err != nil {
		return nil, fmt.Errorf("collectImageBlobTree: cannot list CAS media types: %v", err)
	}
	ordered := []string{}
	seen := map[string]bool{}
	queue := []string{indexSha}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == "" || seen[cur] {
			continue
		}
		seen[cur] = true
		ordered = append(ordered, cur)
		// Only index/manifest blobs reference children worth recursing into.
		if !isImageIndexOrManifest(mediaMap["sha256:"+cur]) {
			continue
		}
		children, err := casClient.Children("sha256:" + cur)
		if err != nil {
			return nil, fmt.Errorf("collectImageBlobTree: children of %s: %v", cur, err)
		}
		for _, child := range children {
			queue = append(queue, strings.TrimPrefix(child, "sha256:"))
		}
	}
	return ordered, nil
}

// isImageIndexOrManifest reports whether the media type is an image index or
// manifest (a blob that legitimately has child descriptors).
func isImageIndexOrManifest(mediaType string) bool {
	switch v1types.MediaType(mediaType) {
	case v1types.OCIImageIndex, v1types.DockerManifestList,
		v1types.OCIManifestSchema1, v1types.DockerManifestSchema2,
		v1types.DockerManifestSchema1, v1types.DockerManifestSchema1Signed:
		return true
	}
	return false
}
