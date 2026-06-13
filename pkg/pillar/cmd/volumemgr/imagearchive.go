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

// loadImageArchive imports a downloaded image archive (rootBlob.Path) into the
// CAS, replacing the content tree's single "bare" blob with the real image
// blobs (index, manifest, config and per-disk layers) so that the proper
// multi-layer manifest is used — exactly as for an image pulled from an OCI
// registry. On success the content tree is moved to the LOADED state with an
// image reference created in the CAS.
//
// This handles the case where a packaged image (e.g. a split-rootfs image of
// Core + Extension) is served by a non-OCI datastore (S3/HTTP) as a single
// file. Without it, the whole archive would be wrapped as one raw disk-root
// layer (see getManifestsForBareBlob), which is both structurally wrong and far
// larger than the target partition.
func loadImageArchive(ctx *volumemgrContext, status *types.ContentTreeStatus,
	rootBlob *types.BlobStatus, refID string) error {

	indexDigest, err := ctx.casClient.ImportImageArchive(refID, rootBlob.Path)
	if err != nil {
		return err
	}
	indexSha := strings.TrimPrefix(indexDigest, "sha256:")

	// The import wrote the index and all its descendants (manifest, config,
	// layers) into the CAS. Build LOADED BlobStatuses for them and make the
	// content tree reference the index instead of the bare archive blob.
	hashes, err := collectImageBlobTree(ctx, indexSha)
	if err != nil {
		return err
	}
	mediaMap, err := ctx.casClient.ListBlobsMediaTypes()
	if err != nil {
		return fmt.Errorf("loadImageArchive: cannot list CAS media types: %v", err)
	}

	newBlobs := make([]*types.BlobStatus, 0, len(hashes))
	for _, h := range hashes {
		full := "sha256:" + h
		var size int64
		if info, err := ctx.casClient.GetBlobInfo(full); err == nil {
			size = info.Size
		}
		newBlobs = append(newBlobs, &types.BlobStatus{
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
	publishBlobStatus(ctx, newBlobs...)
	AddRefToBlobStatus(ctx, newBlobs...)

	blobHashes := make([]string, 0, len(newBlobs))
	for _, b := range newBlobs {
		blobHashes = append(blobHashes, b.Sha256)
	}
	status.Blobs = blobHashes

	// Drop the original "bare" archive blob: release its downloader/verifier
	// references and its content-tree reference. It was never loaded into the
	// CAS (loading happens later in the normal flow), so there is nothing to
	// remove from the blob store itself.
	MaybeRemoveDownloaderConfig(ctx, rootBlob)
	MaybeRemoveVerifyImageConfig(ctx, rootBlob)
	RemoveRefFromBlobStatus(ctx, rootBlob)

	// Everything is in the CAS and the image reference was created during the
	// import, so the content tree is fully loaded.
	status.State = types.LOADED
	status.CreateTime = time.Now()
	status.FileLocation = ""
	return nil
}

// collectImageBlobTree returns the index blob and all of its descendant blob
// hashes (manifest, config, layers) by walking CAS children breadth-first.
// Hashes are returned without the "sha256:" prefix, index first.
func collectImageBlobTree(ctx *volumemgrContext, indexSha string) ([]string, error) {
	ordered := []string{indexSha}
	seen := map[string]bool{indexSha: true}
	queue := []string{indexSha}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		children, err := ctx.casClient.Children("sha256:" + cur)
		if err != nil {
			return nil, fmt.Errorf("collectImageBlobTree: children of %s: %v", cur, err)
		}
		for _, child := range children {
			ch := strings.TrimPrefix(child, "sha256:")
			if seen[ch] {
				continue
			}
			seen[ch] = true
			ordered = append(ordered, ch)
			queue = append(queue, ch)
		}
	}
	return ordered, nil
}
