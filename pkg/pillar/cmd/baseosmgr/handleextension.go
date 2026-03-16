// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// WriteExtensionToPersist extracts the Extension Image (disk-additional layer)
// from the OCI Content Tree in containerd CAS and writes it to the paired
// PERSIST file. The target filename is derived from the partition label:
// IMGA → ext-imga.img, IMGB → ext-imgb.img.
//
// Returns nil if the OCI image has no disk-additional layer (monolithic image).
// This is the normal case when upgrading between monolithic versions.
func WriteExtensionToPersist(ref, targetPartLabel string) error {
	// Determine the target file path based on partition label
	targetPath, err := types.ExtensionImagePath(targetPartLabel)
	if err != nil {
		return fmt.Errorf("WriteExtensionToPersist: %w", err)
	}

	// Open CAS client
	casClient, err := cas.NewCAS("containerd")
	if err != nil {
		return fmt.Errorf("WriteExtensionToPersist: failed to create CAS client: %w", err)
	}
	defer casClient.CloseClient()

	// Find the disk-additional blob digest in the OCI manifest
	blobDigest, err := cas.FindAdditionalDiskBlob(casClient, ref)
	if err != nil {
		return fmt.Errorf("WriteExtensionToPersist: %w", err)
	}
	if blobDigest == "" {
		// No Extension layer — monolithic image, nothing to do
		log.Functionf("WriteExtensionToPersist: no disk-additional layer in %s (monolithic), skipping", ref)
		return nil
	}

	log.Functionf("WriteExtensionToPersist: extracting Extension %s to %s", blobDigest, targetPath)

	// Read the blob from CAS
	ctrdCtx, done := casClient.CtrNewUserServicesCtx()
	defer done()

	reader, err := casClient.ReadBlob(ctrdCtx, blobDigest)
	if err != nil {
		return fmt.Errorf("WriteExtensionToPersist: failed to read blob %s: %w", blobDigest, err)
	}

	// Write to a temp file, then atomically rename
	tmpPath := targetPath + ".tmp"
	if err := writeReaderToFile(reader, tmpPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("WriteExtensionToPersist: failed to write %s: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("WriteExtensionToPersist: failed to rename %s to %s: %w", tmpPath, targetPath, err)
	}

	log.Functionf("WriteExtensionToPersist: successfully wrote Extension to %s", targetPath)
	return nil
}

// writeReaderToFile streams data from reader to a file at path.
func writeReaderToFile(reader io.Reader, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, reader); err != nil {
		return err
	}
	return f.Sync()
}
