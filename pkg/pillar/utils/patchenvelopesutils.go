// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// GetZipArchive archives list of patch envelopes in a given path and returns
// full path to zip archive
func GetZipArchive(root string, pe types.PatchEnvelopeInfo) (string, error) {
	zipFilename := filepath.Join(root, pe.PatchID+".zip")
	zipFile, err := os.Create(zipFilename)
	if err != nil {
		return "", err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	for _, b := range pe.BinaryBlobs {
		// We only want to archive binary blobs which are ready
		file, err := os.Open(b.URL)
		if err != nil {
			return "", err
		}
		defer file.Close()

		baseName := filepath.Base(b.URL)
		zipEntry, err := zipWriter.Create(baseName)
		if err != nil {
			return "", err
		}

		_, err = io.Copy(zipEntry, file)
		if err != nil {
			return "", err
		}

	}

	// The CipherBlobs, temporarily, store the decrypted content of the blob file in
	// the Inline.URL string. Directly use that for zipEntry write.
	for _, b := range pe.CipherBlobs {
		// We only want to archive cipher blobs which are ready
		if b.EncType != types.BlobEncrytedTypeInline || b.Inline == nil {
			continue
		}

		zipEntry, err := zipWriter.Create(b.Inline.FileName)
		if err != nil {
			return "", err
		}

		_, err = zipEntry.Write([]byte(b.Inline.URL))
		if err != nil {
			return "", err
		}
	}

	return zipFilename, nil
}
