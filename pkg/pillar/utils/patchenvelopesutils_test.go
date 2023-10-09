// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
)

func TestGetZipArchive(t *testing.T) {
	t.Parallel()

	g := gomega.NewGomegaWithT(t)
	pe := types.PatchEnvelopeInfoList{}

	uuidString := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	peInfo := types.PatchEnvelopeInfo{
		PatchID:     "PatchId1",
		AllowedApps: []string{uuidString},
		BinaryBlobs: []types.BinaryBlobCompleted{
			{
				FileName:     "TestFileName",
				FileSha:      "TestFileSha",
				FileMetadata: "TestFileMetadata",
				URL:          "./testurl",
			},
		},
	}

	pe.Envelopes = append(pe.Envelopes, peInfo)

	g.Expect(pe.Get(uuidString)).To(gomega.BeEquivalentTo([]types.PatchEnvelopeInfo{peInfo}))

	// Test GetZipArchive
	root := "./"
	filecontent := "blobfilecontent"
	os.WriteFile(peInfo.BinaryBlobs[0].URL, []byte(filecontent), 0755)
	defer os.Remove(peInfo.BinaryBlobs[0].URL)

	archivePath, _ := utils.GetZipArchive(root, peInfo)
	defer os.Remove(archivePath)
	assert.Equal(t, filepath.Join(root, peInfo.PatchID+".zip"), archivePath)

	r, _ := zip.OpenReader(archivePath)
	defer r.Close()

	for _, f := range r.File {
		if f.Name == filepath.Base(peInfo.BinaryBlobs[0].URL) {
			// Open the file from the archive
			rc, _ := f.Open()
			defer rc.Close()

			contents, _ := io.ReadAll(rc)
			assert.Equal(t, filecontent, string(contents))
		}
	}
}
