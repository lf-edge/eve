// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func TestPatchEnvelopes(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	pe := PatchEnvelopes{}

	uuidString := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	peInfo := PatchEnvelopeInfo{
		PatchId:     "PatchId1",
		AllowedApps: []string{uuidString},
		BinaryBlobs: []BinaryBlobCompleted{
			{
				FileName:     "TestFileName",
				FileSha:      "TestFileSha",
				FileMetadata: "TestFileMetadata",
				Url:          "./testurl",
			},
		},
	}

	pe.Envelopes = append(pe.Envelopes, peInfo)

	g.Expect(pe.Get(uuidString)).To(gomega.BeEquivalentTo([]PatchEnvelopeInfo{peInfo}))

	// Test GetZipArchive
	root := "./"
	filecontent := "blobfilecontent"
	os.WriteFile(peInfo.BinaryBlobs[0].Url, []byte(filecontent), 0755)
	defer os.Remove(peInfo.BinaryBlobs[0].Url)

	archivePath, _ := GetZipArchive(root, peInfo)
	defer os.Remove(archivePath)
	assert.Equal(t, filepath.Join(root, peInfo.PatchId+".zip"), archivePath)

	r, _ := zip.OpenReader(archivePath)
	defer r.Close()

	for _, f := range r.File {
		if f.Name == filepath.Base(peInfo.BinaryBlobs[0].Url) {
			// Open the file from the archive
			rc, _ := f.Open()
			defer rc.Close()

			contents, _ := io.ReadAll(rc)
			assert.Equal(t, filecontent, string(contents))
			break
		}
	}

	peInfo = PatchEnvelopeInfo{
		AllowedApps: []string{"17daa0ff-39d6-42be-a537-44c974276aec"},
		PatchId:     "699fbdb2-e455-448f-84f5-68e547ec1305",
		BinaryBlobs: []BinaryBlobCompleted{
			{
				FileName:     "textfile1.txt",
				FileSha:      "e5f3f80da0f9a3add3540a80d214069079f71e879b87c51c4c3a258989294812",
				FileMetadata: "YXJ0aWZhY3QgbWV0YWRhdGE=",
				Url:          "/persist/patchEnvelopesCache/textfile1.txt",
			},
			{
				FileName:     "textfile2.txt",
				FileSha:      "e5f3f80da0f9a3add3540a80d214069079f71e879b87c51c4c3a258989294812",
				FileMetadata: "YXJ0aWZhY3QgbWV0YWRhdGE=",
				Url:          "/persist/patchEnvelopesCache/textfile2.txt",
			},
		},
	}
	pe = PatchEnvelopes{
		Envelopes: []PatchEnvelopeInfo{peInfo},
	}

	got := pe.Get("17daa0ff-39d6-42be-a537-44c974276aec")
	assert.Equal(t, got, []PatchEnvelopeInfo{peInfo})

	assert.Equal(t, peInfo, *FindPatchEnvelopeById(got, "699fbdb2-e455-448f-84f5-68e547ec1305"))

}

func TestFindPatchEnvelopeById(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	pe1 := PatchEnvelopeInfo{
		PatchId: "PatchId1",
	}
	pe2 := PatchEnvelopeInfo{
		PatchId: "PatchId2",
	}
	pe3 := PatchEnvelopeInfo{
		PatchId: "PatchId3",
	}

	pes := []PatchEnvelopeInfo{pe1, pe2, pe3}

	got := FindPatchEnvelopeById(pes, pe1.PatchId)
	g.Expect(got).To(gomega.BeEquivalentTo(&pe1))

	got = FindPatchEnvelopeById(pes, pe2.PatchId)
	g.Expect(got).To(gomega.BeEquivalentTo(&pe2))

	got = FindPatchEnvelopeById(pes, "NonExistingPatchId")
	g.Expect(got).To(gomega.BeNil())
}
