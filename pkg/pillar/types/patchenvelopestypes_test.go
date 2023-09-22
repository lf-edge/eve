// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestPatchEnvelopeInfo(t *testing.T) {
	t.Parallel()

	g := gomega.NewGomegaWithT(t)
	pe := []types.PatchEnvelopeInfo{}

	uuidString := "6ba7b810-9dad-13d0-80b4-00c04fd430c8"
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

	pe = append(pe, peInfo)

	g.Expect(types.FindPatchEnvelopesByApp(pe, uuidString)).To(gomega.BeEquivalentTo([]types.PatchEnvelopeInfo{peInfo}))

	// Test GetZipArchive
	filecontent := "blobfilecontent"
	err := os.WriteFile(peInfo.BinaryBlobs[0].URL, []byte(filecontent), 0600)
	g.Expect(err).To(gomega.BeNil())
	defer os.Remove(peInfo.BinaryBlobs[0].URL)

	peInfo = types.PatchEnvelopeInfo{
		AllowedApps: []string{"17daa0ff-39d6-42be-a537-44c974276aec"},
		PatchID:     "699fbdb2-e455-448f-84f5-68e547ec1305",
		BinaryBlobs: []types.BinaryBlobCompleted{
			{
				FileName: "textfile1.txt",
				//pragma: allowlist nextline secret
				FileSha:      "e5f3f80da0f9a3add3540a80d214069079f71e879b87c51c4c3a258989294812",
				FileMetadata: "YXJ0aWZhY3QgbWV0YWRhdGE=",
				URL:          "/persist/patchEnvelopesCache/textfile1.txt",
			},
			{
				FileName: "textfile2.txt",
				//pragma: allowlist nextline secret
				FileSha:      "e5f3f80da0f9a3add3540a80d214069079f71e879b87c51c4c3a258989294812",
				FileMetadata: "YXJ0aWZhY3QgbWV0YWRhdGE=",
				URL:          "/persist/patchEnvelopesCache/textfile2.txt",
			},
		},
	}
	pe = []types.PatchEnvelopeInfo{peInfo}

	got := types.FindPatchEnvelopesByApp(pe, "17daa0ff-39d6-42be-a537-44c974276aec")
	assert.Equal(t, got, []types.PatchEnvelopeInfo{peInfo})

	assert.Equal(t, peInfo, *types.FindPatchEnvelopeByID(got, "699fbdb2-e455-448f-84f5-68e547ec1305"))

}

func TestFindPatchEnvelopeById(t *testing.T) {
	t.Parallel()

	g := gomega.NewGomegaWithT(t)

	pe1 := types.PatchEnvelopeInfo{
		PatchID: "PatchId1",
	}
	pe2 := types.PatchEnvelopeInfo{
		PatchID: "PatchId2",
	}
	pe3 := types.PatchEnvelopeInfo{
		PatchID: "PatchId3",
	}

	pes := []types.PatchEnvelopeInfo{pe1, pe2, pe3}

	got := types.FindPatchEnvelopeByID(pes, pe1.PatchID)
	g.Expect(got).To(gomega.BeEquivalentTo(&pe1))

	got = types.FindPatchEnvelopeByID(pes, pe2.PatchID)
	g.Expect(got).To(gomega.BeEquivalentTo(&pe2))

	got = types.FindPatchEnvelopeByID(pes, "NonExistingPatchId")
	g.Expect(got).To(gomega.BeNil())
}

func TestPatchEnvelopes(t *testing.T) {
	t.Parallel()

	g := gomega.NewGomegaWithT(t)

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "petypes", 1234)
	peStore := types.NewPatchEnvelopes(log)

	u := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	u1, _ := uuid.FromString(u)
	filecontent := "blobfilecontent"
	path, err := os.MkdirTemp("", "testFolder")
	f := filepath.Join(path, "blobfile")
	g.Expect(err).To(gomega.BeNil())

	err = os.WriteFile(f, []byte(filecontent), 0600)
	g.Expect(err).To(gomega.BeNil())

	defer os.Remove(f)

	volumeStatuses := []types.VolumeStatus{
		{
			VolumeID:     u1,
			State:        types.INSTALLED,
			FileLocation: f,
		},
	}

	peInfo := []types.PatchEnvelopeInfo{
		{
			PatchID:     "PatchId1",
			AllowedApps: []string{u},
			BinaryBlobs: []types.BinaryBlobCompleted{
				{
					FileName:     "TestFileName",
					FileSha:      "TestFileSha",
					FileMetadata: "TestFileMetadata",
					URL:          "./testurl",
				},
			},
			VolumeRefs: []types.BinaryBlobVolumeRef{
				{
					FileName:     "VolTestFileName",
					ImageName:    "VolTestImageName",
					FileMetadata: "VolTestFileMetadata",
					ImageID:      u,
				},
			},
		},
	}

	peStore.Wg.Add(1)
	go func() {
		for _, vs := range volumeStatuses {
			peStore.VolumeStatusCh <- types.PatchEnvelopesVsCh{
				Vs:     vs,
				Action: types.PatchEnvelopesVsChActionPut,
			}
		}
	}()

	peStore.Wg.Add(1)
	go func() {
		peStore.PatchEnvelopeInfoCh <- peInfo
	}()

	peStore.Wg.Wait()

	g.Expect(peStore.Get(u)).To(gomega.BeEquivalentTo(
		[]types.PatchEnvelopeInfo{
			{
				PatchID:     "PatchId1",
				AllowedApps: []string{u},
				BinaryBlobs: []types.BinaryBlobCompleted{
					{
						FileName:     "TestFileName",
						FileSha:      "TestFileSha",
						FileMetadata: "TestFileMetadata",
						URL:          "./testurl",
					},
					{
						FileName: "VolTestFileName",
						//pragma: allowlist nextline secret
						FileSha:      "2c096be52e6f8510b4deac978f700dd103f144539e4ccdede5b075ce55dca980",
						FileMetadata: "VolTestFileMetadata",
						URL:          f,
					},
				},
				VolumeRefs: []types.BinaryBlobVolumeRef{
					{
						FileName:     "VolTestFileName",
						ImageName:    "VolTestImageName",
						FileMetadata: "VolTestFileMetadata",
						ImageID:      u,
					},
				},
			},
		}))
}
