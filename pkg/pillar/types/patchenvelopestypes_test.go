// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types_test

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/onsi/gomega"
)

func TestPatchEnvelopeInfoList(t *testing.T) {
	t.Parallel()

	g := gomega.NewGomegaWithT(t)
	pe := types.PatchEnvelopeInfoList{}

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

	pe.Envelopes = append(pe.Envelopes, peInfo)

	g.Expect(pe.Get(uuidString)).To(gomega.BeEquivalentTo([]types.PatchEnvelopeInfo{peInfo}))
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

	pes := types.PatchEnvelopeInfoList{
		Envelopes: []types.PatchEnvelopeInfo{pe1, pe2, pe3},
	}

	got := pes.FindPatchEnvelopeByID(pe1.PatchID)
	g.Expect(got).To(gomega.BeEquivalentTo(&pe1))

	got = pes.FindPatchEnvelopeByID(pe2.PatchID)
	g.Expect(got).To(gomega.BeEquivalentTo(&pe2))

	got = pes.FindPatchEnvelopeByID("NonExistingPatchId")
	g.Expect(got).To(gomega.BeNil())
}
