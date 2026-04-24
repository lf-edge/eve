// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types_test

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	g.Expect(pe.Get(uuidString).Envelopes).To(gomega.BeEquivalentTo([]types.PatchEnvelopeInfo{peInfo}))
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

// PatchEnvelopeInfo.Size

func TestPatchEnvelopeInfoSize(t *testing.T) {
	pe := types.PatchEnvelopeInfo{}
	assert.Equal(t, int64(0), pe.Size())

	pe.BinaryBlobs = []types.BinaryBlobCompleted{
		{FileName: "a", Size: 100},
		{FileName: "b", Size: 200},
		{FileName: "c", Size: 50},
	}
	assert.Equal(t, int64(350), pe.Size())
}

// CompletedBinaryBlobIdxByName

func TestCompletedBinaryBlobIdxByName(t *testing.T) {
	blobs := []types.BinaryBlobCompleted{
		{FileName: "alpha"},
		{FileName: "beta"},
		{FileName: "gamma"},
	}

	assert.Equal(t, 0, types.CompletedBinaryBlobIdxByName(blobs, "alpha"))
	assert.Equal(t, 1, types.CompletedBinaryBlobIdxByName(blobs, "beta"))
	assert.Equal(t, 2, types.CompletedBinaryBlobIdxByName(blobs, "gamma"))
	assert.Equal(t, -1, types.CompletedBinaryBlobIdxByName(blobs, "missing"))
	assert.Equal(t, -1, types.CompletedBinaryBlobIdxByName(nil, "alpha"))
}

// CompletedCipherBlobIdxByName

func TestCompletedCipherBlobIdxByName(t *testing.T) {
	blobs := []types.BinaryCipherBlob{
		{Inline: &types.BinaryBlobCompleted{FileName: "file0"}},
		{Inline: nil},
		{Inline: &types.BinaryBlobCompleted{FileName: "file2"}},
	}

	assert.Equal(t, 0, types.CompletedCipherBlobIdxByName(blobs, "file0"))
	assert.Equal(t, 2, types.CompletedCipherBlobIdxByName(blobs, "file2"))
	// nil Inline is skipped
	assert.Equal(t, -1, types.CompletedCipherBlobIdxByName(blobs, ""))
	assert.Equal(t, -1, types.CompletedCipherBlobIdxByName(blobs, "missing"))
}

// PatchEnvelopeUsageFromInfo

func TestPatchEnvelopeUsageFromInfo(t *testing.T) {
	app1 := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	app2 := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

	pe := types.PatchEnvelopeInfo{
		PatchID:     "patch-1",
		Version:     "v2",
		AllowedApps: []string{app1, app2},
	}

	usages := types.PatchEnvelopeUsageFromInfo(pe)
	require.Len(t, usages, 2)

	assert.Equal(t, app1, usages[0].AppUUID)
	assert.Equal(t, "patch-1", usages[0].PatchID)
	assert.Equal(t, "v2", usages[0].Version)

	assert.Equal(t, app2, usages[1].AppUUID)
	assert.Equal(t, "patch-1", usages[1].PatchID)
	assert.Equal(t, "v2", usages[1].Version)

	// No allowed apps → empty slice (not nil)
	pe.AllowedApps = nil
	usages = types.PatchEnvelopeUsageFromInfo(pe)
	assert.Len(t, usages, 0)
}
