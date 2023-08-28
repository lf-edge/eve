// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPatchEnvelopes(t *testing.T) {
	pe := NewPatchEnvelopes()
	peInfo := PatchEnvelopeInfo{
		PatchId: "PatchId1",
		BinaryBlobs: []BinaryBlob{
			{
				FileName:     "TestFileName",
				FileSha:      "TestFileSha",
				FileMetadata: "TestFileMetadata",
				Url:          "testurl",
			},
		},
	}
	uuidString := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	allowedApps := []string{uuidString}

	pe.Add(peInfo, allowedApps)

	u1 := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	expected := make(map[string][]PatchEnvelopeInfo)
	expected[u1] = append(expected[u1], peInfo)

	assert.Equal(t, true, reflect.DeepEqual(expected, pe.AppsToEnvelopes))

	assert.Equal(t, true, reflect.DeepEqual([]PatchEnvelopeInfo{peInfo}, pe.Get(u1)))
}
