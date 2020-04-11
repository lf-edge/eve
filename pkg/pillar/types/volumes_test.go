// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"crypto/sha256"
	"fmt"
	"testing"

	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestVolumeKey(t *testing.T) {

	// Generate some random UUIDs and hash
	u1 := uuid.NewV4()
	u2 := uuid.NewV4()
	h := sha256.New()
	h.Write(u1.Bytes())
	h.Write(u2.Bytes())
	hash := h.Sum(nil)
	sha256 := fmt.Sprintf("%x", hash)

	testMatrix := map[string]struct {
		inputSha        string
		inputAppInstID  uuid.UUID
		inputVolumeID   uuid.UUID
		purgeCounter    uint32 // Input and output
		expectedValue   string
		decodeValue     string
		expectSucceed   bool
		outputSha       string
		outputAppInstID uuid.UUID
		outputVolumeID  uuid.UUID
	}{
		"onlySha": {
			inputSha:      sha256,
			expectedValue: sha256 + "+" + nilUUID.String(),
			expectSucceed: true,
			outputSha:     sha256,
		},
		"sha+appInstID": {
			inputSha:        sha256,
			inputAppInstID:  u1,
			expectedValue:   sha256 + "+" + u1.String(),
			expectSucceed:   true,
			outputSha:       sha256,
			outputAppInstID: u1,
		},
		"sha+volumeID": {
			inputSha:      sha256,
			inputVolumeID: u1,
			expectedValue: sha256 + "+" + nilUUID.String(),
			expectSucceed: true,
			outputSha:     sha256,
		},
		"sha+appInstID+volumeID": {
			inputSha:        sha256,
			inputAppInstID:  u1,
			inputVolumeID:   u2,
			expectedValue:   sha256 + "+" + u1.String(),
			expectSucceed:   true,
			outputSha:       sha256,
			outputAppInstID: u1,
		},
		"appInstID": {
			inputAppInstID:  u1,
			expectedValue:   u1.String() + ":" + nilUUID.String(),
			expectSucceed:   true,
			outputAppInstID: u1,
		},
		"volumeID": {
			inputVolumeID:  u1,
			expectedValue:  u1.String(),
			expectSucceed:  true,
			outputVolumeID: u1,
		},
		"appInstID+volumeID": {
			inputAppInstID:  u1,
			inputVolumeID:   u2,
			expectedValue:   u1.String() + ":" + u2.String(),
			expectSucceed:   true,
			outputAppInstID: u1,
			outputVolumeID:  u2,
		},
		"Sha+purge": {
			inputSha:      sha256,
			purgeCounter:  3,
			expectedValue: sha256 + "+" + nilUUID.String() + ".3",
			expectSucceed: true,
			outputSha:     sha256,
		},
		"sha+appInstID+purge": {
			inputSha:        sha256,
			inputAppInstID:  u1,
			purgeCounter:    7,
			expectedValue:   sha256 + "+" + u1.String() + ".7",
			expectSucceed:   true,
			outputSha:       sha256,
			outputAppInstID: u1,
		},
		"sha+volumeID+purge": {
			inputSha:      sha256,
			inputVolumeID: u1,
			purgeCounter:  937,
			expectedValue: sha256 + "+" + nilUUID.String() + ".937",
			expectSucceed: true,
			outputSha:     sha256,
		},
		"sha+appInstID+volumeID+purge": {
			inputSha:        sha256,
			inputAppInstID:  u1,
			inputVolumeID:   u2,
			purgeCounter:    3,
			expectedValue:   sha256 + "+" + u1.String() + ".3",
			expectSucceed:   true,
			outputSha:       sha256,
			outputAppInstID: u1,
		},
		"appInstID+purge": {
			inputAppInstID:  u1,
			purgeCounter:    3,
			expectedValue:   u1.String() + ":" + nilUUID.String() + ".3",
			expectSucceed:   true,
			outputAppInstID: u1,
		},
		"volumeID+purge": {
			inputVolumeID:  u1,
			purgeCounter:   3,
			expectedValue:  u1.String() + ".3",
			expectSucceed:  true,
			outputVolumeID: u1,
		},
		"appInstID+volumeID+purge": {
			inputAppInstID:  u1,
			inputVolumeID:   u2,
			purgeCounter:    3,
			expectedValue:   u1.String() + ":" + u2.String() + ".3",
			expectSucceed:   true,
			outputAppInstID: u1,
			outputVolumeID:  u2,
		},
		"badParseUUIDlength": {
			expectedValue: nilUUID.String(),
			decodeValue:   "0" + nilUUID.String(),
		},
		"badParseUUID": {
			expectedValue: nilUUID.String(),
			decodeValue:   "12+xyzzy",
		},
		"badParseAppInstID": {
			expectedValue: nilUUID.String(),
			decodeValue:   u1.String() + ":xyzzy",
		},
		"badParseVolumeID": {
			expectedValue: nilUUID.String(),
			decodeValue:   "xyzzy:" + u1.String(),
		},
		"badParsePurgeCounter": {
			expectedValue: nilUUID.String(),
			decodeValue:   u1.String() + ".abc",
		},
		"negativeParsePurgeCounter": {
			expectedValue: nilUUID.String(),
			decodeValue:   u1.String() + ".-3",
		},
	}

	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := VolumeKeyFromParts(test.inputSha, test.inputAppInstID,
			test.inputVolumeID, test.purgeCounter)
		assert.Equal(t, test.expectedValue, value)
		if test.decodeValue != "" {
			value = test.decodeValue
		}
		s, ua, uv, pc, err := VolumeKeyToParts(value)
		succeeded := (err == nil)
		assert.Equal(t, test.expectSucceed, succeeded)
		assert.Equal(t, test.outputSha, s)
		assert.Equal(t, test.outputAppInstID, ua)
		assert.Equal(t, test.outputVolumeID, uv)
		assert.Equal(t, test.purgeCounter, pc)
	}
}
