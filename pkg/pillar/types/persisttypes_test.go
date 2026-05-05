// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ParsePersistType and PersistType.String

func TestParsePersistType(t *testing.T) {
	cases := []struct {
		input string
		want  PersistType
	}{
		{"ext3", PersistExt3},
		{"ext4", PersistExt4},
		{"zfs", PersistZFS},
		{"unknown", PersistUnknown},
		{"", PersistUnknown},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, ParsePersistType(tc.input), "input=%q", tc.input)
	}
}

func TestPersistTypeString(t *testing.T) {
	assert.Equal(t, "ext3", PersistExt3.String())
	assert.Equal(t, "ext4", PersistExt4.String())
	assert.Equal(t, "zfs", PersistZFS.String())
	assert.Equal(t, "", PersistUnknown.String())
}
