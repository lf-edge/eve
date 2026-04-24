// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PhysicalIOAdapterList.LookupAdapter

func TestPhysicalIOAdapterListLookupAdapter(t *testing.T) {
	list := PhysicalIOAdapterList{
		AdapterList: []PhysicalIOAdapter{
			{Phylabel: "eth0"},
			{Phylabel: "eth1"},
			{Phylabel: "usb0"},
		},
	}

	got := list.LookupAdapter("eth0")
	require.NotNil(t, got)
	assert.Equal(t, "eth0", got.Phylabel)

	got = list.LookupAdapter("usb0")
	require.NotNil(t, got)
	assert.Equal(t, "usb0", got.Phylabel)

	assert.Nil(t, list.LookupAdapter("eth9"))
}
