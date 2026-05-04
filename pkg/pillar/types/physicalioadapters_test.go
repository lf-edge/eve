// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
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

// PhysicalIOAdapterList.Key / LogKey

func TestPhysicalIOAdapterListLogKey(t *testing.T) {
	list := PhysicalIOAdapterList{}
	assert.Equal(t, "global", list.Key())
	assert.Contains(t, list.LogKey(), "global")
}

// PhysicalIOAdapterList LogCreate / LogModify / LogDelete

func TestPhysicalIOAdapterListLogCreateModifyDelete(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.TraceLevel)
	log := base.NewSourceLogObject(logger, t.Name(), 0) //nolint:staticcheck
	list := PhysicalIOAdapterList{}
	list.LogCreate(log)
	assert.NotEmpty(t, buf.String())
	list.LogModify(log, list)
	list.LogDelete(log)
}
