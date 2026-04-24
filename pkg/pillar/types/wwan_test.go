// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WwanConfig.GetNetworkConfig

func TestWwanConfigGetNetworkConfig(t *testing.T) {
	cfg := WwanConfig{
		Networks: []WwanNetworkConfig{
			{LogicalLabel: "wwan0"},
			{LogicalLabel: "wwan1"},
		},
	}

	nc := cfg.GetNetworkConfig("wwan0")
	require.NotNil(t, nc)
	assert.Equal(t, "wwan0", nc.LogicalLabel)

	assert.Nil(t, cfg.GetNetworkConfig("missing"))
}

// WwanStatus.GetNetworkStatus

func TestWwanStatusGetNetworkStatus(t *testing.T) {
	ws := WwanStatus{
		Networks: []WwanNetworkStatus{
			{LogicalLabel: "wwan0"},
			{LogicalLabel: "wwan1"},
		},
	}

	ns := ws.GetNetworkStatus("wwan1")
	require.NotNil(t, ns)
	assert.Equal(t, "wwan1", ns.LogicalLabel)

	assert.Nil(t, ws.GetNetworkStatus("missing"))
}

// WwanNetworkConfig.Equal

func TestWwanNetworkConfigEqual(t *testing.T) {
	wnc1 := WwanNetworkConfig{
		LogicalLabel: "wwan0",
		MTU:          1500,
		RouteMetric:  100,
	}
	wnc2 := wnc1
	assert.True(t, wnc1.Equal(wnc2))

	wnc2.LogicalLabel = "wwan1"
	assert.False(t, wnc1.Equal(wnc2))

	wnc2 = wnc1
	wnc2.MTU = 1400
	assert.False(t, wnc1.Equal(wnc2))
}

// WwanAuthProtocol.FromProto and ToProto

func TestWwanAuthProtocolFromProto(t *testing.T) {
	cases := []struct {
		proto evecommon.CellularAuthProtocol
		want  WwanAuthProtocol
		isErr bool
	}{
		{evecommon.CellularAuthProtocol_CELLULAR_AUTH_PROTOCOL_NONE, WwanAuthProtocolNone, false},
		{evecommon.CellularAuthProtocol_CELLULAR_AUTH_PROTOCOL_PAP, WwanAuthProtocolPAP, false},
		{evecommon.CellularAuthProtocol_CELLULAR_AUTH_PROTOCOL_CHAP, WwanAuthProtocolCHAP, false},
		{evecommon.CellularAuthProtocol_CELLULAR_AUTH_PROTOCOL_PAP_AND_CHAP, WwanAuthProtocolPAPAndCHAP, false},
		{evecommon.CellularAuthProtocol(99), WwanAuthProtocolNone, true},
	}
	for _, tc := range cases {
		var wp WwanAuthProtocol
		err := wp.FromProto(tc.proto)
		assert.Equal(t, tc.want, wp)
		if tc.isErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestWwanAuthProtocolToProto(t *testing.T) {
	cases := []struct {
		ap   WwanAuthProtocol
		want evecommon.CellularAuthProtocol
	}{
		{WwanAuthProtocolNone, evecommon.CellularAuthProtocol_CELLULAR_AUTH_PROTOCOL_NONE},
		{WwanAuthProtocolPAP, evecommon.CellularAuthProtocol_CELLULAR_AUTH_PROTOCOL_PAP},
		{WwanAuthProtocolCHAP, evecommon.CellularAuthProtocol_CELLULAR_AUTH_PROTOCOL_CHAP},
		{WwanAuthProtocolPAPAndCHAP, evecommon.CellularAuthProtocol_CELLULAR_AUTH_PROTOCOL_PAP_AND_CHAP},
		{WwanAuthProtocol("unknown"), evecommon.CellularAuthProtocol_CELLULAR_AUTH_PROTOCOL_NONE},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.ap.ToProto())
	}
}

// WwanIPType.FromProto and ToProto

func TestWwanIPTypeFromProto(t *testing.T) {
	cases := []struct {
		proto evecommon.CellularIPType
		want  WwanIPType
		isErr bool
	}{
		{evecommon.CellularIPType_CELLULAR_IP_TYPE_UNSPECIFIED, WwanIPTypeUnspecified, false},
		{evecommon.CellularIPType_CELLULAR_IP_TYPE_IPV4, WwanIPTypeIPv4, false},
		{evecommon.CellularIPType_CELLULAR_IP_TYPE_IPV4_AND_IPV6, WwanIPTypeIPv4AndIPv6, false},
		{evecommon.CellularIPType_CELLULAR_IP_TYPE_IPV6, WwanIPTypeIPv6, false},
		{evecommon.CellularIPType(99), WwanIPTypeUnspecified, true},
	}
	for _, tc := range cases {
		var ipt WwanIPType
		err := ipt.FromProto(tc.proto)
		assert.Equal(t, tc.want, ipt)
		if tc.isErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}
