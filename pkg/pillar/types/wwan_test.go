// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
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

// WwanMetrics helpers

func TestWwanMetricsGetNetworkMetrics(t *testing.T) {
	wm := WwanMetrics{
		Networks: []WwanNetworkMetrics{
			{LogicalLabel: "wwan0"},
			{LogicalLabel: "wwan1"},
		},
	}
	m := wm.GetNetworkMetrics("wwan1")
	require.NotNil(t, m)
	assert.Equal(t, "wwan1", m.LogicalLabel)

	assert.Nil(t, wm.GetNetworkMetrics("missing"))
}

func TestWwanMetricsLookupNetworkMetrics(t *testing.T) {
	wm := WwanMetrics{
		Networks: []WwanNetworkMetrics{
			{LogicalLabel: "wwan0"},
		},
	}
	m, ok := wm.LookupNetworkMetrics("wwan0")
	assert.True(t, ok)
	assert.Equal(t, "wwan0", m.LogicalLabel)

	_, ok = wm.LookupNetworkMetrics("missing")
	assert.False(t, ok)
}

func TestWwanMetricsEqual(t *testing.T) {
	wm1 := WwanMetrics{
		Networks: []WwanNetworkMetrics{
			{LogicalLabel: "wwan0"},
		},
	}
	wm2 := WwanMetrics{
		Networks: []WwanNetworkMetrics{
			{LogicalLabel: "wwan0"},
		},
	}
	assert.True(t, wm1.Equal(wm2))

	wm2.Networks[0].LogicalLabel = "wwan1"
	assert.False(t, wm1.Equal(wm2))
}

// WwanIPSettings.Equal

func TestWwanIPSettingsEqual(t *testing.T) {
	_, net1, _ := net.ParseCIDR("10.0.0.0/24")
	s1 := WwanIPSettings{
		Address: net1,
		Gateway: net.ParseIP("10.0.0.1"),
		MTU:     1500,
	}
	s2 := s1
	assert.True(t, s1.Equal(s2))

	s2.MTU = 1400
	assert.False(t, s1.Equal(s2))

	s2 = s1
	s2.Gateway = net.ParseIP("10.0.0.2")
	assert.False(t, s1.Equal(s2))
}

// WwanNetworkStatus.Equal

func TestWwanNetworkStatusEqual(t *testing.T) {
	wns1 := WwanNetworkStatus{LogicalLabel: "wwan0"}
	wns2 := wns1
	assert.True(t, wns1.Equal(wns2))

	wns2.LogicalLabel = "wwan1"
	assert.False(t, wns1.Equal(wns2))
}

// WwanConfig.Equal

func TestWwanConfigEqual(t *testing.T) {
	wc1 := WwanConfig{
		DPCKey:      "key1",
		RadioSilence: false,
	}
	wc2 := wc1
	assert.True(t, wc1.Equal(wc2))

	wc2.DPCKey = "key2"
	assert.False(t, wc1.Equal(wc2))

	wc2 = wc1
	wc2.RadioSilence = true
	assert.False(t, wc1.Equal(wc2))
}

// WwanStatus.Equal

func TestWwanStatusEqual(t *testing.T) {
	ws1 := WwanStatus{DPCKey: "key1"}
	ws2 := ws1
	assert.True(t, ws1.Equal(ws2))

	ws2.DPCKey = "key2"
	assert.False(t, ws1.Equal(ws2))
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
