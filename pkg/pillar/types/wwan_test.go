// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
	"testing"
	"time"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
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

// WwanProvider.ToProto

func TestWwanProviderToProto(t *testing.T) {
	wp := WwanProvider{
		PLMN:           "310410",
		Description:    "AT&T",
		CurrentServing: true,
		Roaming:        false,
		Forbidden:      false,
	}
	got := wp.ToProto()
	require.NotNil(t, got)
	assert.Equal(t, "310410", got.Plmn)
	assert.Equal(t, "AT&T", got.Description)
	assert.True(t, got.CurrentServing)
	assert.False(t, got.Roaming)
	assert.False(t, got.Forbidden)
}

// WwanCellModule.ToProto

func TestWwanCellModuleToProto(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 0) //nolint:staticcheck
	m := WwanCellModule{
		Name:            "modem0",
		IMEI:            "123456789012345",
		Revision:        "v1.0",
		Model:           "EM7455",
		Manufacturer:    "Sierra Wireless",
		OpMode:          WwanOpModeOnline,
		ControlProtocol: WwanCtrlProtQMI,
	}
	got := m.ToProto(log)
	require.NotNil(t, got)
	assert.Equal(t, "modem0", got.Name)
	assert.Equal(t, "123456789012345", got.Imei)
	assert.Equal(t, info.ZCellularOperatingState_Z_CELLULAR_OPERATING_STATE_ONLINE, got.OperatingState)
	assert.Equal(t, info.ZCellularControlProtocol_Z_CELLULAR_CONTROL_PROTOCOL_QMI, got.ControlProtocol)
}

// BearerType.ToProto

func TestBearerTypeToProto(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 0) //nolint:staticcheck
	cases := []struct {
		in   BearerType
		want evecommon.BearerType
	}{
		{BearerTypeUnspecified, evecommon.BearerType_BEARER_TYPE_UNSPECIFIED},
		{BearerTypeAttach, evecommon.BearerType_BEARER_TYPE_ATTACH},
		{BearerTypeDefault, evecommon.BearerType_BEARER_TYPE_DEFAULT},
		{BearerTypeDedicated, evecommon.BearerType_BEARER_TYPE_DEDICATED},
		{BearerType(99), evecommon.BearerType_BEARER_TYPE_UNSPECIFIED},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.in.ToProto(log))
	}
}

// WwanNetworkStatus.CellProvidersToProto

func TestWwanNetworkStatusCellProvidersToProto(t *testing.T) {
	visible := WwanProvider{PLMN: "310410", CurrentServing: false}
	current := WwanProvider{PLMN: "310260", CurrentServing: true}
	wns := WwanNetworkStatus{
		CurrentProvider:  current,
		VisibleProviders: []WwanProvider{visible},
	}

	providers := wns.CellProvidersToProto()
	// Visible + current (not in visible list → appended)
	require.Len(t, providers, 2)
	assert.Equal(t, "310410", providers[0].Plmn)
	assert.Equal(t, "310260", providers[1].Plmn)

	// Current already in VisibleProviders → no duplicate
	wns2 := WwanNetworkStatus{
		CurrentProvider:  visible,
		VisibleProviders: []WwanProvider{visible},
	}
	providers2 := wns2.CellProvidersToProto()
	assert.Len(t, providers2, 1)
}

// WwanNetworkStatus.SimCardsToProto

func TestWwanNetworkStatusSimCardsToProto(t *testing.T) {
	wns := WwanNetworkStatus{
		Module: WwanCellModule{Name: "modem0"},
		SimCards: []WwanSimCard{
			{Name: "sim0", SlotNumber: 1, SlotActivated: true, ICCID: "89011200000002345678", IMSI: "310410123456789"},
		},
	}
	cards := wns.SimCardsToProto()
	require.Len(t, cards, 1)
	assert.Equal(t, "sim0", cards[0].Name)
	assert.Equal(t, "modem0", cards[0].CellModuleName)
	assert.Equal(t, "89011200000002345678", cards[0].Iccid)
	assert.Equal(t, "310410123456789", cards[0].Imsi)
	assert.True(t, cards[0].SlotActivated)
}

// WwanNetworkStatus.CellBearersToProto

func TestWwanNetworkStatusCellBearersToProto(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 0) //nolint:staticcheck
	wns := WwanNetworkStatus{
		Bearers: []WwanBearer{
			{APN: "internet", Type: BearerTypeDefault, Connected: true},
		},
	}
	bearers := wns.CellBearersToProto(log)
	require.Len(t, bearers, 1)
	assert.Equal(t, "internet", bearers[0].Apn)
	assert.True(t, bearers[0].Connected)
	assert.Equal(t, evecommon.BearerType_BEARER_TYPE_DEFAULT, bearers[0].BearerType)
}

// WwanNetworkStatus.CellProfilesToProto

func TestWwanNetworkStatusCellProfilesToProto(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 0) //nolint:staticcheck
	wns := WwanNetworkStatus{
		Profiles: []WwanProfile{
			{Name: "default", APN: "internet", BearerType: BearerTypeDefault, ForbidRoaming: false},
		},
	}
	profiles := wns.CellProfilesToProto(log)
	require.Len(t, profiles, 1)
	assert.Equal(t, "default", profiles[0].ProfileName)
	assert.Equal(t, "internet", profiles[0].Apn)
	assert.Equal(t, evecommon.BearerType_BEARER_TYPE_DEFAULT, profiles[0].BearerType)
	assert.False(t, profiles[0].ForbidRoaming)
}

// WwanMetrics.ToProto

func TestWwanMetricsToProto(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 0) //nolint:staticcheck
	wm := WwanMetrics{
		Networks: []WwanNetworkMetrics{
			{
				LogicalLabel: "wwan0",
				SignalInfo:   WwanSignalInfo{RSSI: -70, RSRQ: -10, RSRP: -100, SNR: 15},
				PacketStats:  WwanPacketStats{RxBytes: 1000, TxBytes: 500},
			},
			// Empty logical label → skipped in ToProto
			{LogicalLabel: ""},
		},
	}
	protoMetrics := wm.ToProto(log)
	require.Len(t, protoMetrics, 1)
	m := protoMetrics[0]
	assert.Equal(t, "wwan0", m.Logicallabel)
	assert.Equal(t, int32(-70), m.SignalStrength.Rssi)
	assert.Equal(t, uint64(1000), m.PacketStats.Rx.TotalBytes)
	assert.Equal(t, uint64(500), m.PacketStats.Tx.TotalBytes)

	// Verify the metrics package import is used
	var _ []*metrics.CellularMetric = protoMetrics
}

// WwanStatus.DoSanitize

func TestWwanStatusDoSanitize(t *testing.T) {
	ws := WwanStatus{
		Networks: []WwanNetworkStatus{
			{
				Module: WwanCellModule{
					IMEI:  "123456789012345",
					Model: "EM7455",
				},
				SimCards: []WwanSimCard{
					{SlotNumber: 1, ICCID: "89011200000002345678"},
					{SlotNumber: 2}, // no ICCID → use module name + slot
				},
			},
		},
	}

	ws.DoSanitize()

	// Module name set from IMEI (first choice)
	assert.Equal(t, "123456789012345", ws.Networks[0].Module.Name)

	// SIM card names set: first from ICCID, second from module name + slot
	assert.Equal(t, "89011200000002345678", ws.Networks[0].SimCards[0].Name)
	assert.Contains(t, ws.Networks[0].SimCards[1].Name, "2") // slot number 2

	// Pre-existing names are preserved
	ws2 := WwanStatus{
		Networks: []WwanNetworkStatus{
			{
				Module: WwanCellModule{Name: "already-set", IMEI: "unused"},
				SimCards: []WwanSimCard{
					{Name: "sim-already-named"},
				},
			},
		},
	}
	ws2.DoSanitize()
	assert.Equal(t, "already-set", ws2.Networks[0].Module.Name)
	assert.Equal(t, "sim-already-named", ws2.Networks[0].SimCards[0].Name)

	// Unique model → use model as module name
	ws3 := WwanStatus{
		Networks: []WwanNetworkStatus{
			{Module: WwanCellModule{Model: "EM7600"}},
		},
	}
	ws3.DoSanitize()
	assert.Equal(t, "EM7600", ws3.Networks[0].Module.Name)
}

// WwanIPType.ToProto — all cases

func TestWwanIPTypeToProto(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 0) //nolint:staticcheck
	cases := []struct {
		in   WwanIPType
		want evecommon.CellularIPType
	}{
		{WwanIPTypeUnspecified, evecommon.CellularIPType_CELLULAR_IP_TYPE_UNSPECIFIED},
		{WwanIPTypeIPv4, evecommon.CellularIPType_CELLULAR_IP_TYPE_IPV4},
		{WwanIPTypeIPv4AndIPv6, evecommon.CellularIPType_CELLULAR_IP_TYPE_IPV4_AND_IPV6},
		{WwanIPTypeIPv6, evecommon.CellularIPType_CELLULAR_IP_TYPE_IPV6},
		{WwanIPType("unknown"), evecommon.CellularIPType_CELLULAR_IP_TYPE_UNSPECIFIED},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.in.ToProto(log))
	}
}

// WwanCellModule.ToProto — additional op modes and control protocols

func TestWwanCellModuleToProtoAllModes(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 0) //nolint:staticcheck

	opModeCases := []struct {
		opMode WwanOpMode
		want   info.ZCellularOperatingState
	}{
		{WwanOpModeUnspecified, info.ZCellularOperatingState_Z_CELLULAR_OPERATING_STATE_UNSPECIFIED},
		{WwanOpModeConnected, info.ZCellularOperatingState_Z_CELLULAR_OPERATING_STATE_ONLINE_AND_CONNECTED},
		{WwanOpModeRadioOff, info.ZCellularOperatingState_Z_CELLULAR_OPERATING_STATE_RADIO_OFF},
		{WwanOpModeOffline, info.ZCellularOperatingState_Z_CELLULAR_OPERATING_STATE_OFFLINE},
		{WwanOpModeUnrecognized, info.ZCellularOperatingState_Z_CELLULAR_OPERATING_STATE_UNRECOGNIZED},
	}
	for _, tc := range opModeCases {
		m := WwanCellModule{OpMode: tc.opMode, ControlProtocol: WwanCtrlProtQMI}
		got := m.ToProto(log)
		assert.Equal(t, tc.want, got.OperatingState, "opMode=%v", tc.opMode)
	}

	// MBIM control protocol
	m := WwanCellModule{OpMode: WwanOpModeOnline, ControlProtocol: WwanCtrlProtMBIM}
	got := m.ToProto(log)
	assert.Equal(t, info.ZCellularControlProtocol_Z_CELLULAR_CONTROL_PROTOCOL_MBIM, got.ControlProtocol)
}

// WwanNetworkStatus.Equal — additional branches

func TestWwanNetworkStatusEqualAdditionalBranches(t *testing.T) {
	wns1 := WwanNetworkStatus{
		LogicalLabel:     "wwan0",
		ConfigError:      "",
		CurrentProvider:  WwanProvider{PLMN: "310410"},
		VisibleProviders: []WwanProvider{{PLMN: "310410"}},
	}
	wns2 := wns1
	assert.True(t, wns1.Equal(wns2))

	// Different ConfigError
	wns2.ConfigError = "some error"
	assert.False(t, wns1.Equal(wns2))
	wns2.ConfigError = ""

	// Different CurrentProvider
	wns2.CurrentProvider = WwanProvider{PLMN: "310260"}
	assert.False(t, wns1.Equal(wns2))
	wns2.CurrentProvider = wns1.CurrentProvider

	// Different Module
	wns2.Module = WwanCellModule{Name: "modem0"}
	assert.False(t, wns1.Equal(wns2))
}

// WwanNetworkStatus.Equal — remaining branches

func TestWwanNetworkStatusEqualRemainingBranches(t *testing.T) {
	base := WwanNetworkStatus{LogicalLabel: "wwan0"}

	// PhysAddrs diff
	s2 := base
	s2.PhysAddrs = WwanPhysAddrs{Interface: "wwan1"}
	assert.False(t, base.Equal(s2))

	// SimCards diff
	s2 = base
	s2.SimCards = []WwanSimCard{{ICCID: "1234"}}
	assert.False(t, base.Equal(s2))

	// ProbeError diff
	s2 = base
	s2.ProbeError = "no signal"
	assert.False(t, base.Equal(s2))

	// VisibleProviders diff
	s2 = base
	s2.VisibleProviders = []WwanProvider{{PLMN: "310260"}}
	assert.False(t, base.Equal(s2))

	// CurrentRATs diff
	s2 = base
	s2.CurrentRATs = []WwanRAT{WwanRATLTE}
	assert.False(t, base.Equal(s2))

	// ConnectedAt diff
	s2 = base
	s2.ConnectedAt = 12345
	assert.False(t, base.Equal(s2))

	// LocationTracking diff
	s2 = base
	s2.LocationTracking = true
	assert.False(t, base.Equal(s2))

	// Bearers diff
	s2 = base
	s2.Bearers = []WwanBearer{{APN: "internet"}}
	assert.False(t, base.Equal(s2))

	// Profiles diff
	s2 = base
	s2.Profiles = []WwanProfile{{Name: "default"}}
	assert.False(t, base.Equal(s2))
}

// WwanNetworkConfig.Equal — remaining branches

func TestWwanNetworkConfigEqualRemainingBranches(t *testing.T) {
	base := WwanNetworkConfig{LogicalLabel: "wwan0"}

	// PhysAddrs diff
	s2 := base
	s2.PhysAddrs = WwanPhysAddrs{Interface: "wwan1"}
	assert.False(t, base.Equal(s2))

	// AccessPoint.Equal returns false
	s2 = base
	s2.AccessPoint = CellularAccessPoint{APN: "internet"}
	assert.False(t, base.Equal(s2))

	// Proxies diff
	s2 = base
	s2.Proxies = []ProxyEntry{{Server: "proxy.example.com", Port: 8080}}
	assert.False(t, base.Equal(s2))

	// Probe diff
	s2 = base
	s2.Probe = WwanProbe{Disable: true}
	assert.False(t, base.Equal(s2))

	// LocationTracking diff
	s2 = base
	s2.LocationTracking = true
	assert.False(t, base.Equal(s2))

	// RouteMetric diff
	s2 = base
	s2.RouteMetric = 200
	assert.False(t, base.Equal(s2))
}

// WwanConfig.Equal — timestamp and networks branches

func TestWwanConfigEqualTimestampNetworks(t *testing.T) {
	now := time.Now()
	wc1 := WwanConfig{DPCKey: "key1"}

	// DPCTimestamp diff
	wc2 := wc1
	wc2.DPCTimestamp = now
	assert.False(t, wc1.Equal(wc2))

	// RSConfigTimestamp diff
	wc2 = wc1
	wc2.RSConfigTimestamp = now
	assert.False(t, wc1.Equal(wc2))

	// Same-length Networks that differ — exercises the closure
	wc1net := WwanConfig{
		DPCKey:   "key1",
		Networks: []WwanNetworkConfig{{LogicalLabel: "wwan0"}},
	}
	wc2net := WwanConfig{
		DPCKey:   "key1",
		Networks: []WwanNetworkConfig{{LogicalLabel: "wwan1"}},
	}
	assert.False(t, wc1net.Equal(wc2net))
}

// WwanStatus.Equal — timestamp and networks branches

func TestWwanStatusEqualTimestampNetworks(t *testing.T) {
	now := time.Now()
	ws1 := WwanStatus{DPCKey: "key1"}

	// DPCTimestamp diff
	ws2 := ws1
	ws2.DPCTimestamp = now
	assert.False(t, ws1.Equal(ws2))

	// RSConfigTimestamp diff
	ws2 = ws1
	ws2.RSConfigTimestamp = now
	assert.False(t, ws1.Equal(ws2))

	// Same-length Networks that differ — exercises the closure
	ws1net := WwanStatus{
		DPCKey:   "key1",
		Networks: []WwanNetworkStatus{{LogicalLabel: "wwan0"}},
	}
	ws2net := WwanStatus{
		DPCKey:   "key1",
		Networks: []WwanNetworkStatus{{LogicalLabel: "wwan1"}},
	}
	assert.False(t, ws1net.Equal(ws2net))
}
