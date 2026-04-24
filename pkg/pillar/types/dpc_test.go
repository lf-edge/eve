// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
	"testing"
	"time"

	"github.com/lf-edge/eve-api/go/evecommon"
	uuid "github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DPCState.Describe

func TestDPCStateDescribe(t *testing.T) {
	cases := []struct {
		state DPCState
		want  string
	}{
		{DPCStateNone, "undefined state"},
		{DPCStateFail, "DPC verification failed"},
		{DPCStateFailWithIPAndDNS, "DPC verification failed, but interface has IP and DNS"},
		{DPCStateSuccess, "DPC verification succeeded"},
		{DPCStateIPDNSWait, "waiting for interface IP address(es) and/or DNS server(s)"},
		{DPCStatePCIWait, "waiting for interface from pciback"},
		{DPCStateIntfWait, "waiting for interface to appear in network stack"},
		{DPCStateRemoteWait, "controller encountered an internal error or is using an outdated certificate"},
		{DPCStateAsyncWait, "waiting for asynchronous config operations to complete"},
		{DPCStateWwanWait, "waiting for wwan microservice to apply cellular configuration"},
		{DPCState(200), "unknown state 200"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.state.Describe())
	}
}

// DPCState.InProgress

func TestDPCStateInProgress(t *testing.T) {
	inProgress := []DPCState{
		DPCStateIPDNSWait,
		DPCStatePCIWait,
		DPCStateIntfWait,
		DPCStateAsyncWait,
		DPCStateWwanWait,
	}
	notInProgress := []DPCState{
		DPCStateNone,
		DPCStateFail,
		DPCStateFailWithIPAndDNS,
		DPCStateSuccess,
		DPCStateRemoteWait,
		DPCState(200),
	}
	for _, s := range inProgress {
		assert.True(t, s.InProgress(), "expected InProgress for %v", s)
	}
	for _, s := range notInProgress {
		assert.False(t, s.InProgress(), "expected !InProgress for %v", s)
	}
}

// DevicePortConfig lookup methods

func makeTestDPC() DevicePortConfig {
	return DevicePortConfig{
		Key: "testkey",
		Ports: []NetworkPortConfig{
			{
				IfName:       "eth0",
				Logicallabel: "eth0label",
				SharedLabels: []string{"uplink", "mgmt"},
			},
			{
				IfName:       "eth1",
				Logicallabel: "eth1label",
				SharedLabels: []string{"uplink"},
				L2LinkConfig: L2LinkConfig{
					L2Type: L2LinkTypeVLAN,
					VLAN: VLANConfig{
						ParentPort: "eth0label",
						ID:         100,
					},
				},
			},
			{
				IfName:       "bond0",
				Logicallabel: "bond0label",
				L2LinkConfig: L2LinkConfig{
					L2Type: L2LinkTypeBond,
					Bond: BondConfig{
						AggregatedPorts: []string{"eth0label", "eth1label"},
					},
				},
			},
		},
	}
}

func TestDevicePortConfigLookupPortByLogicallabel(t *testing.T) {
	dpc := makeTestDPC()

	port := dpc.LookupPortByLogicallabel("eth0label")
	assert.NotNil(t, port)
	assert.Equal(t, "eth0", port.IfName)

	missing := dpc.LookupPortByLogicallabel("nonexistent")
	assert.Nil(t, missing)
}

func TestDevicePortConfigLookupPortsByLabel(t *testing.T) {
	dpc := makeTestDPC()

	// Shared label "uplink" appears on eth0 and eth1
	ports := dpc.LookupPortsByLabel("uplink")
	assert.Len(t, ports, 2)

	// Logical label lookup
	ports = dpc.LookupPortsByLabel("bond0label")
	assert.Len(t, ports, 1)
	assert.Equal(t, "bond0", ports[0].IfName)

	// Shared label only on eth0
	ports = dpc.LookupPortsByLabel("mgmt")
	assert.Len(t, ports, 1)

	// Missing
	ports = dpc.LookupPortsByLabel("missing")
	assert.Empty(t, ports)
}

func TestDevicePortConfigRecordPortSuccess(t *testing.T) {
	dpc := makeTestDPC()
	dpc.RecordPortSuccess("eth0")

	port := dpc.LookupPortByIfName("eth0")
	assert.NotNil(t, port)
	assert.False(t, port.HasError())
	assert.False(t, port.LastSucceeded.IsZero())

	// Calling on non-existent ifname should not panic
	dpc.RecordPortSuccess("wlan99")
}

func TestDevicePortConfigRecordPortFailure(t *testing.T) {
	dpc := makeTestDPC()
	dpc.RecordPortFailure("eth0", "link down")

	port := dpc.LookupPortByIfName("eth0")
	assert.NotNil(t, port)
	assert.True(t, port.HasError())
	assert.Equal(t, "link down", port.LastError)

	// Non-existent ifname should be a no-op
	dpc.RecordPortFailure("wlan99", "no link")
}

func TestDevicePortConfigIsPortUsedAsVlanParent(t *testing.T) {
	dpc := makeTestDPC()

	assert.True(t, dpc.IsPortUsedAsVlanParent("eth0label"))
	assert.False(t, dpc.IsPortUsedAsVlanParent("eth1label"))
	assert.False(t, dpc.IsPortUsedAsVlanParent("bond0label"))
}

func TestDevicePortConfigIsPortAggregatedByBond(t *testing.T) {
	dpc := makeTestDPC()

	assert.True(t, dpc.IsPortAggregatedByBond("eth0label"))
	assert.True(t, dpc.IsPortAggregatedByBond("eth1label"))
	assert.False(t, dpc.IsPortAggregatedByBond("bond0label"))
}

func TestDevicePortConfigLastTestTime(t *testing.T) {
	var dpc DevicePortConfig

	// Both zero: returns zero
	assert.True(t, dpc.LastTestTime().IsZero())

	now := time.Now()
	dpc.LastSucceeded = now
	assert.Equal(t, now, dpc.LastTestTime())

	later := now.Add(time.Second)
	dpc.LastFailed = later
	assert.Equal(t, later, dpc.LastTestTime())
}

// DevicePortConfigList.MostlyEqual

func TestDevicePortConfigListMostlyEqual(t *testing.T) {
	list1 := DevicePortConfigList{
		CurrentIndex: 0,
		PortConfigList: []DevicePortConfig{
			{Key: "k1", State: DPCStateSuccess},
		},
	}
	list2 := DevicePortConfigList{
		CurrentIndex: 0,
		PortConfigList: []DevicePortConfig{
			{Key: "k1", State: DPCStateSuccess},
		},
	}
	assert.True(t, list1.MostlyEqual(list2))

	// Different CurrentIndex
	list2.CurrentIndex = 1
	assert.False(t, list1.MostlyEqual(list2))
	list2.CurrentIndex = 0

	// Different length
	list2.PortConfigList = append(list2.PortConfigList, DevicePortConfig{Key: "k2"})
	assert.False(t, list1.MostlyEqual(list2))
	list2.PortConfigList = list2.PortConfigList[:1]

	// Different State
	list2.PortConfigList[0].State = DPCStateFail
	assert.False(t, list1.MostlyEqual(list2))
}

func TestDevicePortConfigListPubKey(t *testing.T) {
	var list DevicePortConfigList
	assert.Equal(t, "global", list.PubKey())
}

// L2LinkConfig.Equal

func TestL2LinkConfigEqual(t *testing.T) {
	l1 := L2LinkConfig{L2Type: L2LinkTypeNone}
	l2 := L2LinkConfig{L2Type: L2LinkTypeNone}
	assert.True(t, l1.Equal(l2))

	// Different type
	l2.L2Type = L2LinkTypeVLAN
	assert.False(t, l1.Equal(l2))

	// VLAN equality
	v1 := L2LinkConfig{
		L2Type: L2LinkTypeVLAN,
		VLAN:   VLANConfig{ParentPort: "eth0", ID: 10},
	}
	v2 := L2LinkConfig{
		L2Type: L2LinkTypeVLAN,
		VLAN:   VLANConfig{ParentPort: "eth0", ID: 10},
	}
	assert.True(t, v1.Equal(v2))
	v2.VLAN.ID = 20
	assert.False(t, v1.Equal(v2))

	// Bond equality
	b1 := L2LinkConfig{
		L2Type: L2LinkTypeBond,
		Bond:   BondConfig{AggregatedPorts: []string{"eth0", "eth1"}},
	}
	b2 := L2LinkConfig{
		L2Type: L2LinkTypeBond,
		Bond:   BondConfig{AggregatedPorts: []string{"eth0", "eth1"}},
	}
	assert.True(t, b1.Equal(b2))
	b2.Bond.AggregatedPorts = []string{"eth0"}
	assert.False(t, b1.Equal(b2))
}

// CellularAccessPoint.Equal

func TestCellularAccessPointEqual(t *testing.T) {
	ap1 := CellularAccessPoint{
		SIMSlot:       1,
		Activated:     true,
		APN:           "internet",
		ForbidRoaming: false,
	}
	ap2 := ap1
	assert.True(t, ap1.Equal(ap2))

	ap2.APN = "lte"
	assert.False(t, ap1.Equal(ap2))

	ap2 = ap1
	ap2.ForbidRoaming = true
	assert.False(t, ap1.Equal(ap2))

	// AttachAPN diff → covers the third return false block
	ap2 = ap1
	ap2.AttachAPN = "attach.example.com"
	assert.False(t, ap1.Equal(ap2))
}

// IPRange.Contains and IPRange.Size

func TestIPRangeContains(t *testing.T) {
	r := IPRange{
		Start: net.ParseIP("192.168.1.10"),
		End:   net.ParseIP("192.168.1.20"),
	}

	assert.True(t, r.Contains(net.ParseIP("192.168.1.10")))
	assert.True(t, r.Contains(net.ParseIP("192.168.1.15")))
	assert.True(t, r.Contains(net.ParseIP("192.168.1.20")))
	assert.False(t, r.Contains(net.ParseIP("192.168.1.9")))
	assert.False(t, r.Contains(net.ParseIP("192.168.1.21")))
}

func TestIPRangeSize(t *testing.T) {
	r := IPRange{
		Start: net.ParseIP("10.0.0.1"),
		End:   net.ParseIP("10.0.0.10"),
	}
	assert.Equal(t, uint32(9), r.Size())

	// Start > End (reversed) → ip1Int > ip2Int path
	r_rev := IPRange{
		Start: net.ParseIP("10.0.0.10"),
		End:   net.ParseIP("10.0.0.1"),
	}
	assert.Equal(t, uint32(9), r_rev.Size())

	// Single address range
	r2 := IPRange{
		Start: net.ParseIP("10.0.0.5"),
		End:   net.ParseIP("10.0.0.5"),
	}
	assert.Equal(t, uint32(0), r2.Size())

	// IPv6 returns 0 (not supported)
	r3 := IPRange{
		Start: net.ParseIP("::1"),
		End:   net.ParseIP("::2"),
	}
	assert.Equal(t, uint32(0), r3.Size())
}

// NetworkXObjectConfig.Key

func TestNetworkXObjectConfigKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	config := NetworkXObjectConfig{UUID: id}
	assert.Equal(t, id.String(), config.Key())
}

// DPCState.String

func TestDPCStateString(t *testing.T) {
	cases := []struct {
		state DPCState
		want  string
	}{
		{DPCStateNone, ""},
		{DPCStateFail, "DPC_FAIL"},
		{DPCStateFailWithIPAndDNS, "DPC_FAIL_WITH_IPANDDNS"},
		{DPCStateSuccess, "DPC_SUCCESS"},
		{DPCStateIPDNSWait, "DPC_IPDNS_WAIT"},
		{DPCStatePCIWait, "DPC_PCI_WAIT"},
		{DPCStateIntfWait, "DPC_INTF_WAIT"},
		{DPCStateRemoteWait, "DPC_REMOTE_WAIT"},
		{DPCStateAsyncWait, "DPC_ASYNC_WAIT"},
		{DPCStateWwanWait, "DPC_WWAN_WAIT"},
		{DPCState(200), "Unknown status 200"}, // default case
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.state.String())
	}
}

// WirelessType.String and WirelessConfig.IsEmpty

func TestWirelessTypeString(t *testing.T) {
	assert.Equal(t, "none", WirelessTypeNone.String())
	assert.Equal(t, "cellular", WirelessTypeCellular.String())
	assert.Equal(t, "wifi", WirelessTypeWifi.String())
}

func TestWirelessConfigIsEmpty(t *testing.T) {
	// None type → always empty
	wc := WirelessConfig{WType: WirelessTypeNone}
	assert.True(t, wc.IsEmpty())

	// Wifi with no entries → empty
	wc = WirelessConfig{WType: WirelessTypeWifi, Wifi: nil}
	assert.True(t, wc.IsEmpty())

	// Wifi with entries → not empty
	wc.Wifi = []WifiConfig{{SSID: "mynet"}}
	assert.False(t, wc.IsEmpty())

	// Cellular with no access points → empty
	wc = WirelessConfig{WType: WirelessTypeCellular}
	assert.True(t, wc.IsEmpty())

	// Cellular with deprecated config → not empty
	wc.Cellular = []DeprecatedCellConfig{{APN: "internet"}}
	assert.False(t, wc.IsEmpty())
}

// IsEveDefinedPortLabel

func TestIsEveDefinedPortLabel(t *testing.T) {
	assert.True(t, IsEveDefinedPortLabel(AllPortsLabel))
	assert.True(t, IsEveDefinedPortLabel(UplinkLabel))
	assert.True(t, IsEveDefinedPortLabel(FreeUplinkLabel))
	assert.False(t, IsEveDefinedPortLabel("custom-label"))
	assert.False(t, IsEveDefinedPortLabel(""))
}

// NetworkPortConfig.UpdateEveDefinedSharedLabels

func TestNetworkPortConfigUpdateEveDefinedSharedLabels(t *testing.T) {
	// Mgmt port with cost 0 → AllPortsLabel, UplinkLabel, FreeUplinkLabel
	port := NetworkPortConfig{IsMgmt: true, Cost: 0}
	port.UpdateEveDefinedSharedLabels()
	assert.Contains(t, port.SharedLabels, AllPortsLabel)
	assert.Contains(t, port.SharedLabels, UplinkLabel)
	assert.Contains(t, port.SharedLabels, FreeUplinkLabel)

	// Mgmt port with cost > 0 → AllPortsLabel, UplinkLabel (no FreeUplinkLabel)
	port = NetworkPortConfig{IsMgmt: true, Cost: 10}
	port.UpdateEveDefinedSharedLabels()
	assert.Contains(t, port.SharedLabels, AllPortsLabel)
	assert.Contains(t, port.SharedLabels, UplinkLabel)
	assert.NotContains(t, port.SharedLabels, FreeUplinkLabel)

	// Non-mgmt port → only AllPortsLabel
	port = NetworkPortConfig{IsMgmt: false, Cost: 0}
	port.UpdateEveDefinedSharedLabels()
	assert.Contains(t, port.SharedLabels, AllPortsLabel)
	assert.NotContains(t, port.SharedLabels, UplinkLabel)
	assert.NotContains(t, port.SharedLabels, FreeUplinkLabel)

	// User labels are preserved, EVE labels are replaced
	port = NetworkPortConfig{IsMgmt: true, Cost: 0, SharedLabels: []string{"my-custom-label", UplinkLabel}}
	port.UpdateEveDefinedSharedLabels()
	assert.Contains(t, port.SharedLabels, "my-custom-label")
	assert.Contains(t, port.SharedLabels, AllPortsLabel)
}

// PortConfigSource.Equal

func TestPortConfigSourceEqual(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s1 := PortConfigSource{SubmittedAt: now}
	s2 := s1
	assert.True(t, s1.Equal(s2))

	s2.SubmittedAt = now.Add(time.Second)
	assert.False(t, s1.Equal(s2))
}

// PortConfigSource.ToProto

func TestPortConfigSourceToProto(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	src := PortConfigSource{
		Origin:      NetworkConfigOriginController,
		SubmittedAt: now,
	}
	got := src.ToProto()
	require.NotNil(t, got)
	assert.Equal(t, evecommon.NetworkConfigOrigin(NetworkConfigOriginController), got.Origin)
	assert.Equal(t, now.Unix(), got.SubmittedAt.GetSeconds())
}

// ProxyEntry.FromProto and ToProto

func TestProxyEntryFromProtoToProto(t *testing.T) {
	cases := []struct {
		proto evecommon.ProxyProto
		want  NetworkProxyType
	}{
		{evecommon.ProxyProto_PROXY_HTTP, NetworkProxyTypeHTTP},
		{evecommon.ProxyProto_PROXY_HTTPS, NetworkProxyTypeHTTPS},
		{evecommon.ProxyProto_PROXY_SOCKS, NetworkProxyTypeSOCKS},
		{evecommon.ProxyProto_PROXY_FTP, NetworkProxyTypeFTP},
	}
	for _, tc := range cases {
		protoServer := &evecommon.ProxyServer{
			Proto:  tc.proto,
			Server: "proxy.example.com",
			Port:   8080,
		}
		var pe ProxyEntry
		pe.FromProto(protoServer)
		assert.Equal(t, tc.want, pe.Type)
		assert.Equal(t, "proxy.example.com", pe.Server)
		assert.Equal(t, uint32(8080), pe.Port)

		// Round-trip: ToProto → back
		got := pe.ToProto()
		require.NotNil(t, got)
		assert.Equal(t, tc.proto, got.Proto)
		assert.Equal(t, "proxy.example.com", got.Server)
	}

	// FromProto with nil is a no-op
	var pe2 ProxyEntry
	pe2.FromProto(nil)
	assert.Equal(t, "", pe2.Server)

	// Unknown type → PROXY_OTHER (default case in ToProto)
	pe3 := ProxyEntry{Type: NetworkProxyType(99), Server: "proxy.example.com", Port: 9090}
	got3 := pe3.ToProto()
	require.NotNil(t, got3)
	assert.Equal(t, evecommon.ProxyProto_PROXY_OTHER, got3.Proto)
}

// WifiKeySchemeType.FromProto and ToProto

func TestWifiKeySchemeTypeFromProtoToProto(t *testing.T) {
	cases := []struct {
		proto evecommon.WiFiKeyScheme
		want  WifiKeySchemeType
	}{
		{evecommon.WiFiKeyScheme_SchemeNOOP, KeySchemeNone},
		{evecommon.WiFiKeyScheme_WPAPSK, KeySchemeWpaPsk},
		{evecommon.WiFiKeyScheme_WPAEAP, KeySchemeWpaEap},
	}
	for _, tc := range cases {
		var kt WifiKeySchemeType
		err := kt.FromProto(tc.proto)
		assert.NoError(t, err)
		assert.Equal(t, tc.want, kt)

		got := kt.ToProto()
		assert.Equal(t, tc.proto, got)
	}

	// Unknown value → KeySchemeOther and error
	var kt WifiKeySchemeType
	err := kt.FromProto(evecommon.WiFiKeyScheme(99))
	assert.Error(t, err)
	assert.Equal(t, KeySchemeOther, kt)

	// KeySchemeOther.ToProto → NOOP fallback
	assert.Equal(t, evecommon.WiFiKeyScheme_SchemeNOOP, KeySchemeOther.ToProto())
}

// DevicePortConfig.UpdatePortStatusFromIntfStatusMap

func TestDevicePortConfigUpdatePortStatusFromIntfStatusMap(t *testing.T) {
	now := time.Now()
	dpc := DevicePortConfig{
		Ports: []NetworkPortConfig{
			{IfName: "eth0"},
			{IfName: "eth1"},
		},
	}
	statusMap := IntfStatusMap{
		StatusMap: map[string]TestResults{
			"eth0": {LastSucceeded: now},
		},
	}
	dpc.UpdatePortStatusFromIntfStatusMap(statusMap)

	port := dpc.LookupPortByIfName("eth0")
	require.NotNil(t, port)
	assert.Equal(t, now, port.LastSucceeded)

	port1 := dpc.LookupPortByIfName("eth1")
	require.NotNil(t, port1)
	assert.True(t, port1.LastSucceeded.IsZero())
}

// DevicePortConfig.IsDPCTestable — not-usable and future-LastFailed branches

func TestIsDPCTestableExtraBranches(t *testing.T) {
	// Not usable (no mgmt ports) → false
	dpc := DevicePortConfig{
		Ports: []NetworkPortConfig{{IfName: "eth0", IsMgmt: false}},
	}
	assert.False(t, dpc.IsDPCTestable(5*time.Minute))

	// Usable, LastFailed in the future (clock not synced) → true
	dpc = DevicePortConfig{
		Ports: []NetworkPortConfig{{IfName: "eth0", IsMgmt: true}},
		TestResults: TestResults{
			LastFailed: time.Now().Add(time.Hour),
		},
	}
	assert.True(t, dpc.IsDPCTestable(5*time.Minute))
}
