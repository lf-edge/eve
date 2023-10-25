// Copyright (c) 2019-2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"

	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

var appNetAdapterUUID = uuid.UUID{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
var appNetworkConfig = AppNetworkConfig{
	AppNetAdapterList: []AppNetAdapterConfig{
		{Network: appNetAdapterUUID},
	},
}

func TestIsIPv6(t *testing.T) {
	testMatrix := map[string]struct {
		config        NetworkInstanceConfig
		expectedValue bool
	}{
		"AddressTypeIPV6": {
			config:        NetworkInstanceConfig{IpType: AddressTypeIPV6},
			expectedValue: true,
		},
		"AddressTypeCryptoIPV6": {
			config:        NetworkInstanceConfig{IpType: AddressTypeCryptoIPV6},
			expectedValue: true,
		},
		"AddressTypeIPV4": {
			config:        NetworkInstanceConfig{IpType: AddressTypeIPV4},
			expectedValue: false,
		},
		"AddressTypeCryptoIPV4": {
			config:        NetworkInstanceConfig{IpType: AddressTypeCryptoIPV4},
			expectedValue: false,
		},
		"AddressTypeNone": {
			config:        NetworkInstanceConfig{IpType: AddressTypeNone},
			expectedValue: false,
		},
		"AddressTypeLast": {
			config:        NetworkInstanceConfig{IpType: AddressTypeLast},
			expectedValue: false,
		},
	}

	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		isIPv6 := test.config.IsIPv6()
		assert.IsType(t, test.expectedValue, isIPv6)
	}
}
func TestGetAppNetAdapterConfig(t *testing.T) {
	t.Parallel()
	testMatrix := map[string]struct {
		network uuid.UUID
		config  AppNetworkConfig
	}{
		"AppNetAdapter UUID": {
			network: appNetAdapterUUID,
			config:  appNetworkConfig,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		config := test.config.getAppNetAdapterConfig(test.network)
		assert.IsType(t, test.config.AppNetAdapterList[0], *config)
	}
}
func TestIsNetworkUsed(t *testing.T) {
	var otherUUID = uuid.UUID{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
		0x80, 0xb4, 0x00, 0xc0, 0xb8, 0xd4, 0x30, 0xc8}
	testMatrix := map[string]struct {
		network       uuid.UUID
		expectedValue bool
		config        AppNetworkConfig
	}{
		"AppNetAdapter UUID": {
			network:       appNetAdapterUUID,
			expectedValue: true,
			config:        appNetworkConfig,
		},
		"Other UUID": {
			network:       otherUUID,
			expectedValue: false,
			config:        appNetworkConfig,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		networkUsed := test.config.IsNetworkUsed(test.network)
		assert.Equal(t, test.expectedValue, networkUsed)
	}
}

// Make sure IsDPCUsable passes
var usablePort = NetworkPortConfig{
	IfName:       "eth0",
	Phylabel:     "eth0",
	Logicallabel: "eth0",
	IsMgmt:       true,
	DhcpConfig:   DhcpConfig{Dhcp: DhcpTypeClient},
}
var usablePorts = []NetworkPortConfig{usablePort}

var unusablePort1 = NetworkPortConfig{
	IfName:       "eth0",
	Phylabel:     "eth0",
	Logicallabel: "eth0",
	IsMgmt:       false,
	DhcpConfig:   DhcpConfig{Dhcp: DhcpTypeClient},
}
var unusablePorts1 = []NetworkPortConfig{unusablePort1}

var unusablePort2 = NetworkPortConfig{
	IfName:       "eth0",
	Phylabel:     "eth0",
	Logicallabel: "eth0",
	IsMgmt:       true,
	DhcpConfig:   DhcpConfig{Dhcp: DhcpTypeNone},
}
var unusablePorts2 = []NetworkPortConfig{unusablePort2}
var mixedPorts = []NetworkPortConfig{usablePort, unusablePort1, unusablePort2}

func TestIsDPCUsable(t *testing.T) {
	n := time.Now()
	testMatrix := map[string]struct {
		devicePortConfig DevicePortConfig
		expectedValue    bool
	}{
		"Management and DhcpTypeClient": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Time{},
					LastSucceeded: n,
				},
				Ports: usablePorts,
			},
			expectedValue: true,
		},
		"Mixture of usable and unusable ports": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Time{},
					LastSucceeded: n,
				},
				Ports: mixedPorts,
			},
			expectedValue: true,
		},
		"Not management and DhcpTypeClient": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Time{},
					LastSucceeded: n,
				},
				Ports: unusablePorts1,
			},
			expectedValue: false,
		},
		"Management and DhcpTypeNone": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Time{},
					LastSucceeded: n,
				},
				Ports: unusablePorts2,
			},
			expectedValue: false,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := test.devicePortConfig.IsDPCUsable()
		assert.Equal(t, test.expectedValue, value)
	}
}

func TestIsDPCTestable(t *testing.T) {
	testMatrix := map[string]struct {
		devicePortConfig DevicePortConfig
		expectedValue    bool
	}{
		"DPC always failed test and not enough time passed since the last test": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Now().Add(-2 * time.Minute),
					LastSucceeded: time.Time{},
				},
				Ports: usablePorts,
			},
			expectedValue: false,
		},
		"DPC succeeded, then failed and not enough time passed since then": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Now().Add(-2 * time.Minute),
					LastSucceeded: time.Now().Add(-4 * time.Minute),
				},
				Ports: usablePorts,
			},
			expectedValue: false,
		},
		"DPC always failed test but enough time passed since the last test": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Now().Add(-6 * time.Minute),
					LastSucceeded: time.Time{},
				},
				Ports: usablePorts,
			},
			expectedValue: true,
		},
		"DPC succeeded, then failed but enough time passed since then": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Now().Add(-6 * time.Minute),
					LastSucceeded: time.Now().Add(-8 * time.Minute),
				},
				Ports: usablePorts,
			},
			expectedValue: true,
		},
		"DPC always succeeded test": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Time{},
					LastSucceeded: time.Now().Add(-2 * time.Minute),
				},
				Ports: usablePorts,
			},
			expectedValue: true,
		},
		"DPC failed but later succeeded test": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Now().Add(-4 * time.Minute),
					LastSucceeded: time.Now().Add(-2 * time.Minute),
				},
				Ports: usablePorts,
			},
			expectedValue: true,
		},
		"Clocks are not synchronized": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Now().Add(time.Hour),
					LastSucceeded: time.Time{},
				},
				Ports: usablePorts,
			},
			expectedValue: true,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := test.devicePortConfig.IsDPCTestable(5 * time.Minute)
		assert.Equal(t, test.expectedValue, value)
	}
}

func TestIsDPCUntested(t *testing.T) {
	n := time.Now()
	testMatrix := map[string]struct {
		devicePortConfig DevicePortConfig
		expectedValue    bool
	}{
		"Last failed and Last Succeeded are 0": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Time{},
					LastSucceeded: time.Time{},
				},
				Ports: usablePorts,
			},
			expectedValue: true,
		},
		"Last Succeeded is not 0": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Time{},
					LastSucceeded: n,
				},
				Ports: usablePorts,
			},
			expectedValue: false,
		},
		"Last failed is not 0": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    time.Time{},
					LastSucceeded: n,
				},
				Ports: usablePorts,
			},
			expectedValue: false,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := test.devicePortConfig.IsDPCUntested()
		assert.Equal(t, test.expectedValue, value)
	}
}

func TestWasDPCWorking(t *testing.T) {
	n := time.Now()
	testMatrix := map[string]struct {
		devicePortConfig DevicePortConfig
		expectedValue    bool
	}{
		"Last Succeeded is 0": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    n,
					LastSucceeded: time.Time{},
				},
				Ports: usablePorts,
			},
			expectedValue: false,
		},
		"Last Succeeded is after Last Failed": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    n,
					LastSucceeded: n.Add(time.Second * 60),
				},
				Ports: usablePorts,
			},
			expectedValue: true,
		},
		"Last Failed is after Last Succeeded": {
			devicePortConfig: DevicePortConfig{
				TestResults: TestResults{
					LastFailed:    n.Add(time.Second * 60),
					LastSucceeded: n,
				},
				Ports: usablePorts,
			},
			expectedValue: false,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := test.devicePortConfig.WasDPCWorking()
		assert.Equal(t, test.expectedValue, value)
	}
}

func TestGetPortByIfName(t *testing.T) {
	testMatrix := map[string]struct {
		deviceNetworkStatus DeviceNetworkStatus
		port                string
		expectedValue       NetworkPortStatus
	}{
		"Test IfnName is port one": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port one"},
				},
			},
			port: "port one",
			expectedValue: NetworkPortStatus{
				IfName: "port one",
			},
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := test.deviceNetworkStatus.GetPortByIfName(test.port)
		assert.Equal(t, test.expectedValue, *value)
	}
}

func TestGetPortCostList(t *testing.T) {
	testMatrix := map[string]struct {
		deviceNetworkStatus DeviceNetworkStatus
		expectedValue       []uint8
	}{
		"Test single": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port one",
						IsMgmt: true,
						Cost:   0},
				},
			},
			expectedValue: []uint8{0},
		},
		"Test empty": {
			deviceNetworkStatus: DeviceNetworkStatus{},
			expectedValue:       []uint8{},
		},
		"Test no management": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port one",
						IsMgmt: false,
						Cost:   1},
				},
			},
			expectedValue: []uint8{1},
		},
		"Test duplicates": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port one",
						IsMgmt: true,
						Cost:   17},
					{IfName: "port two",
						IsMgmt: true,
						Cost:   1},
					{IfName: "port three",
						IsMgmt: true,
						Cost:   17},
				},
			},
			expectedValue: []uint8{1, 17},
		},
		"Test reverse": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port one",
						IsMgmt: true,
						Cost:   2},
					{IfName: "port two",
						IsMgmt: true,
						Cost:   1},
					{IfName: "port three",
						IsMgmt: true,
						Cost:   0},
				},
			},
			expectedValue: []uint8{0, 1, 2},
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := GetPortCostList(test.deviceNetworkStatus)
		assert.Equal(t, test.expectedValue, value)
	}
}

// TestGetMgmtPortsSortedCost covers both GetMgmtPortsSortedCost and GetAllPortsSortedCost.
func TestGetMgmtPortsSortedCost(t *testing.T) {
	testMatrix := map[string]struct {
		deviceNetworkStatus DeviceNetworkStatus
		rotate              int
		expectedMgmtValue   []string
		expectedAllValue    []string
	}{
		"Test single": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: true,
						Cost:   0},
				},
			},
			expectedMgmtValue: []string{"port1"},
			expectedAllValue:  []string{"port1"},
		},
		"Test single rotate": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: true,
						Cost:   0},
				},
			},
			rotate:            14,
			expectedMgmtValue: []string{"port1"},
			expectedAllValue:  []string{"port1"},
		},
		"Test empty": {
			deviceNetworkStatus: DeviceNetworkStatus{},
			expectedMgmtValue:   []string{},
			expectedAllValue:    []string{},
		},
		"Test no management": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: false,
						Cost:   0},
				},
			},
			rotate:            14,
			expectedMgmtValue: []string{},
			expectedAllValue:  []string{"port1"},
		},
		"Test duplicates": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: true,
						Cost:   17},
					{IfName: "port2",
						IsMgmt: true,
						Cost:   1},
					{IfName: "port3",
						IsMgmt: true,
						Cost:   17},
					{IfName: "port4",
						IsMgmt: true,
						Cost:   1},
				},
			},
			expectedMgmtValue: []string{"port2", "port4", "port1", "port3"},
			expectedAllValue:  []string{"port2", "port4", "port1", "port3"},
		},
		"Test duplicates rotate": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: true,
						Cost:   17},
					{IfName: "port2",
						IsMgmt: true,
						Cost:   1},
					{IfName: "port3",
						IsMgmt: true,
						Cost:   17},
					{IfName: "port4",
						IsMgmt: true,
						Cost:   1},
				},
			},
			rotate:            1,
			expectedMgmtValue: []string{"port4", "port2", "port3", "port1"},
			expectedAllValue:  []string{"port4", "port2", "port3", "port1"},
		},
		"Test duplicates some management": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: false,
						Cost:   17},
					{IfName: "port2",
						IsMgmt: false,
						Cost:   1},
					{IfName: "port3",
						IsMgmt: true,
						Cost:   17},
					{IfName: "port4",
						IsMgmt: true,
						Cost:   1},
				},
			},
			expectedMgmtValue: []string{"port4", "port3"},
			expectedAllValue:  []string{"port2", "port4", "port1", "port3"},
		},
		"Test reverse": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: true,
						Cost:   2},
					{IfName: "port2",
						IsMgmt: true,
						Cost:   1},
					{IfName: "port3",
						IsMgmt: true,
						Cost:   0},
				},
			},
			expectedMgmtValue: []string{"port3", "port2", "port1"},
			expectedAllValue:  []string{"port3", "port2", "port1"},
		},
		"Test reverse some management": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: true,
						Cost:   2},
					{IfName: "port2",
						IsMgmt: false,
						Cost:   1},
					{IfName: "port3",
						IsMgmt: true,
						Cost:   0},
				},
			},
			expectedMgmtValue: []string{"port3", "port1"},
			expectedAllValue:  []string{"port3", "port2", "port1"},
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := GetMgmtPortsSortedCost(test.deviceNetworkStatus, test.rotate)
		assert.Equal(t, test.expectedMgmtValue, value)
		value = GetAllPortsSortedCost(test.deviceNetworkStatus, test.rotate)
		assert.Equal(t, test.expectedAllValue, value)
	}
}

func TestGetMgmtPortsByCost(t *testing.T) {
	testMatrix := map[string]struct {
		deviceNetworkStatus DeviceNetworkStatus
		cost                uint8
		expectedValue       []string
	}{
		"Test single": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: true,
						Cost:   0},
				},
			},
			cost:          0,
			expectedValue: []string{"port1"},
		},
		"Test single wrong cost": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: true,
						Cost:   0},
				},
			},
			cost:          14,
			expectedValue: []string{},
		},
		"Test empty": {
			deviceNetworkStatus: DeviceNetworkStatus{},
			cost:                0,
			expectedValue:       []string{},
		},
		"Test no management": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: false,
						Cost:   0},
				},
			},
			cost:          0,
			expectedValue: []string{},
		},
		"Test duplicates cost 1": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: true,
						Cost:   17},
					{IfName: "port2",
						IsMgmt: true,
						Cost:   1},
					{IfName: "port3",
						IsMgmt: true,
						Cost:   17},
					{IfName: "port4",
						IsMgmt: true,
						Cost:   1},
				},
			},
			cost:          1,
			expectedValue: []string{"port2", "port4"},
		},
		"Test duplicates cost 17": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: true,
						Cost:   17},
					{IfName: "port2",
						IsMgmt: true,
						Cost:   1},
					{IfName: "port3",
						IsMgmt: true,
						Cost:   17},
					{IfName: "port4",
						IsMgmt: true,
						Cost:   1},
				},
			},
			cost:          17,
			expectedValue: []string{"port1", "port3"},
		},
		"Test duplicates bad cost": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: true,
						Cost:   17},
					{IfName: "port2",
						IsMgmt: true,
						Cost:   1},
					{IfName: "port3",
						IsMgmt: true,
						Cost:   17},
					{IfName: "port4",
						IsMgmt: true,
						Cost:   1},
				},
			},
			cost:          18,
			expectedValue: []string{},
		},
		"Test duplicates some management": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt: false,
						Cost:   17},
					{IfName: "port2",
						IsMgmt: false,
						Cost:   1},
					{IfName: "port3",
						IsMgmt: true,
						Cost:   17},
					{IfName: "port4",
						IsMgmt: true,
						Cost:   1},
				},
			},
			cost:          17,
			expectedValue: []string{"port3"},
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := GetMgmtPortsByCost(test.deviceNetworkStatus, test.cost)
		assert.Equal(t, test.expectedValue, value)
	}
}

// Common DeviceNetworkStatus with addresses and costs; link-local etc
// for the Count and Get functions
// Note that
var (
	commonDeviceNetworkStatus = DeviceNetworkStatus{
		Version: DPCIsMgmt,
		Ports: []NetworkPortStatus{
			{
				// Global and link local
				IfName: "port1",
				IsMgmt: true,
				Cost:   17,
				AddrInfoList: []AddrInfo{
					{Addr: addrIPv4Global1},
					{Addr: addrIPv4Local1},
					{Addr: addrIPv6Global1},
					{Addr: addrIPv6Local1},
					{Addr: addrIPv4Global5},
				},
			},
			{
				// Only link local
				IfName: "port2",
				IsMgmt: true,
				Cost:   1,
				AddrInfoList: []AddrInfo{
					{Addr: addrIPv4Local2},
					{Addr: addrIPv6Local2},
				},
			},
			{
				// Has no AddrInfo
				IfName: "port3",
				IsMgmt: true,
				Cost:   17,
			},
			{
				// Global and link local; more globals per if
				IfName: "port4",
				IsMgmt: true,
				Cost:   1,
				AddrInfoList: []AddrInfo{
					{Addr: addrIPv4Global4},
					{Addr: addrIPv4Local4},
					{Addr: addrIPv6Global4},
					{Addr: addrIPv6Local4},
					{Addr: addrIPv4Global3},
					{Addr: addrIPv6Global3},
					{Addr: addrIPv4Global6},
				},
			},
			{
				// Has no IP addresses but has AddrInfo
				IfName: "port5",
				IsMgmt: true,
				Cost:   17,
				AddrInfoList: []AddrInfo{
					{LastGeoTimestamp: time.Now()},
					{LastGeoTimestamp: time.Now()},
				},
			},
		},
	}

	addrIPv4Global1 = net.ParseIP("192.168.1.10")
	addrIPv4Global2 = net.ParseIP("192.168.2.10")
	addrIPv4Global3 = net.ParseIP("192.168.3.10")
	addrIPv4Global4 = net.ParseIP("192.168.4.10")
	addrIPv4Global5 = net.ParseIP("192.168.5.10")
	addrIPv4Global6 = net.ParseIP("192.168.6.10")
	addrIPv4Local1  = net.ParseIP("169.254.99.1")
	addrIPv4Local2  = net.ParseIP("169.254.99.2")
	addrIPv4Local3  = net.ParseIP("169.254.99.3")
	addrIPv4Local4  = net.ParseIP("169.254.99.4")
	addrIPv6Global1 = net.ParseIP("fec0::1")
	addrIPv6Global2 = net.ParseIP("fec0::2")
	addrIPv6Global3 = net.ParseIP("fec0::3")
	addrIPv6Global4 = net.ParseIP("fec0::4")
	addrIPv6Local1  = net.ParseIP("fe80::1")
	addrIPv6Local2  = net.ParseIP("fe80::2")
	addrIPv6Local3  = net.ParseIP("fe80::3")
	addrIPv6Local4  = net.ParseIP("fe80::4")
)

func TestCountLocalAddrAnyNoLinkLocal(t *testing.T) {
	testMatrix := map[string]struct {
		expectedValue int
	}{
		"Test CountLocalAddrAnyNoLinkLocal": {
			expectedValue: 8,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := CountLocalAddrAnyNoLinkLocal(commonDeviceNetworkStatus)
		assert.Equal(t, test.expectedValue, value)
	}
}

func TestCountLocalAddrAnyNoLinkLocalIf(t *testing.T) {
	testMatrix := map[string]struct {
		ifname        string
		expectFail    bool
		expectedValue int
	}{
		"Test port1 CountLocalAddrAnyNoLinkLocalIf": {
			ifname:        "port1",
			expectedValue: 3,
		},
		"Test port2 CountLocalAddrAnyNoLinkLocalIf": {
			ifname:        "port2",
			expectedValue: 0,
			expectFail:    true,
		},
		"Test port3 CountLocalAddrAnyNoLinkLocalIf": {
			ifname:        "port3",
			expectedValue: 0,
			expectFail:    true,
		},
		"Test port4 CountLocalAddrAnyNoLinkLocalIf": {
			ifname:        "port4",
			expectedValue: 5,
		},
		"Test badport CountLocalAddrAnyNoLinkLocalIf": {
			ifname:        "badport",
			expectedValue: 0,
			expectFail:    true,
		},
		"Test noport CountLocalAddrAnyNoLinkLocalIf": {
			expectedValue: 0,
			expectFail:    true,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value, err := CountLocalAddrAnyNoLinkLocalIf(commonDeviceNetworkStatus,
			test.ifname)
		assert.Equal(t, test.expectedValue, value)
		if test.expectFail {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestCountLocalAddrNoLinkLocalWithCost(t *testing.T) {
	testMatrix := map[string]struct {
		cost          uint8
		expectedValue int
	}{
		"Test 0 CountLocalAddrNoLinkLocalWithCost": {
			cost:          0,
			expectedValue: 5,
		},
		"Test 16 CountLocalAddrNoLinkLocalWithCost": {
			cost:          16,
			expectedValue: 5,
		},
		"Test 17 CountLocalAddrNoLinkLocalWithCost": {
			cost:          17,
			expectedValue: 8,
		},
		"Test 255 CountLocalAddrNoLinkLocalWithCost": {
			cost:          255,
			expectedValue: 8,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := CountLocalAddrNoLinkLocalWithCost(commonDeviceNetworkStatus,
			test.cost)
		assert.Equal(t, test.expectedValue, value)
	}
}

func TestCountLocalIPv4AddrAnyNoLinkLocal(t *testing.T) {
	testMatrix := map[string]struct {
		expectedValue int
	}{
		"Test CountLocalIPv4AddrAnyNoLinkLocal": {
			expectedValue: 5,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := CountLocalIPv4AddrAnyNoLinkLocal(commonDeviceNetworkStatus)
		assert.Equal(t, test.expectedValue, value)
	}
}

func TestCountLocalIPv4AddrAnyNoLinkLocalIf(t *testing.T) {
	testMatrix := map[string]struct {
		ifname        string
		expectFail    bool
		expectedValue int
	}{
		"Test port1 CountLocalIPv4AddrAnyNoLinkLocalIf": {
			ifname:        "port1",
			expectedValue: 2,
		},
		"Test port2 CountLocalIPv4AddrAnyNoLinkLocalIf": {
			ifname:        "port2",
			expectedValue: 0,
			expectFail:    true,
		},
		"Test port3 CountLocalIPv4AddrAnyNoLinkLocalIf": {
			ifname:        "port3",
			expectedValue: 0,
			expectFail:    true,
		},
		"Test port4 CountLocalIPv4AddrAnyNoLinkLocalIf": {
			ifname:        "port4",
			expectedValue: 3,
		},
		"Test badport CountLocalIPv4AddrAnyNoLinkLocalIf": {
			ifname:        "badport",
			expectedValue: 0,
			expectFail:    true,
		},
		"Test noport CountLocalIPv4AddrAnyNoLinkLocalIf": {
			expectedValue: 0,
			expectFail:    true,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value, err := CountLocalIPv4AddrAnyNoLinkLocalIf(commonDeviceNetworkStatus,
			test.ifname)
		assert.Equal(t, test.expectedValue, value)
		if test.expectFail {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestGetLocalAddrAnyNoLinkLocal(t *testing.T) {
	testMatrix := map[string]struct {
		pickNum       int
		expectedValue net.IP
		expectFail    bool
	}{
		"Test 0 GetLocalAddrAnyNoLinkLocal": {
			pickNum:       0,
			expectedValue: addrIPv4Global4,
		},
		"Test 1 GetLocalAddrAnyNoLinkLocal": {
			pickNum:       1,
			expectedValue: addrIPv6Global4,
		},
		"Test 2 GetLocalAddrAnyNoLinkLocal": {
			pickNum:       2,
			expectedValue: addrIPv4Global3,
		},
		"Test 3 GetLocalAddrAnyNoLinkLocal": {
			pickNum:       3,
			expectedValue: addrIPv6Global3,
		},
		"Test 7 GetLocalAddrAnyNoLinkLocal": {
			pickNum:       7,
			expectedValue: addrIPv4Global5,
		},
		// Wrap around
		"Test 8 GetLocalAddrAnyNoLinkLocal": {
			pickNum:       8,
			expectedValue: addrIPv4Global4,
		},
		"Test 9 GetLocalAddrAnyNoLinkLocal": {
			pickNum:       9,
			expectedValue: addrIPv6Global4,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value, err := GetLocalAddrAnyNoLinkLocal(commonDeviceNetworkStatus,
			test.pickNum, "")
		assert.Equal(t, test.expectedValue, value)
		if test.expectFail {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestGetLocalAddrAnyNoLinkLocal_Interface(t *testing.T) {
	testMatrix := map[string]struct {
		ifname        string
		pickNum       int
		expectedValue net.IP
		expectFail    bool
	}{
		"Test port1 pick 0 GetLocalAddrAnyNoLinkLocal_Interface": {
			ifname:        "port1",
			pickNum:       0,
			expectedValue: addrIPv4Global1,
		},
		"Test port1 pick 1 GetLocalAddrAnyNoLinkLocal_Interface": {
			ifname:        "port1",
			pickNum:       1,
			expectedValue: addrIPv6Global1,
		},
		"Test port1 pick 2 GetLocalAddrAnyNoLinkLocal_Interface": {
			ifname:        "port1",
			pickNum:       2,
			expectedValue: addrIPv4Global5,
		},
		// Wraparound
		"Test port1 pick 3 GetLocalAddrAnyNoLinkLocal_Interface": {
			ifname:        "port1",
			pickNum:       3,
			expectedValue: addrIPv4Global1,
		},
		"Test port2 pick 0 GetLocalAddrAnyNoLinkLocal_Interface": {
			ifname: "port2",

			pickNum:       0,
			expectedValue: net.IP{},
			expectFail:    true,
		},
		"Test port3 pick 0 GetLocalAddrAnyNoLinkLocal_Interface": {
			ifname:        "port3",
			pickNum:       0,
			expectedValue: net.IP{},
			expectFail:    true,
		},
		"Test port4 pick 0 GetLocalAddrAnyNoLinkLocal_Interface": {
			ifname:        "port4",
			pickNum:       0,
			expectedValue: addrIPv4Global4,
		},
		"Test port4 pick 1 GetLocalAddrAnyNoLinkLocal_Interface": {
			ifname:        "port4",
			pickNum:       1,
			expectedValue: addrIPv6Global4,
		},
		"Test port4 pick 2 GetLocalAddrAnyNoLinkLocal_Interface": {
			ifname:        "port4",
			pickNum:       2,
			expectedValue: addrIPv4Global3,
		},
		"Test badport pick 0 GetLocalAddrAnyNoLinkLocal_Interface": {
			ifname:        "badport",
			pickNum:       0,
			expectedValue: net.IP{},
			expectFail:    true,
		},
		// This is the same as above; get across all interfaces
		"Test noport pick 0 GetLocalAddrAnyNoLinkLocal_Interface": {
			pickNum:       0,
			expectedValue: addrIPv4Global4,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value, err := GetLocalAddrAnyNoLinkLocal(commonDeviceNetworkStatus,
			test.pickNum, test.ifname)
		assert.Equal(t, test.expectedValue, value)
		if test.expectFail {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestGetLocalAddrNoLinkLocalWithCost(t *testing.T) {
	testMatrix := map[string]struct {
		pickNum       int
		cost          uint8
		expectedValue net.IP
		expectFail    bool
	}{
		"Test 0 cost 0 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       0,
			cost:          0,
			expectedValue: addrIPv4Global4,
		},
		"Test 1 cost 0 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       1,
			cost:          0,
			expectedValue: addrIPv6Global4,
		},
		"Test 2 cost 0 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       2,
			cost:          0,
			expectedValue: addrIPv4Global3,
		},
		"Test 3 cost 0 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       3,
			cost:          0,
			expectedValue: addrIPv6Global3,
		},
		// Wrap around
		"Test 7 cost 0 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       7,
			cost:          0,
			expectedValue: addrIPv4Global3,
		},
		"Test 8 cost 0 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       8,
			cost:          0,
			expectedValue: addrIPv6Global3,
		},
		"Test 9 cost 0 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       9,
			cost:          0,
			expectedValue: addrIPv4Global6,
		},
		"Test 0 cost 20 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       0,
			cost:          20,
			expectedValue: addrIPv4Global4,
		},
		"Test 1 cost 20 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       1,
			cost:          20,
			expectedValue: addrIPv6Global4,
		},
		"Test 2 cost 20 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       2,
			cost:          20,
			expectedValue: addrIPv4Global3,
		},
		"Test 3 cost 20 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       3,
			cost:          20,
			expectedValue: addrIPv6Global3,
		},
		"Test 7 cost 20 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       7,
			cost:          20,
			expectedValue: addrIPv4Global5,
		},
		// Wrap around
		"Test 8 cost 20 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       8,
			cost:          20,
			expectedValue: addrIPv4Global4,
		},
		"Test 9 cost 20 GetLocalAddrNoLinkLocalWithCost": {
			pickNum:       9,
			cost:          20,
			expectedValue: addrIPv6Global4,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value, err := GetLocalAddrNoLinkLocalWithCost(commonDeviceNetworkStatus,
			test.pickNum, "", test.cost)
		assert.Equal(t, test.expectedValue, value)
		if test.expectFail {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestGetLocalAddrNoLinkLocalWithCost_Interface(t *testing.T) {
	testMatrix := map[string]struct {
		ifname        string
		pickNum       int
		cost          uint8
		expectedValue net.IP
		expectFail    bool
	}{
		"Test port1 pick 0 cost 10 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port1",
			pickNum:       0,
			cost:          10,
			expectedValue: net.IP{},
			expectFail:    true,
		},
		"Test port1 pick 1 cost 10 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port1",
			pickNum:       1,
			cost:          10,
			expectedValue: net.IP{},
			expectFail:    true,
		},
		"Test port2 pick 0 cost 10 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname: "port2",

			pickNum:       0,
			cost:          10,
			expectedValue: net.IP{},
			expectFail:    true,
		},
		"Test port3 pick 0 cost 10 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port3",
			pickNum:       0,
			cost:          10,
			expectedValue: net.IP{},
			expectFail:    true,
		},
		"Test port4 pick 0 cost 10 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port4",
			pickNum:       0,
			cost:          10,
			expectedValue: addrIPv4Global4,
		},
		"Test port4 pick 1 cost 10 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port4",
			pickNum:       1,
			cost:          10,
			expectedValue: addrIPv6Global4,
		},
		"Test port4 pick 2 cost 10 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port4",
			pickNum:       2,
			cost:          10,
			expectedValue: addrIPv4Global3,
		},
		"Test badport pick 0 cost 10 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "badport",
			pickNum:       0,
			cost:          10,
			expectedValue: net.IP{},
			expectFail:    true,
		},
		// This is the same as above; get across all interfaces
		"Test noport pick 0 cost 10 GetLocalAddrNoLinkLocalWithCost_Interface": {
			pickNum:       0,
			cost:          10,
			expectedValue: addrIPv4Global4,
		},
		"Test port1 pick 0 cost 99 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port1",
			pickNum:       0,
			cost:          99,
			expectedValue: addrIPv4Global1,
		},
		"Test port1 pick 1 cost 99 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port1",
			pickNum:       1,
			cost:          99,
			expectedValue: addrIPv6Global1,
		},
		"Test port1 pick 2 cost 99 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port1",
			pickNum:       2,
			cost:          99,
			expectedValue: addrIPv4Global5,
		},
		// Wraparound
		"Test port1 pick 3 cost 99 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port1",
			pickNum:       3,
			cost:          99,
			expectedValue: addrIPv4Global1,
		},
		"Test port2 pick 0 cost 99 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname: "port2",

			pickNum:       0,
			cost:          99,
			expectedValue: net.IP{},
			expectFail:    true,
		},
		"Test port3 pick 0 cost 99 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port3",
			pickNum:       0,
			cost:          99,
			expectedValue: net.IP{},
			expectFail:    true,
		},
		"Test port4 pick 0 cost 99 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port4",
			pickNum:       0,
			cost:          99,
			expectedValue: addrIPv4Global4,
		},
		"Test port4 pick 1 cost 99 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port4",
			pickNum:       1,
			cost:          99,
			expectedValue: addrIPv6Global4,
		},
		"Test port4 pick 2 cost 99 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "port4",
			pickNum:       2,
			cost:          99,
			expectedValue: addrIPv4Global3,
		},
		"Test badport pick 0 cost 99 GetLocalAddrNoLinkLocalWithCost_Interface": {
			ifname:        "badport",
			pickNum:       0,
			cost:          99,
			expectedValue: net.IP{},
			expectFail:    true,
		},
		// This is the same as above; get across all interfaces
		"Test noport pick 0 cost 99 GetLocalAddrNoLinkLocalWithCost_Interface": {
			pickNum:       0,
			cost:          99,
			expectedValue: addrIPv4Global4,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value, err := GetLocalAddrNoLinkLocalWithCost(commonDeviceNetworkStatus,
			test.pickNum, test.ifname, test.cost)
		assert.Equal(t, test.expectedValue, value)
		if test.expectFail {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

func TestGetLocalAddrList(t *testing.T) {
	testMatrix := map[string]struct {
		ifname        string
		expectFail    bool
		expectedValue []net.IP
	}{
		"Test port1 GetLocalAddrList": {
			ifname:        "port1",
			expectedValue: []net.IP{addrIPv4Global1, addrIPv6Global1, addrIPv4Global5},
		},
		"Test port2 GetLocalAddrList": {
			ifname:        "port2",
			expectedValue: []net.IP{},
			expectFail:    true,
		},
		"Test port3 GetLocalAddrList": {
			ifname:        "port3",
			expectedValue: []net.IP{},
			expectFail:    true,
		},
		"Test port4 GetLocalAddrList": {
			ifname:        "port4",
			expectedValue: []net.IP{addrIPv4Global4, addrIPv6Global4, addrIPv4Global3, addrIPv6Global3, addrIPv4Global6},
		},
		"Test badport GetLocalAddrList": {
			ifname:        "badport",
			expectedValue: []net.IP{},
			expectFail:    true,
		},
		"Test noport GetLocalAddrList": {
			expectedValue: []net.IP{},
			expectFail:    true,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value, err := GetLocalAddrList(commonDeviceNetworkStatus,
			test.ifname)
		assert.Equal(t, test.expectedValue, value)
		if test.expectFail {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}
