// Copyright (c) 2019-2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"net"
	"testing"
	"time"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestLookupPortByIfName(t *testing.T) {
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
		value := test.deviceNetworkStatus.LookupPortByIfName(test.port)
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
		l3Only              bool
		rotate              int
		expectedMgmtValue   []string
		expectedAllValue    []string
	}{
		"Test single": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     0},
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
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     0},
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
						IsMgmt:   false,
						IsL3Port: true,
						Cost:     0},
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
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port2",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     1},
					{IfName: "port3",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port4",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     1},
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
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port2",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     1},
					{IfName: "port3",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port4",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     1},
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
						IsMgmt:   false,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port2",
						IsMgmt:   false,
						IsL3Port: true,
						Cost:     1},
					{IfName: "port3",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port4",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     1},
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
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     2},
					{IfName: "port2",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     1},
					{IfName: "port3",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     0},
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
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     2},
					{IfName: "port2",
						IsMgmt:   false,
						IsL3Port: true,
						Cost:     1},
					{IfName: "port3",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     0},
				},
			},
			expectedMgmtValue: []string{"port3", "port1"},
			expectedAllValue:  []string{"port3", "port2", "port1"},
		},
		"Test L3-only": {
			deviceNetworkStatus: DeviceNetworkStatus{
				Version: DPCIsMgmt,
				Ports: []NetworkPortStatus{
					{IfName: "port1",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port2",
						IsMgmt:   false,
						IsL3Port: false,
						Cost:     1},
					{IfName: "port3",
						IsMgmt:   false,
						IsL3Port: false,
						Cost:     17},
					{IfName: "port4",
						IsMgmt:   false,
						IsL3Port: true,
						Cost:     1},
				},
			},
			l3Only:            true,
			expectedMgmtValue: []string{"port1"},
			expectedAllValue:  []string{"port4", "port1"},
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := GetMgmtPortsSortedCost(test.deviceNetworkStatus, test.rotate)
		assert.Equal(t, test.expectedMgmtValue, value)
		value = GetAllPortsSortedCost(test.deviceNetworkStatus, test.l3Only, test.rotate)
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
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     0},
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
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     0},
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
						IsMgmt:   false,
						IsL3Port: true,
						Cost:     0},
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
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port2",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     1},
					{IfName: "port3",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port4",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     1},
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
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port2",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     1},
					{IfName: "port3",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port4",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     1},
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
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port2",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     1},
					{IfName: "port3",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port4",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     1},
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
						IsMgmt:   false,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port2",
						IsMgmt:   false,
						IsL3Port: true,
						Cost:     1},
					{IfName: "port3",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     17},
					{IfName: "port4",
						IsMgmt:   true,
						IsL3Port: true,
						Cost:     1},
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
				IfName:   "port1",
				IsMgmt:   true,
				IsL3Port: true,
				Cost:     17,
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
				IfName:   "port2",
				IsMgmt:   true,
				IsL3Port: true,
				Cost:     1,
				AddrInfoList: []AddrInfo{
					{Addr: addrIPv4Local2},
					{Addr: addrIPv6Local2},
				},
			},
			{
				// Has no AddrInfo
				IfName:   "port3",
				IsMgmt:   true,
				IsL3Port: true,
				Cost:     17,
			},
			{
				// Global and link local; more globals per if
				IfName:   "port4",
				IsMgmt:   true,
				IsL3Port: true,
				Cost:     1,
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
				IfName:   "port5",
				IsMgmt:   true,
				IsL3Port: true,
				Cost:     17,
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

// AppNetworkStatus.AwaitingNetwork

func TestAppNetworkStatusAwaitingNetwork(t *testing.T) {
	status := AppNetworkStatus{}
	assert.False(t, status.AwaitingNetwork())

	status.AwaitNetworkInstance = true
	assert.True(t, status.AwaitingNetwork())
}

// AppContainerMetrics.Key

func TestAppContainerMetricsKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	m := AppContainerMetrics{
		UUIDandVersion: UUIDandVersion{UUID: id},
	}
	assert.Equal(t, id.String(), m.Key())
}

// FlowScope.Key

func TestFlowScopeKey(t *testing.T) {
	appID := uuid.Must(uuid.NewV4())
	fs := FlowScope{
		AppUUID:        appID,
		NetAdapterName: "adapter0",
	}
	assert.Equal(t, appID.String()+"-adapter0", fs.Key())

	fs.Sequence = "seq1"
	assert.Equal(t, appID.String()+"-adapter0-seq1", fs.Key())
}

// IPFlow.Key

func TestIPFlowKey(t *testing.T) {
	appID := uuid.Must(uuid.NewV4())
	flow := IPFlow{
		Scope: FlowScope{
			AppUUID:        appID,
			NetAdapterName: "eth0",
		},
	}
	assert.Equal(t, appID.String()+"-eth0", flow.Key())
}

// ConnectivityProbe.FromProto and ToProto

func TestConnectivityProbeFromProtoNil(t *testing.T) {
	var cp ConnectivityProbe
	err := cp.FromProto(nil)
	assert.NoError(t, err)
	assert.Equal(t, ConnectivityProbeMethodNone, cp.Method)
}

func TestConnectivityProbeFromProtoUnspecified(t *testing.T) {
	var cp ConnectivityProbe
	proto := &evecommon.ConnectivityProbe{
		ProbeMethod: evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_UNSPECIFIED,
	}
	err := cp.FromProto(proto)
	assert.NoError(t, err)
	assert.Equal(t, ConnectivityProbeMethodNone, cp.Method)
}

func TestConnectivityProbeFromProtoICMP(t *testing.T) {
	var cp ConnectivityProbe
	proto := &evecommon.ConnectivityProbe{
		ProbeMethod: evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_ICMP,
		ProbeEndpoint: &evecommon.ProbeEndpoint{
			Host: "8.8.8.8",
		},
	}
	err := cp.FromProto(proto)
	assert.NoError(t, err)
	assert.Equal(t, ConnectivityProbeMethodICMP, cp.Method)
	assert.Equal(t, "8.8.8.8", cp.ProbeHost)
}

func TestConnectivityProbeFromProtoICMPInvalidIP(t *testing.T) {
	var cp ConnectivityProbe
	proto := &evecommon.ConnectivityProbe{
		ProbeMethod: evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_ICMP,
		ProbeEndpoint: &evecommon.ProbeEndpoint{
			Host: "not-an-ip",
		},
	}
	err := cp.FromProto(proto)
	assert.Error(t, err)
}

func TestConnectivityProbeFromProtoTCP(t *testing.T) {
	var cp ConnectivityProbe
	proto := &evecommon.ConnectivityProbe{
		ProbeMethod: evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_TCP,
		ProbeEndpoint: &evecommon.ProbeEndpoint{
			Host: "10.0.0.1",
			Port: 443,
		},
	}
	err := cp.FromProto(proto)
	assert.NoError(t, err)
	assert.Equal(t, ConnectivityProbeMethodTCP, cp.Method)
	assert.Equal(t, "10.0.0.1", cp.ProbeHost)
	assert.Equal(t, uint16(443), cp.ProbePort)
}

func TestConnectivityProbeFromProtoTCPMissingHost(t *testing.T) {
	var cp ConnectivityProbe
	proto := &evecommon.ConnectivityProbe{
		ProbeMethod: evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_TCP,
		ProbeEndpoint: &evecommon.ProbeEndpoint{
			Port: 443,
		},
	}
	err := cp.FromProto(proto)
	assert.Error(t, err)
}

func TestConnectivityProbeFromProtoTCPMissingPort(t *testing.T) {
	var cp ConnectivityProbe
	proto := &evecommon.ConnectivityProbe{
		ProbeMethod: evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_TCP,
		ProbeEndpoint: &evecommon.ProbeEndpoint{
			Host: "10.0.0.1",
		},
	}
	err := cp.FromProto(proto)
	assert.Error(t, err)
}

func TestConnectivityProbeToProtoNone(t *testing.T) {
	cp := ConnectivityProbe{Method: ConnectivityProbeMethodNone}
	proto := cp.ToProto()
	require.NotNil(t, proto)
	assert.Equal(t, evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_UNSPECIFIED,
		proto.ProbeMethod)
}

func TestConnectivityProbeToProtoICMP(t *testing.T) {
	cp := ConnectivityProbe{Method: ConnectivityProbeMethodICMP, ProbeHost: "1.2.3.4"}
	proto := cp.ToProto()
	require.NotNil(t, proto)
	assert.Equal(t, evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_ICMP,
		proto.ProbeMethod)
	assert.Equal(t, "1.2.3.4", proto.ProbeEndpoint.Host)
}

func TestConnectivityProbeToProtoTCP(t *testing.T) {
	cp := ConnectivityProbe{Method: ConnectivityProbeMethodTCP, ProbeHost: "10.0.0.1", ProbePort: 80}
	proto := cp.ToProto()
	require.NotNil(t, proto)
	assert.Equal(t, evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_TCP,
		proto.ProbeMethod)
	assert.Equal(t, "10.0.0.1", proto.ProbeEndpoint.Host)
	assert.Equal(t, uint32(80), proto.ProbeEndpoint.Port)
}

// IPRouteConfig.IsDefaultRoute

func TestIPRouteConfigIsDefaultRoute(t *testing.T) {
	// Nil network is default
	r := IPRouteConfig{}
	assert.True(t, r.IsDefaultRoute())

	// 0.0.0.0/0 is default
	_, ipNet, _ := net.ParseCIDR("0.0.0.0/0")
	r.DstNetwork = ipNet
	assert.True(t, r.IsDefaultRoute())

	// Specific subnet is not default
	_, ipNet2, _ := net.ParseCIDR("192.168.1.0/24")
	r.DstNetwork = ipNet2
	assert.False(t, r.IsDefaultRoute())
}

// NetworkInstanceStatus.IsIpAssigned

func TestNetworkInstanceStatusIsIpAssigned(t *testing.T) {
	ip1 := net.ParseIP("192.168.1.10")
	ip2 := net.ParseIP("10.0.0.5")
	ip6 := net.ParseIP("fd00::1")

	status := NetworkInstanceStatus{
		NetworkInstanceInfo: NetworkInstanceInfo{
			IPAssignments: map[string]AssignedAddrs{
				"mac1": {
					IPv4Addrs: []AssignedAddr{{Address: ip1}},
					IPv6Addrs: []AssignedAddr{{Address: ip6}},
				},
			},
		},
	}

	assert.True(t, status.IsIpAssigned(ip1))
	assert.True(t, status.IsIpAssigned(ip6))
	assert.False(t, status.IsIpAssigned(ip2))
}

// NestedAppDomainStatus.Key

func TestNestedAppDomainStatusKey(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	s := NestedAppDomainStatus{
		UUIDandVersion: UUIDandVersion{UUID: id},
	}
	assert.Equal(t, id.String(), s.Key())
}

// NestedAppRuntimeDiskMetric.Key

func TestNestedAppRuntimeDiskMetricKey(t *testing.T) {
	m := NestedAppRuntimeDiskMetric{UUID: "some-uuid-string"}
	assert.Equal(t, "some-uuid-string", m.Key())
}

// AppNetworkStatus.Pending and GetAdaptersStatusForNI

func TestAppNetworkStatusPending(t *testing.T) {
	assert.False(t, AppNetworkStatus{}.Pending())
	assert.True(t, AppNetworkStatus{PendingAdd: true}.Pending())
	assert.True(t, AppNetworkStatus{PendingModify: true}.Pending())
	assert.True(t, AppNetworkStatus{PendingDelete: true}.Pending())
}

func TestAppNetworkStatusGetAdaptersStatusForNI(t *testing.T) {
	ni1 := uuid.Must(uuid.NewV4())
	ni2 := uuid.Must(uuid.NewV4())
	status := AppNetworkStatus{
		AppNetAdapterList: []AppNetAdapterStatus{
			{AppNetAdapterConfig: AppNetAdapterConfig{Network: ni1}},
			{AppNetAdapterConfig: AppNetAdapterConfig{Network: ni2}},
			{AppNetAdapterConfig: AppNetAdapterConfig{Network: ni1}},
		},
	}
	adapters := status.GetAdaptersStatusForNI(ni1)
	assert.Len(t, adapters, 2)

	assert.Len(t, status.GetAdaptersStatusForNI(uuid.Must(uuid.NewV4())), 0)
}

// AssignedAddrs.GetInternallyLeasedIPv4Addr

func TestAssignedAddrsGetInternallyLeasedIPv4Addr(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	aa := AssignedAddrs{
		IPv4Addrs: []AssignedAddr{
			{Address: net.ParseIP("192.168.1.1"), AssignedBy: AddressSourceExternalDHCP},
			{Address: ip, AssignedBy: AddressSourceInternalDHCP},
		},
	}
	got := aa.GetInternallyLeasedIPv4Addr()
	require.NotNil(t, got)
	assert.Equal(t, ip.String(), got.String())

	// No internal DHCP → nil
	aa2 := AssignedAddrs{
		IPv4Addrs: []AssignedAddr{
			{Address: net.ParseIP("192.168.1.1"), AssignedBy: AddressSourceExternalDHCP},
		},
	}
	assert.Nil(t, aa2.GetInternallyLeasedIPv4Addr())
}

// DnsmasqLeaseFilePath

func TestDnsmasqLeaseFilePath(t *testing.T) {
	p := DnsmasqLeaseFilePath("bn1")
	assert.Equal(t, DnsmasqLeaseDir+"bn1", p)
}

// NetworkInstanceInfo.IsVifInBridge

func TestNetworkInstanceInfoIsVifInBridge(t *testing.T) {
	info := &NetworkInstanceInfo{
		Vifs: []VifNameMac{
			{Name: "vif0"},
			{Name: "vif1"},
		},
	}
	assert.True(t, info.IsVifInBridge("vif0"))
	assert.True(t, info.IsVifInBridge("vif1"))
	assert.False(t, info.IsVifInBridge("vif2"))
}

// NetworkMetrics.LookupNetworkMetrics

func TestNetworkMetricsLookupNetworkMetrics(t *testing.T) {
	nms := NetworkMetrics{
		MetricList: []NetworkMetric{
			{IfName: "eth0", TxBytes: 100},
			{IfName: "eth1", TxBytes: 200},
		},
	}
	m, ok := nms.LookupNetworkMetrics("eth0")
	assert.True(t, ok)
	assert.Equal(t, uint64(100), m.TxBytes)

	_, ok = nms.LookupNetworkMetrics("eth9")
	assert.False(t, ok)
}

// NetworkInstanceConfig.IsIPv6

func TestNetworkInstanceConfigIsIPv6(t *testing.T) {
	assert.True(t, (&NetworkInstanceConfig{IpType: AddressTypeIPV6}).IsIPv6())
	assert.True(t, (&NetworkInstanceConfig{IpType: AddressTypeCryptoIPV6}).IsIPv6())
	assert.False(t, (&NetworkInstanceConfig{IpType: AddressTypeIPV4}).IsIPv6())
	assert.False(t, (&NetworkInstanceConfig{}).IsIPv6())
}

// NetworkInstanceStatus.EligibleForActivate

func TestNetworkInstanceStatusEligibleForActivate(t *testing.T) {
	s := NetworkInstanceStatus{}
	assert.True(t, s.EligibleForActivate())

	s.ValidationErr = ErrorAndTime{ErrorDescription: ErrorDescription{Error: "err"}}
	assert.False(t, s.EligibleForActivate())
}

// IPRouteInfo.IsDefaultRoute and Equal

func TestIPRouteInfoIsDefaultRoute(t *testing.T) {
	// nil DstNetwork → default
	r := IPRouteInfo{}
	assert.True(t, r.IsDefaultRoute())

	// 0.0.0.0/0 → default
	_, netw, _ := net.ParseCIDR("0.0.0.0/0")
	r.DstNetwork = netw
	assert.True(t, r.IsDefaultRoute())

	// Specific subnet → not default
	_, netw, _ = net.ParseCIDR("10.0.0.0/8")
	r.DstNetwork = netw
	assert.False(t, r.IsDefaultRoute())
}

func TestIPRouteInfoEqual(t *testing.T) {
	_, dst, _ := net.ParseCIDR("192.168.0.0/24")
	gw := net.ParseIP("10.0.0.1")
	id := uuid.Must(uuid.NewV4())

	r1 := IPRouteInfo{
		IPVersion:   4,
		DstNetwork:  dst,
		Gateway:     gw,
		OutputPort:  "eth0",
		GatewayApp:  id,
	}
	r2 := r1
	assert.True(t, r1.Equal(r2))

	r2.OutputPort = "eth1"
	assert.False(t, r1.Equal(r2))

	r2 = r1
	r2.IPVersion = 6
	assert.False(t, r1.Equal(r2))
}

// AppNetworkStatus.GetAllAppIPs

func TestAppNetworkStatusGetAllAppIPs(t *testing.T) {
	ip4 := net.ParseIP("10.0.0.1")
	ip6 := net.ParseIP("fd00::1")

	s := AppNetworkStatus{
		AppNetAdapterList: []AppNetAdapterStatus{
			{
				AssignedAddresses: AssignedAddrs{
					IPv4Addrs: []AssignedAddr{{Address: ip4}},
					IPv6Addrs: []AssignedAddr{{Address: ip6}},
				},
			},
		},
	}

	ips := s.GetAllAppIPs()
	require.Len(t, ips, 2)

	// Empty status → nil
	assert.Nil(t, AppNetworkStatus{}.GetAllAppIPs())
}

// NetworkInstanceInfo.AddVif and RemoveVif

func TestNetworkInstanceInfoAddRemoveVif(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 0) //nolint:staticcheck
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	appID := uuid.Must(uuid.NewV4())

	info := &NetworkInstanceInfo{}
	info.AddVif(log, "vif0", mac, appID)
	require.Len(t, info.Vifs, 1)
	assert.Equal(t, "vif0", info.Vifs[0].Name)

	// Adding same vif again is a no-op (logged error)
	info.AddVif(log, "vif0", mac, appID)
	assert.Len(t, info.Vifs, 1)

	info.RemoveVif(log, "vif0")
	assert.Len(t, info.Vifs, 0)
}

// IPRouteConfig.Equal
// Note: the implementation uses && not == for PreferStrongerWwanSignal,
// so both must be true for Equal to return true with that flag set.

func TestIPRouteConfigEqual(t *testing.T) {
	_, dst, _ := net.ParseCIDR("192.168.0.0/24")
	gw := net.ParseIP("10.0.0.1")

	r1 := IPRouteConfig{
		DstNetwork:              dst,
		Gateway:                 gw,
		OutputPortLabel:         "eth0",
		PreferStrongerWwanSignal: true,
	}
	r2 := r1
	assert.True(t, r1.Equal(r2))

	r2.OutputPortLabel = "eth1"
	assert.False(t, r1.Equal(r2))

	r2 = r1
	r2.Gateway = net.ParseIP("10.0.0.2")
	assert.False(t, r1.Equal(r2))
}

// IPRouteConfig.String

func TestIPRouteConfigString(t *testing.T) {
	_, dst, _ := net.ParseCIDR("10.0.0.0/8")
	gw := net.ParseIP("192.168.1.1")

	r := IPRouteConfig{
		DstNetwork:      dst,
		Gateway:         gw,
		OutputPortLabel: "eth0",
	}
	s := r.String()
	assert.Contains(t, s, "10.0.0.0/8")
	assert.Contains(t, s, "eth0")
}

// ConnectivityProbe.String

func TestConnectivityProbeString(t *testing.T) {
	cp := ConnectivityProbe{Method: ConnectivityProbeMethodNone}
	assert.Equal(t, "<none>", cp.String())

	cp = ConnectivityProbe{Method: ConnectivityProbeMethodICMP, ProbeHost: "1.2.3.4"}
	assert.Equal(t, "icmp://1.2.3.4", cp.String())

	cp = ConnectivityProbe{Method: ConnectivityProbeMethodTCP, ProbeHost: "1.2.3.4", ProbePort: 80}
	assert.Equal(t, "tcp://1.2.3.4:80", cp.String())
}

// NetworkInstanceStatus.CombineErrors

func TestNetworkInstanceStatusCombineErrors(t *testing.T) {
	// No errors → empty result
	s := NetworkInstanceStatus{}
	combined := s.CombineErrors()
	assert.False(t, combined.HasError())

	// One error present
	s.ValidationErr = ErrorAndTime{}
	s.ValidationErr.SetError("validation failed", time.Now())
	combined = s.CombineErrors()
	assert.True(t, combined.HasError())
	assert.Contains(t, combined.Error, "validation failed")
}

// AppMACGenerator.New

func TestAppMACGeneratorNew(t *testing.T) {
	id := uuid.Must(uuid.NewV4())
	gen := &AppMACGenerator{UuidToNum: &UuidToNum{}}
	key := UuidToNumKey{UUID: id}
	obj := gen.New(key)
	require.NotNil(t, obj)
	result, ok := obj.(*AppMACGenerator)
	require.True(t, ok)
	assert.Equal(t, id, result.UUID)
}

// NetworkInstanceInfo.RemoveVif — not-found case

func TestNetworkInstanceInfoRemoveVifNotFound(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 0) //nolint:staticcheck
	info := NetworkInstanceInfo{
		BridgeName: "br0",
		Vifs:       []VifNameMac{{Name: "vif0"}},
	}
	// Removing a vif that doesn't exist logs an error but doesn't panic
	info.RemoveVif(log, "vif99")
	// Original vif is still there
	assert.Len(t, info.Vifs, 1)
	assert.Equal(t, "vif0", info.Vifs[0].Name)
}

// ConnectivityProbe.FromProto — port out of range

func TestConnectivityProbeFromProtoTCPPortOutOfRange(t *testing.T) {
	var cp ConnectivityProbe
	proto := &evecommon.ConnectivityProbe{
		ProbeMethod: evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_TCP,
		ProbeEndpoint: &evecommon.ProbeEndpoint{
			Host: "10.0.0.1",
			Port: 70000, // > 65535
		},
	}
	err := cp.FromProto(proto)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

// ConnectivityProbe.FromProto — ICMP with invalid IP

func TestConnectivityProbeFromProtoICMPInvalidIPAddr(t *testing.T) {
	var cp ConnectivityProbe
	proto := &evecommon.ConnectivityProbe{
		ProbeMethod: evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_ICMP,
		ProbeEndpoint: &evecommon.ProbeEndpoint{
			Host: "not-an-ip",
		},
	}
	err := cp.FromProto(proto)
	assert.Error(t, err)
}

// ConnectivityProbe.ToProto — unknown method (default fallback)

func TestConnectivityProbeToProtoUnknownMethod(t *testing.T) {
	cp := ConnectivityProbe{Method: ConnectivityProbeMethod(99)}
	proto := cp.ToProto()
	require.NotNil(t, proto)
	assert.Equal(t, evecommon.ConnectivityProbeMethod_CONNECTIVITY_PROBE_METHOD_UNSPECIFIED,
		proto.ProbeMethod)
}
