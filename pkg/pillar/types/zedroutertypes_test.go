// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

var underlayUUID = uuid.UUID{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
var overlayUUID = uuid.UUID{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0xd4, 0xd4, 0xd4, 0xd4, 0x30, 0xc8}
var appNetworkConfig = AppNetworkConfig{
	OverlayNetworkList: []OverlayNetworkConfig{
		{Network: overlayUUID},
	},
	UnderlayNetworkList: []UnderlayNetworkConfig{
		{Network: underlayUUID},
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
func TestGetOverlayConfig(t *testing.T) {
	testMatrix := map[string]struct {
		network uuid.UUID
		config  AppNetworkConfig
	}{
		"Overlay UUID": {
			network: overlayUUID,
			config:  appNetworkConfig,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		config := test.config.getOverlayConfig(test.network)
		assert.IsType(t, test.config.OverlayNetworkList[0], *config)
	}
}
func TestGetUnderlayConfig(t *testing.T) {
	testMatrix := map[string]struct {
		network uuid.UUID
		config  AppNetworkConfig
	}{
		"Underlay UUID": {
			network: underlayUUID,
			config:  appNetworkConfig,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		config := test.config.getUnderlayConfig(test.network)
		assert.IsType(t, test.config.UnderlayNetworkList[0], *config)
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
		"Overlay UUID": {
			network:       overlayUUID,
			expectedValue: true,
			config:        appNetworkConfig,
		},
		"Underlay UUID": {
			network:       underlayUUID,
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
	DhcpConfig:   DhcpConfig{Dhcp: DT_CLIENT},
}
var usablePorts = []NetworkPortConfig{usablePort}

var unusablePort1 = NetworkPortConfig{
	IfName:       "eth0",
	Phylabel:     "eth0",
	Logicallabel: "eth0",
	IsMgmt:       false,
	DhcpConfig:   DhcpConfig{Dhcp: DT_CLIENT},
}
var unusablePorts1 = []NetworkPortConfig{unusablePort1}

var unusablePort2 = NetworkPortConfig{
	IfName:       "eth0",
	Phylabel:     "eth0",
	Logicallabel: "eth0",
	IsMgmt:       true,
	DhcpConfig:   DhcpConfig{Dhcp: DT_NONE},
}
var unusablePorts2 = []NetworkPortConfig{unusablePort2}
var mixedPorts = []NetworkPortConfig{usablePort, unusablePort1, unusablePort2}

func TestIsDPCUsable(t *testing.T) {
	n := time.Now()
	testMatrix := map[string]struct {
		devicePortConfig DevicePortConfig
		expectedValue    bool
	}{
		"Management and DT_CLIENT": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    time.Time{},
				LastSucceeded: n,
				Ports:         usablePorts,
			},
			expectedValue: true,
		},
		"Mixture of usable and unusable ports": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    time.Time{},
				LastSucceeded: n,
				Ports:         mixedPorts,
			},
			expectedValue: true,
		},
		"Not management and DT_CLIENT": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    time.Time{},
				LastSucceeded: n,
				Ports:         unusablePorts1,
			},
			expectedValue: false,
		},
		"Management and DT_NONE": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    time.Time{},
				LastSucceeded: n,
				Ports:         unusablePorts2,
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
	n := time.Now()
	testMatrix := map[string]struct {
		devicePortConfig DevicePortConfig
		expectedValue    bool
	}{
		"Difference is exactly 60 seconds": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    n.Add(time.Second * 60),
				LastSucceeded: n,
				Ports:         usablePorts,
			},
			expectedValue: false,
		},
		"Difference is 61 seconds": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    n.Add(time.Second * 61),
				LastSucceeded: n,
				Ports:         usablePorts,
			},
			expectedValue: false,
		},
		"Difference is 59 seconds": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    n.Add(time.Second * 59),
				LastSucceeded: n,
				Ports:         usablePorts,
			},
			expectedValue: false,
		},
		"LastFailed is 0": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    time.Time{},
				LastSucceeded: n,
				Ports:         usablePorts,
			},
			expectedValue: true,
		},
		"Last Succeded is after Last Failed": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    n,
				LastSucceeded: n.Add(time.Second * 61),
				Ports:         usablePorts,
			},
			expectedValue: true,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		value := test.devicePortConfig.IsDPCTestable()
		assert.Equal(t, test.expectedValue, value)
	}
}

func TestIsDPCUntested(t *testing.T) {
	n := time.Now()
	testMatrix := map[string]struct {
		devicePortConfig DevicePortConfig
		expectedValue    bool
	}{
		"Last failed and Last Succesed are 0": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    time.Time{},
				LastSucceeded: time.Time{},
				Ports:         usablePorts,
			},
			expectedValue: true,
		},
		"Last Succesed is not 0": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    time.Time{},
				LastSucceeded: n,
				Ports:         usablePorts,
			},
			expectedValue: false,
		},
		"Last failed is not 0": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    time.Time{},
				LastSucceeded: n,
				Ports:         usablePorts,
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
		"LastSucceeded is 0": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    n,
				LastSucceeded: time.Time{},
				Ports:         usablePorts,
			},
			expectedValue: false,
		},
		"Last Succeded is after Last Failed": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    n,
				LastSucceeded: n.Add(time.Second * 60),
				Ports:         usablePorts,
			},
			expectedValue: true,
		},
		"Last Failed is after Last Succeeded": {
			devicePortConfig: DevicePortConfig{
				LastFailed:    n.Add(time.Second * 60),
				LastSucceeded: n,
				Ports:         usablePorts,
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
