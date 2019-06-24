// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"testing"
)

var underlayUUID = uuid.UUID{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
var overlayUUID = uuid.UUID{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1,
	0x80, 0xb4, 0xd4, 0xd4, 0xd4, 0xd4, 0x30, 0xc8}
var appNetworkConfig = AppNetworkConfig{
	OverlayNetworkList: []OverlayNetworkConfig{
		OverlayNetworkConfig{Network: overlayUUID},
	},
	UnderlayNetworkList: []UnderlayNetworkConfig{
		UnderlayNetworkConfig{Network: underlayUUID},
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
		assert.Equal(t, networkUsed, test.expectedValue)
	}
}
