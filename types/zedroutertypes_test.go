// Copyright (c) 2019 Zededa, Inc.
// All rights reserved.

package types

import (
	"net"
	"testing"

	log "github.com/sirupsen/logrus"
)

type TestIsIPv6MatrixEntry struct {
	config        NetworkInstanceConfig
	expectedValue bool
}

func TestIsIPv6(t *testing.T) {
	log.Infof("TestIsIPv6: START\n")

	testMatrix := []TestIsIPv6MatrixEntry{
		{config: NetworkInstanceConfig{IpType: AddressTypeIPV6},
			expectedValue: true},
		{config: NetworkInstanceConfig{IpType: AddressTypeCryptoIPV6},
			expectedValue: true},
		{config: NetworkInstanceConfig{IpType: AddressTypeIPV4},
			expectedValue: false},
		{config: NetworkInstanceConfig{IpType: AddressTypeCryptoIPV4},
			expectedValue: false},
		{config: NetworkInstanceConfig{IpType: AddressTypeFirst},
			expectedValue: false},
		{config: NetworkInstanceConfig{IpType: AddressTypeLast},
			expectedValue: false},
	}

	// Basic test
	for index := range testMatrix {
		entry := &testMatrix[index]
		isIPv6 := entry.config.IsIPv6()
		if isIPv6 != entry.expectedValue {
			t.Errorf("Test Entry Index %d Failed: Expected %t, Actual: %t\n",
				index, entry.expectedValue, isIPv6)
		}
	}
	log.Infof("TestIsIPv6: DONE\n")
}

type TestSubnetBroadcastAddrMatrixEntry struct {
	subnet        string
	expectedValue string
}

func TestSubnetBroadcastAddr(t *testing.T) {
	log.Infof("TestSubnetBroadcastAddr: START\n")

	testMatrix := []TestSubnetBroadcastAddrMatrixEntry{
		{subnet: "192.168.254.0/24", expectedValue: "192.168.254.255"},
		{subnet: "192.168.1.1/32", expectedValue: "192.168.1.1"},
		{subnet: "10.0.1.16/28", expectedValue: "10.0.1.31"},
		{subnet: "192.168.1.0/29", expectedValue: "192.168.1.7"},
		{subnet: "32.0.0.0/4", expectedValue: "47.255.255.255"},
		{subnet: "165.24.0.0/14", expectedValue: "165.27.255.255"},
		{subnet: "212.34.32.0/22", expectedValue: "212.34.35.255"},
	}

	// Basic test
	for index := range testMatrix {
		entry := &testMatrix[index]
		var config NetworkInstanceConfig
		_, subnet, _ := net.ParseCIDR(entry.subnet)
		config.Subnet = *subnet
		subnetBroadcastAddr := config.SubnetBroadcastAddr().String()
		if subnetBroadcastAddr != entry.expectedValue {
			t.Errorf("Test Entry Index %d Failed: Expected %s, Actual: %s\n",
				index, entry.expectedValue, subnetBroadcastAddr)
		}
	}
	log.Infof("TestSubnetBroadcastAddr: DONE\n")
}
