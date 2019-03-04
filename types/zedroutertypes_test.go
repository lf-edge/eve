// Copyright (c) 2019 Zededa, Inc.
// All rights reserved.

package types

import (
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
		{config: NetworkInstanceConfig{IpType: AddressTypeNone},
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
