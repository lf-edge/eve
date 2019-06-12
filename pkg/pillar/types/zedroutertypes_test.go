// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

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
