// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// IPAddrNotAvailError.Error

func TestIPAddrNotAvailErrorError(t *testing.T) {
	err := &IPAddrNotAvailError{IfName: "eth0"}
	assert.Equal(t, "interface eth0: no suitable IP address available", err.Error())
}

// DNSNotAvailError.Error

func TestDNSNotAvailErrorError(t *testing.T) {
	err := &DNSNotAvailError{IfName: "wlan0"}
	assert.Equal(t, "interface wlan0: no DNS server available", err.Error())
}
