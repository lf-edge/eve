// Copyright (c) 2017-2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import "fmt"

// IPAddrNotAvailError is returned when there is no (suitable) IP address
// assigned to a given interface.
type IPAddrNotAvailError struct {
	IfName string
}

// Error message.
func (e *IPAddrNotAvailError) Error() string {
	return fmt.Sprintf("interface %s: no suitable IP address available", e.IfName)
}

// DNSNotAvailError is returned when there is no DNS server configured
// for a given interface.
type DNSNotAvailError struct {
	IfName string
}

// Error message.
func (e *DNSNotAvailError) Error() string {
	return fmt.Sprintf("interface %s: no DNS server available", e.IfName)
}
