// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"bytes"
	"fmt"
	"net"

	"github.com/lf-edge/eve-libs/depgraph"
)

// AdapterAddrs : allocated network adapter IP addresses (statically or through DHCP).
// This is an external item referenced by items that depend on IP addresses.
type AdapterAddrs struct {
	AdapterIfName string
	// AdapterLL : Adapter's logical label.
	AdapterLL string
	IPAddrs   []*net.IPNet // IP address + subnet
}

// Name returns adapter interface name.
func (a AdapterAddrs) Name() string {
	return a.AdapterIfName
}

// Label for the item.
func (a AdapterAddrs) Label() string {
	return a.AdapterLL + " IP addresses"
}

// Type of the item.
func (a AdapterAddrs) Type() string {
	return AdapterAddrsTypename
}

// Equal compares IP addresses (order is irrelevant).
func (a AdapterAddrs) Equal(other depgraph.Item) bool {
	a2 := other.(AdapterAddrs)
	return isSubsetOf(a.IPAddrs, a2.IPAddrs) &&
		isSubsetOf(a2.IPAddrs, a.IPAddrs)
}

// External returns true because addresses are learned through the NetworkMonitor.
func (a AdapterAddrs) External() bool {
	return true
}

// String describes adapter addresses.
func (a AdapterAddrs) String() string {
	return fmt.Sprintf("Adapter %s IP addresses: %v",
		a.AdapterLL, a.IPAddrs)
}

// Dependencies returns nothing (external item).
func (a AdapterAddrs) Dependencies() (deps []depgraph.Dependency) {
	return nil
}

func isSubsetOf(subset, set []*net.IPNet) bool {
	for _, addr := range subset {
		var found bool
		for _, addr2 := range set {
			if addr.IP.Equal(addr2.IP) &&
				bytes.Compare(addr.Mask, addr2.Mask) == 0 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
