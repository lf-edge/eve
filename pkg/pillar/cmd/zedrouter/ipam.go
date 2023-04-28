// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"crypto/sha256"
	"fmt"
	"net"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

func (z *zedrouter) generateBridgeMAC(brNum int) net.HardwareAddr {
	return net.HardwareAddr{0x00, 0x16, 0x3e, 0x06, 0x00, byte(brNum)}
}

// generateAppMac picks a fixed address for Local and uses a fixed hash for Switch
// which still produces a stable MAC address for a given app instance.
func (z *zedrouter) generateAppMac(appUUID uuid.UUID, ulNum int, appNum int,
	netInstStatus *types.NetworkInstanceStatus) net.HardwareAddr {
	switch netInstStatus.Type {
	case types.NetworkInstanceTypeSwitch:
		h := sha256.New()
		h.Write(appUUID[:])
		h.Write(netInstStatus.UUIDandVersion.UUID[:])
		nums := make([]byte, 2)
		nums[0] = byte(ulNum)
		nums[1] = byte(appNum)
		h.Write(nums)
		hash := h.Sum(nil)
		return net.HardwareAddr{0x02, 0x16, 0x3e, hash[0], hash[1], hash[2]}

	case types.NetworkInstanceTypeLocal:
		// Room to handle multiple underlays in 5th byte
		return net.HardwareAddr{0x00, 0x16, 0x3e, 0x00, byte(ulNum), byte(appNum)}
	}
	return nil
}

// Returns an IPv4 address allocated for the guest side of an application VIF.
func (z *zedrouter) lookupOrAllocateIPv4ForVIF(niStatus *types.NetworkInstanceStatus,
	ulStatus types.UnderlayNetworkStatus, appID uuid.UUID) (net.IP, error) {
	var err error
	var ipAddr net.IP
	networkID := niStatus.UUID

	if niStatus.Subnet.IP == nil || niStatus.DhcpRange.Start == nil {
		z.log.Functionf("lookupOrAllocateIPv4(NI:%v, app:%v): no IP subnet",
			networkID, appID)
		return nil, nil
	}
	if ulStatus.Mac == nil {
		z.log.Functionf("lookupOrAllocateIPv4(NI:%v, app:%v): no MAC address",
			networkID, appID)
		return nil, nil
	}

	if ulStatus.AppIPAddr != nil {
		// User-configured static IP address.
		ipAddr = ulStatus.AppIPAddr
		if niStatus.DhcpRange.Contains(ulStatus.AppIPAddr) {
			err = fmt.Errorf("static IP(%v) is in DhcpRange(%v, %v)",
				ipAddr, niStatus.DhcpRange.Start,
				niStatus.DhcpRange.End)
			z.log.Errorf("lookupOrAllocateIPv4(NI:%v, app:%v): %v",
				networkID, appID, err)
			return nil, err
		}
		if !niStatus.Subnet.Contains(ulStatus.AppIPAddr) {
			err = fmt.Errorf("static IP(%s) is outside subnet range",
				ipAddr)
			z.log.Errorf("lookupOrAllocateIPv4(NI:%v, app:%v): %v",
				networkID, appID, err)
			return nil, err
		}
	}

	// Lookup to see if it is already allocated.
	if ipAddr == nil {
		addrs := niStatus.IPAssignments[ulStatus.Mac.String()]
		if !isEmptyIP(addrs.IPv4Addr) {
			z.log.Functionf("lookupOrAllocateIPv4(NI:%v, app:%v): found IP %v for MAC %v",
				networkID, appID, addrs.IPv4Addr, ulStatus.Mac)
			ipAddr = addrs.IPv4Addr
		}
	}

	if ipAddr == nil {
		// Allocate IP address dynamically.
		// Get the app number for the underlay network entry.
		var appNum int
		appNum, err = z.getAppIntfNum(networkID, appID, ulStatus.IfIdx)
		if err != nil {
			err = fmt.Errorf("failed to get app number: %w", err)
			z.log.Errorf("lookupOrAllocateIPv4(NI:%v, app:%v): %v",
				networkID, appID, err)
			return nil, err
		}
		// Pick an IP address from the subnet.
		ipAddr = types.AddToIP(niStatus.DhcpRange.Start, appNum)
		// Check if the address falls into the Dhcp Range.
		if !niStatus.DhcpRange.Contains(ipAddr) {
			err := fmt.Errorf("no free IP addresses in DHCP range(%v, %v)",
				niStatus.DhcpRange.Start, niStatus.DhcpRange.End)
			z.log.Errorf("lookupOrAllocateIPv4(NI:%v, app:%v): %v",
				networkID, appID, err)
			return nil, err
		}
	}
	// Later will be overwritten with addresses received from NIStateCollector,
	// which snoops DHCP traffic and watches DNS server leases to learn the *actual*
	// IP address assignments.
	addrs := niStatus.IPAssignments[ulStatus.Mac.String()] // preserve IPv6 addresses
	addrs.IPv4Addr = ipAddr
	niStatus.IPAssignments[ulStatus.Mac.String()] = addrs
	z.publishNetworkInstanceStatus(niStatus)
	z.log.Functionf("lookupOrAllocateIPv4(NI:%v, app:%v): allocated IP %v for MAC %v",
		networkID, appID, ipAddr, ulStatus.Mac)
	return ipAddr, nil
}

func (z *zedrouter) releaseAllIPsForVIF(status *types.NetworkInstanceStatus,
	mac net.HardwareAddr) error {
	z.log.Functionf("releaseIPv4FromNetworkInstance(NI:%v, MAC:%v)",
		status.UUID, mac)
	// Lookup to see if VIF IP addresses are allocated.
	if _, ok := status.IPAssignments[mac.String()]; !ok {
		err := fmt.Errorf("IP address not found for MAC %v", mac)
		z.log.Errorf("releaseIPv4FromNetworkInstance(NI:%v, MAC:%v): %v",
			status.UUID, mac, err)
		return err
	}
	delete(status.IPAssignments, mac.String())
	z.publishNetworkInstanceStatus(status)
	return nil
}

func isEmptyIP(ip net.IP) bool {
	return ip == nil || ip.Equal(net.IP{})
}
