// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"crypto/sha256"
	"fmt"
	"net"

	"github.com/lf-edge/eve/pkg/pillar/nistate"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	uuid "github.com/satori/go.uuid"
)

func (z *zedrouter) generateBridgeMAC(brNum int) net.HardwareAddr {
	return net.HardwareAddr{0x00, 0x16, 0x3e, 0x06, 0x00, byte(brNum)}
}

// generateAppMac calculates random but stable (not changing across reboots) MAC address
// for a given app instance.
// The generated MAC addresses are locally administered addresses (LAA).
//
// For switch network instances we use OUI 02-16-3E. It is important to preserve
// the method of generating addresses for VIFs on switch network instances across EVE
// versions, so that DHCP servers on external networks are likely to assign the same
// IP addresses across upgrades.
// Another important aspect of switch network instances, is that two edge nodes could be
// connected to the same network segment. It is therefore important that the seed used
// to randomly generate the second half of the MAC address is unique to the app VIF
// globally or at least within the enterprise (e.g. app UUID + VIF index).
//
// Even for local network instances we generate random MAC address that with a high
// probability will not collide with other apps on other edge nodes. From networking
// point of view this is not necessary, but there are apps that use MAC address as some
// sort of ID and could fail to function properly if there is a collision across edge
// nodes. Here the collision could be a problem from edge app perspective even for edge
// nodes in completely different locations and connected to different networks.
// We therefore need even higher probability of address uniqueness. For example, with 24
// random bits and 1000 app interfaces the change of a collision would be as high as 3%.
// Since these MAC addresses will not appear on external Ethernet networks, we can also
// use OUI octets for randomness. Only I/G and U/L bits need to stay constant and set
// appropriately.
func (z *zedrouter) generateAppMac(appUUID uuid.UUID, adapterNum int, appNum int,
	netInstStatus *types.NetworkInstanceStatus) net.HardwareAddr {
	h := sha256.New()
	h.Write(appUUID[:])
	h.Write(netInstStatus.UUIDandVersion.UUID[:])
	nums := make([]byte, 2)
	nums[0] = byte(adapterNum)
	nums[1] = byte(appNum)
	h.Write(nums)
	hash := h.Sum(nil)
	switch netInstStatus.Type {
	case types.NetworkInstanceTypeSwitch:
		return net.HardwareAddr{0x02, 0x16, 0x3e, hash[0], hash[1], hash[2]}
	case types.NetworkInstanceTypeLocal:
		if z.localLegacyMACAddr {
			z.log.Noticef("generateAppMac: legacy MAC address for app %v", appUUID)
			// Room to handle multiple underlays in 5th byte
			return net.HardwareAddr{0x00, 0x16, 0x3e, 0x00, byte(adapterNum), byte(appNum)}
		}
		z.log.Noticef("generateAppMac: random MAC address for app %v", appUUID)
		mac := net.HardwareAddr{hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]}
		// Mark this MAC address as unicast by setting the I/G bit to zero.
		mac[0] &= ^byte(1)
		// Mark this MAC address as locally administered by setting the U/L bit to 1.
		mac[0] |= byte(1 << 1)
		return mac
	default:
		z.log.Fatalf("unsupported network instance type")
	}
	return nil
}

// Returns an IPv4 address allocated for the guest side of an application VIF.
func (z *zedrouter) lookupOrAllocateIPv4ForVIF(niStatus *types.NetworkInstanceStatus,
	adapterStatus types.AppNetAdapterStatus, appID uuid.UUID) (net.IP, error) {
	var err error
	var ipAddr net.IP
	networkID := niStatus.UUID

	if niStatus.Subnet.IP == nil || niStatus.DhcpRange.Start == nil {
		z.log.Functionf("lookupOrAllocateIPv4(NI:%v, app:%v): no IP subnet",
			networkID, appID)
		return nil, nil
	}
	if adapterStatus.Mac == nil {
		z.log.Functionf("lookupOrAllocateIPv4(NI:%v, app:%v): no MAC address",
			networkID, appID)
		return nil, nil
	}

	if adapterStatus.AppIPAddr != nil {
		// User-configured static IP address.
		ipAddr = adapterStatus.AppIPAddr
		if niStatus.DhcpRange.Contains(adapterStatus.AppIPAddr) {
			err = fmt.Errorf("static IP(%v) is in DhcpRange(%v, %v)",
				ipAddr, niStatus.DhcpRange.Start,
				niStatus.DhcpRange.End)
			z.log.Errorf("lookupOrAllocateIPv4(NI:%v, app:%v): %v",
				networkID, appID, err)
			return nil, err
		}
		if !niStatus.Subnet.Contains(adapterStatus.AppIPAddr) {
			err = fmt.Errorf("static IP(%s) is outside subnet range",
				ipAddr)
			z.log.Errorf("lookupOrAllocateIPv4(NI:%v, app:%v): %v",
				networkID, appID, err)
			return nil, err
		}
	}

	// Lookup to see if it is already allocated.
	if ipAddr == nil {
		addrs := niStatus.IPAssignments[adapterStatus.Mac.String()]
		if !isEmptyIP(addrs.IPv4Addr) {
			z.log.Functionf("lookupOrAllocateIPv4(NI:%v, app:%v): found IP %v for MAC %v",
				networkID, appID, addrs.IPv4Addr, adapterStatus.Mac)
			ipAddr = addrs.IPv4Addr
		}
	}

	if ipAddr == nil {
		// Allocate IP address dynamically.
		// Get the app number for the AppNetAdapter entry.
		var appNum int
		appNum, err = z.getAppIntfNum(networkID, appID, adapterStatus.IfIdx)
		if err != nil {
			err = fmt.Errorf("failed to get app number: %w", err)
			z.log.Errorf("lookupOrAllocateIPv4(NI:%v, app:%v): %v",
				networkID, appID, err)
			return nil, err
		}
		// Pick an IP address from the subnet.
		ipAddr = netutils.AddToIP(niStatus.DhcpRange.Start, appNum)
		// Check if the address falls into the Dhcp Range.
		if !niStatus.DhcpRange.Contains(ipAddr) {
			err := fmt.Errorf("no free IP addresses in DHCP range(%v, %v)",
				niStatus.DhcpRange.Start, niStatus.DhcpRange.End)
			z.log.Errorf("lookupOrAllocateIPv4(NI:%v, app:%v): %v",
				networkID, appID, err)
			// Release this interface number, it produces IP address outside the range
			// anyway. Once another already deployed app is deleted and its IP allocations
			// are freed, retryTimer will call handleAppNetworkCreate for this app
			// again and it will reuse interface number(s) of the deleted app, which
			// will then produce a valid IP address fitting the DHCP range.
			// Otherwise, zedrouter would just try to use the same IP address outside
			// the DHCP range and fail repeatedly, even after there is free IP available.
			err2 := z.freeAppIntfNum(networkID, appID, adapterStatus.IfIdx)
			if err2 != nil {
				// Should be unreachable.
				z.log.Error(err2)
			}
			return nil, err
		}
	}
	// Later will be overwritten with addresses received from nistate.Collector,
	// which snoops DHCP traffic and watches DNS server leases to learn the *actual*
	// IP address assignments.
	addrs := niStatus.IPAssignments[adapterStatus.Mac.String()] // preserve IPv6 addresses
	addrs.IPv4Addr = ipAddr
	niStatus.IPAssignments[adapterStatus.Mac.String()] = addrs
	z.publishNetworkInstanceStatus(niStatus)
	z.log.Functionf("lookupOrAllocateIPv4(NI:%v, app:%v): allocated IP %v for MAC %v",
		networkID, appID, ipAddr, adapterStatus.Mac)
	return ipAddr, nil
}

func (z *zedrouter) reloadStatusOfAssignedIPs(status *types.AppNetworkStatus) {
	for i := range status.AppNetAdapterList {
		adapterStatus := &status.AppNetAdapterList[i]
		allAddrs, _ := z.niStateCollector.GetIPAssignments(adapterStatus.Network)
		vifAddrs := allAddrs.LookupByAdapterName(status.UUIDandVersion.UUID, adapterStatus.Name)
		z.recordAssignedIPsToAdapterStatus(adapterStatus, vifAddrs)
	}
}

func (z *zedrouter) recordAssignedIPsToAdapterStatus(adapter *types.AppNetAdapterStatus,
	vifAddrs *nistate.VIFAddrs) {
	if vifAddrs == nil {
		z.removeAssignedIPsFromAdapterStatus(adapter)
		return
	}
	adapter.AllocatedIPv4Addr = vifAddrs.IPv4Addr
	if !isEmptyIP(adapter.AppIPAddr) &&
		!adapter.AppIPAddr.Equal(adapter.AllocatedIPv4Addr) {
		// Config and status do not match.
		adapter.IPAddrMisMatch = true
	} else {
		adapter.IPAddrMisMatch = false
	}
	adapter.AllocatedIPv6List = vifAddrs.IPv6Addrs
	adapter.IPv4Assigned = !isEmptyIP(vifAddrs.IPv4Addr)
}

func (z *zedrouter) removeAssignedIPsFromAppNetStatus(status *types.AppNetworkStatus) {
	for i := range status.AppNetAdapterList {
		adapterStatus := &status.AppNetAdapterList[i]
		z.removeAssignedIPsFromAdapterStatus(adapterStatus)
	}
}

func (z *zedrouter) removeAssignedIPsFromAdapterStatus(adapterStatus *types.AppNetAdapterStatus) {
	adapterStatus.AllocatedIPv6List = nil
	adapterStatus.AllocatedIPv4Addr = nil
	adapterStatus.IPAddrMisMatch = false
	adapterStatus.IPv4Assigned = false
}

func isEmptyIP(ip net.IP) bool {
	return ip == nil || ip.Equal(net.IP{})
}
