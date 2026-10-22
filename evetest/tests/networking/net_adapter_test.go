// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"net"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
)

func deviceRequirementsForNetAdapterTests(
	devName string, hypervisor evetest.Hypervisor) evetest.RequireEdgeDevice {
	return evetest.RequireEdgeDevice{
		Name:           devName,
		WithHypervisor: hypervisor,
		MinCPUs:        4,
		WithGrubOptions: []string{
			// No applications are deployed in these network adapter tests.
			// Prioritize maximizing EVE performance and reducing device onboarding time.
			"set_global hv_dom0_cpu_settings \"dom0_max_vcpus=4\"",
			"set_global hv_eve_cpu_settings \"eve_max_vcpus=3\"",
			"set_global hv_ctrd_cpu_settings \"ctrd_max_vcpus=3\""},
		DeviceReusePolicy: evetest.ResetDeviceConfig,
	}
}

// TestDHCPIPv4Only verifies that when a port is configured with DHCP-enabled
// and IPv4-only, EVE acquires an IPv4 address via DHCP and explicitly
// does NOT pick up an IPv6 address, even though the SDN network advertises
// IPv6 (DHCPv6 + SLAAC) alongside IPv4.
//
// Network model
// -------------
//   - Dual-stack network that would happily hand out both v4 and v6 if EVE
//     asked for both.
//
// Device configuration
// --------------------
//   - network with DHCP-enabled and NetworkType=V4Only, applied on eth0
//     (mgmt+app usage).
//
// Phases
// ------
//   - Eventually: eth0 acquires IPv4 address AND no IPv6 address.
//   - Consistently for one minute: no IPv6 ever appears on the port.
func TestDHCPIPv4Only(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	// Set up the test harness and specify the test prerequisites.
	devName := "edge-dev"
	requiredDevice := deviceRequirementsForNetAdapterTests(devName, hypervisor)
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCPAndIPv6,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build and apply the initial device configuration.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")

	log := evetest.Logger()

	log.Infof("Waiting for device to report IPv4 (only) address...")
	t.Eventually(func() bool {
		ips := device.GetDeviceIPAddress("ethernet0")
		return containsIPv4(ips) && !containsIPv6(ips)
	}, 3*time.Minute, 10*time.Second).Should(BeTrue())

	t.Consistently(func() bool {
		log.Infof("Checking that eth0 remains without any IPv6 address assigned...")
		ips := device.GetDeviceIPAddress("ethernet0")
		return containsIPv6(ips)
	}, time.Minute, 10*time.Second).Should(BeFalse())
}

// TestStaticIPv4Only verifies that when a port is configured with a
// static network config for IPv4-only, EVE applies the exact static IPv4
// address and does NOT pick up an IPv6 address from a v6-capable SDN
// network.
//
// Network model
// -------------
//   - Dual-stack network without DHCP; the v4 subnet matches the static IP
//     we will assign so the link works, while v6 stays available for the negative
//     assertion.
//
// Device configuration
// --------------------
//   - network with static IPv4 configuration matching the network model
//   - SystemAdapter on eth0 (mgmt+app) with the static IP 172.20.20.100.
//
// Phases
// ------
//   - Eventually: eth0 is configured with 172.20.20.100 AND no IPv6 address.
//   - Consistently for one minute: no IPv6 ever appears on the port.
func TestStaticIPv4Only(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	// Set up the test harness and specify the test prerequisites.
	devName := "edge-dev"
	requiredDevice := deviceRequirementsForNetAdapterTests(devName, hypervisor)
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCPAndIPv6,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build and apply the initial device configuration.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	staticNet := devConfig.AddNetwork(
		evetest.StaticNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
			Subnet:      evetest.IPSubnet("172.20.20.0/24"),
			Gateway:     evetest.IPAddress("172.20.20.1"),
			DNSServers:  []net.IP{evetest.IPAddress("10.16.16.25")},
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   staticNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			StaticIP:      evetest.IPAddress("172.20.20.100"),
		})
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")

	log := evetest.Logger()

	log.Infof("Waiting for device to report the static IPv4 (only) address...")
	t.Eventually(func() bool {
		ips := device.GetDeviceIPAddress("ethernet0")
		containsStaticIP := generics.ContainsItemFn(
			ips, evetest.IPAddress("172.20.20.100"), netutils.EqualIPs)
		return containsStaticIP && !containsIPv6(ips)
	}, 3*time.Minute, 10*time.Second).Should(BeTrue())

	t.Consistently(func() bool {
		log.Infof("Checking that eth0 remains without any IPv6 address assigned...")
		ips := device.GetDeviceIPAddress("ethernet0")
		return containsIPv6(ips)
	}, time.Minute, 10*time.Second).Should(BeFalse())
}

// getPortIPv4Addr returns the first IPv4 address assigned to the port with
// the given logical label from the currently active DevicePortStatus entry,
// or nil if the port is not found or has no IPv4 address.
func getPortIPv4Addr(portLL string, dinfo *eveinfo.ZInfoDevice) net.IP {
	port := getDevicePort(portLL, dinfo)
	if port == nil {
		return nil
	}
	for _, ipStr := range port.GetIPAddrs() {
		ip := net.ParseIP(ipStr)
		if ip != nil && ip.To4() != nil {
			return ip
		}
	}
	return nil
}

// getCurrentDPC returns the active DevicePortStatus from dinfo, or nil if the
// system adapter info is absent or the current index is out of range.
func getCurrentDPC(dinfo *eveinfo.ZInfoDevice) *eveinfo.DevicePortStatus {
	sa := dinfo.GetSystemAdapter()
	if sa == nil {
		return nil
	}
	statusList := sa.GetStatus()
	idx := int(sa.GetCurrentIndex())
	if idx >= len(statusList) {
		return nil
	}
	return statusList[idx]
}

// getDevicePort finds and returns the DevicePort with the given logical label
// from the currently active DevicePortStatus entry in the device info.
func getDevicePort(portLL string, dinfo *eveinfo.ZInfoDevice) *eveinfo.DevicePort {
	dpc := getCurrentDPC(dinfo)
	if dpc == nil {
		return nil
	}
	for _, port := range dpc.GetPorts() {
		if port.GetName() == portLL {
			return port
		}
	}
	return nil
}

func containsIPv4(ips []net.IP) bool {
	for _, ip := range ips {
		if ip.To4() != nil {
			return true
		}
	}
	return false
}

func containsIPv6(ips []net.IP) bool {
	for _, ip := range ips {
		if ip.To4() == nil {
			return true
		}
	}
	return false
}
