// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test creating, changing, deleting NI. Try to run traffic etc.

package networking_test

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveflowlog "github.com/lf-edge/eve-api/go/flowlog"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	uuid "github.com/satori/go.uuid"
)

// TestLocalNI is the canonical end-to-end exercise of a Local (L3/NAT)
// Network Instance. It covers the full life-cycle of a Local NI -- create,
// update, delete -- and then redeploys it with a connected application to
// verify DHCP, DNS, port-forwarding, ACLs and per-NI metrics.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port plus the SDN DNS
//     server, http-server.test endpoint and a static DNS entry for the
//     controller.
//
// Phases
// ------
//  1. NI create: define a Local NI ("local-ni") on ethernet0 with subnet
//     10.11.12.0/24, DHCP range .2..254, gateway .1, MTU 1500,
//     EnableFlowlog=false, ForwardLLDP=false. Wait for
//     ZNETINST_STATE_ONLINE. Note: we deliberately do NOT bail on
//     transient ERROR (no StopIf(niHasError)) because zedrouter/NIM races
//     can briefly flag NI as errored before settling -- the eventual
//     ONLINE is what matters. Then assert the full ZInfoNetworkInstance
//     payload: NetworkID, Displayname, Activated=true, NetworkErr empty,
//     Ports=["ethernet0"], BridgeIPAddr=10.11.12.1, single IpAssignment
//     for the bridge IP, AssignedAdapters reports ethernet0 with
//     PhyIoNetEth, BridgeName="bn1", BridgeNum=1, InstType=2 (Local),
//     MTU=1500, no VIFs yet, two IpRoutes in deterministic order
//     (default via the eth0 gateway and the connected route for the
//     port subnet).
//  2. NI update: change subnet to 10.11.13.0/24 and re-apply. Wait until
//     BridgeIPAddr flips to 10.11.13.1 and the IpAssignment reflects the
//     new subnet.
//  3. NI delete: assert the state returns to ZNETINST_STATE_UNSPECIFIED.
//  4. NI + app: recreate the NI (subnet 10.11.12.0/24 again, this time
//     EnableFlowlog=true) and deploy a container app
//     (lfedge/evetest-ubuntu-ctr:1.0) with a single
//     VirtualNetworkAdapter on the NI, a fixed MAC 02:16:3e:00:00:01, a
//     port-fwd 2222->22 ACE, and an allow-all ACL. VirtualizationMode=HVM
//     (PV does not work on Xen because the shim VM fails to start there).
//     WaitUntilAppIsRunning, then assert:
//     - app reports one VIF "vif0" with the chosen MAC, exactly one IPv4
//     from the NI subnet, DefaultRouters=[10.11.12.1], no NTP, no
//     network error, Ipv4Up=true, IpAddrMisMatch=false.
//     - NetworkInstanceInfo eventually reports a VIF "nbu1x1" with the
//     same MAC and AppID, plus the IP assignment matching the app's IP.
//  5. Inside-app probes (via RunShellScriptInsideApp using the 2222->22
//     port-fwd + UsernamePasswordAuth root/testpassword):
//     - `hostname` returns the app UUID -- confirms port-forwarding works.
//     - `nslookup <controller-hostname>` resolves to the controller IPv4
//     -- confirms the per-NI dnsmasq is wired up.
//     - `curl -sS http://http-server.test/helloworld` returns
//     "Hello world!" -- confirms outbound app traffic (NAT, ACL allow,
//     external HTTP).
//  6. NI metrics: ZMetricNetworkInstance for the NI eventually has
//     non-zero RX and TX TotalPackets, proving the per-NI dataplane
//     counters track the traffic generated above.
//  7. Flow / DNS log check: flow logging is off by default (it is enabled
//     and exercised in TestFlowLog), so GetAppFlowLogs / GetAppDNSLogs must
//     both return empty for this app's VIF.
//  8. App teardown: delete the app, wait until ZSwState_INVALID, then
//     assert NetworkInstance.Vifs is empty and the bridge-IP assignment
//     persists. Finally delete the NI and wait for UNSPECIFIED.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestApplicationConnectivitySuite (deploys an app, hence
//     hypervisor-parameterized).
func TestLocalNI(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()

	// Set up the test harness and specify the test prerequisites.
	devName := "edge-dev"
	requiredDevice := evetest.RequireEdgeDevice{
		Name:              devName,
		WithHypervisor:    hypervisor,
		DeviceReusePolicy: evetest.ResetDeviceConfig,
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCP,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build and apply the initial device configuration, without including any
	// network instances for now.
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
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	// Try to create local network instance.
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:       evetest.IPAddress("10.11.12.1"),
		EnableFlowlog: false,
		MTU:           1500,
		ForwardLLDP:   false,
	})
	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	device.ApplyConfig(devConfig, false, false)

	timeout := 3 * time.Minute
	var niInfo *eveinfo.ZInfoNetworkInstance
	// Do not stop monitoring the Network Instance state after an error
	// (StopIf(niHasError) is intentionally not used).
	// NI may enter a temporary error condition due to race conditions
	// between zedrouter and NIM, but this is expected to eventually resolve.
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI state is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))

	evetest.Checkpoint("ni-created")

	t.Expect(niInfo.NetworkID).To(Equal(niUUID.String()))
	t.Expect(niInfo.Displayname).To(Equal("local-ni"))
	t.Expect(niInfo.Activated).To(BeTrue())
	t.Expect(niInfo.NetworkErr).To(BeEmpty())
	t.Expect(niInfo.Ports).To(HaveLen(1))
	t.Expect(niInfo.Ports[0]).To(Equal("ethernet0"))
	t.Expect(niInfo.BridgeIPAddr).To(Equal("10.11.12.1"))
	t.Expect(niInfo.IpAssignments).To(HaveLen(1))
	t.Expect(niInfo.IpAssignments[0].IpAddress).To(HaveLen(1))
	t.Expect(niInfo.IpAssignments[0].IpAddress[0]).To(Equal("10.11.12.1"))
	t.Expect(niInfo.AssignedAdapters).To(HaveLen(1))
	t.Expect(niInfo.AssignedAdapters[0].Name).To(Equal("ethernet0"))
	t.Expect(niInfo.AssignedAdapters[0].Type).To(Equal(evecommon.PhyIoType_PhyIoNetEth))
	t.Expect(niInfo.BridgeName).To(Equal("bn1"))
	t.Expect(niInfo.BridgeNum).To(BeEquivalentTo(1))
	t.Expect(niInfo.InstType).To(BeEquivalentTo(2))
	t.Expect(niInfo.Mtu).To(BeEquivalentTo(1500))
	t.Expect(niInfo.Vifs).To(BeEmpty())
	t.Expect(niInfo.IpRoutes).To(HaveLen(2))
	// Routes are returned by EVE in deterministic and therefore easy-to-test order.
	t.Expect(niInfo.IpRoutes[0].DestinationNetwork).To(Equal("0.0.0.0/0"))
	t.Expect(niInfo.IpRoutes[0].Gateway).To(Equal("172.20.20.1"))
	t.Expect(niInfo.IpRoutes[0].Port).To(Equal("ethernet0"))
	t.Expect(niInfo.IpRoutes[1].DestinationNetwork).To(Equal("172.20.20.0/24"))
	t.Expect(niInfo.IpRoutes[1].Gateway).To(Equal(""))
	t.Expect(niInfo.IpRoutes[1].Port).To(Equal("ethernet0"))

	// Try to update network instance - change IP subnet.
	devConfig.UpdateNetworkInstance(niUUID, evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.13.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.13.2"),
			End:   evetest.IPAddress("10.11.13.254"),
		},
		Gateway:       evetest.IPAddress("10.11.13.1"),
		EnableFlowlog: false,
		MTU:           1500,
		ForwardLLDP:   false,
	})
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI bridgeIP is 10.11.13.1",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return info.BridgeIPAddr == "10.11.13.1"
		}).StopIf(niHasError)))

	evetest.Checkpoint("ni-updated")

	t.Expect(niInfo.Activated).To(BeTrue())
	t.Expect(niInfo.NetworkErr).To(BeEmpty())
	t.Expect(niInfo.BridgeIPAddr).To(Equal("10.11.13.1"))
	t.Expect(niInfo.IpAssignments).To(HaveLen(1))
	t.Expect(niInfo.IpAssignments[0].IpAddress).To(HaveLen(1))
	t.Expect(niInfo.IpAssignments[0].IpAddress[0]).To(Equal("10.11.13.1"))

	// Try to delete the network instance.
	devConfig.DeleteNetworkInstance(niUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI state is UNSPECIFIED",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		}).StopIf(niHasError)))
	stopNIWatch()

	evetest.Checkpoint("ni-deleted")

	// Create NI again, this time with an app connected to it.
	subnet := evetest.IPSubnet("10.11.12.0/24")
	niUUID = devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      subnet,
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:       evetest.IPAddress("10.11.12.1"),
		EnableFlowlog: true,
		MTU:           1500,
		ForwardLLDP:   false,
	})

	const appMACAddr = "02:16:3e:00:00:01"
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "container-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM, // PV does not work in xen, shim VM fails to start
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				MAC:                 evetest.MACAddress(appMACAddr),
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
						AppPort:      22,
					},
				},
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	})

	niUpdates, stopNIWatch = device.WatchNetworkInstanceInfo(niUUID)
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	device.ApplyConfig(devConfig, false, false)

	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)

	evetest.Checkpoint("ni-with-app-created")

	// Wait until application receives IP address from the NI subnet.
	var appInfo *eveinfo.ZInfoApp
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App receives IP address",
		func(info *eveinfo.ZInfoApp) bool {
			appInfo = info
			return len(appInfo.Network) == 1 && len(appInfo.Network[0].IPAddrs) == 1
		}).StopIf(appHasError)))
	t.Expect(appInfo.Network).To(HaveLen(1))
	t.Expect(appInfo.Network[0].DevName).To(Equal("vif0"))
	t.Expect(appInfo.Network[0].MacAddr).To(Equal(appMACAddr))
	t.Expect(appInfo.Network[0].IPAddrs).To(HaveLen(1))
	appIP := evetest.IPAddress(appInfo.Network[0].IPAddrs[0])
	t.Expect(subnet.Contains(appIP)).To(BeTrue())
	t.Expect(appInfo.Network[0].DefaultRouters).To(HaveLen(1))
	t.Expect(appInfo.Network[0].DefaultRouters[0]).To(Equal("10.11.12.1"))
	t.Expect(appInfo.Network[0].NtpServers).To(BeEmpty())
	t.Expect(appInfo.Network[0].NetworkErr).To(BeNil())
	t.Expect(appInfo.Network[0].Ipv4Up).To(BeTrue())
	t.Expect(appInfo.Network[0].IpAddrMisMatch).To(BeFalse())

	// Confirm that application IP address is (eventually) reported in the network
	// instance status.
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App IP is reported inside the NI status",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			if len(niInfo.Vifs) == 0 || len(niInfo.IpAssignments) == 0 {
				return false
			}
			for _, ipAssignment := range niInfo.IpAssignments {
				if ipAssignment.MacAddress == appMACAddr {
					return generics.ContainsItem(ipAssignment.IpAddress, appIP.String())
				}
			}
			return false
		}).StopIf(niHasError)))
	t.Expect(niInfo.Vifs).To(HaveLen(1))
	t.Expect(niInfo.Vifs[0].VifName).To(Equal("nbu1x1"))
	t.Expect(niInfo.Vifs[0].MacAddress).To(Equal(appMACAddr))
	t.Expect(niInfo.Vifs[0].AppID).To(Equal(appUUID.String()))

	niMetricsUpdates, stopNIMetricsWatch := device.WatchNetworkInstanceMetrics(niUUID)

	// Test port forwarding.
	// RunShellScriptInsideApp will try to use the 2222->22 port forwarding rule.
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second
	log := evetest.Logger()
	log.Infof("Testing port forwarding")
	t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app SSH daemon to start and become reachable...")
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"hostname", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring(appUUID.String()))
	}, timeout, polling).Should(Succeed())

	// Test DNS provided by the Local NI.
	log.Infof("Testing DNS resolution from inside the application")
	output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"nslookup "+evetest.GetControllerHostname(), sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring(evetest.GetControllerIPv4().String()))

	// Test application connectivity initiated from inside the application.
	log.Infof("Testing application connectivity")
	output, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS http://http-server.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring("Hello world!"))

	// Check that NI metrics recorded the traffic that was created.
	t.Eventually(niMetricsUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI metrics have non-zero RX and TX packet counters",
		func(metrics *evemetrics.ZMetricNetworkInstance) bool {
			return metrics.GetNetworkStats().GetRx().GetTotalPackets() != 0 &&
				metrics.GetNetworkStats().GetTx().GetTotalPackets() != 0
		})))
	stopNIMetricsWatch()

	// Flowlog is disabled by default (it is enabled and tested in TestFlowLog).
	t.Expect(device.GetAppFlowLogs(appUUID, evetest.FlowLogMatch{
		VirtualNetAdapter: "vif0",
		NetworkInstance:   niUUID,
	})).To(BeEmpty())
	t.Expect(device.GetAppDNSLogs(appUUID, evetest.DNSLogMatch{
		VirtualNetAdapter: "vif0",
		NetworkInstance:   niUUID,
	})).To(BeEmpty())

	// Undeploy app and check that VIF was disconnected from the network instance.
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App state is UNSPECIFIED",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))
	stopAppWatch()

	evetest.Checkpoint("app-deleted")

	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI has no VIFs attached",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return len(niInfo.Vifs) == 0
		}).StopIf(niHasError)))

	t.Expect(niInfo.IpAssignments).To(HaveLen(1))
	t.Expect(niInfo.IpAssignments[0].IpAddress).To(HaveLen(1))
	t.Expect(niInfo.IpAssignments[0].IpAddress[0]).To(Equal("10.11.12.1"))

	// Delete the network instance in the end.
	devConfig.DeleteNetworkInstance(niUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI state is UNSPECIFIED",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		}).StopIf(niHasError)))
	stopNIWatch()
}

// TestSwitchNI is the canonical end-to-end exercise of a Switch (L2-only)
// Network Instance. It covers the full Switch NI life-cycle and then
// redeploys with a connected app whose IP is learned by EVE via packet
// snooping (no internal DHCP server runs for switch NIs).
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port. The SDN-side DHCP
//     server / DNS / http-server.test are part of the same L2 segment that
//     the switch NI bridges into.
//
// Phases
// ------
//  1. NI create: define a Switch NI ("switch-ni") on ethernet0 with
//     EnableFlowlog=false, MTU=1500, ForwardLLDP=false. Wait for
//     ZNETINST_STATE_ONLINE (transient errors are tolerated, same race
//     reasoning as in TestLocalNI). Assert: Activated=true, NetworkErr
//     empty, Ports=["ethernet0"], BridgeIPAddr empty (Switch NI does not
//     hold an IP), IpAssignments empty, AssignedAdapters reports
//     ethernet0/PhyIoNetEth, BridgeName="eth0" (switch NI's bridge takes
//     the port's name), InstType=1 (Switch), MTU=1500, no VIFs, no
//     IpRoutes.
//  2. NI update: turn the NI air-gap (Port="") and bump MTU to 2000. Wait
//     until Ports is empty and BridgeName no longer matches "eth0".
//     Assert AssignedAdapters empty, BridgeName becomes a synthetic "bn1"
//     bridge, MTU=2000.
//  3. NI delete: state returns to ZNETINST_STATE_UNSPECIFIED.
//  4. NI + app: recreate the NI on ethernet0 and deploy a container app
//     (lfedge/evetest-ubuntu-ctr:1.0) with one VirtualNetworkAdapter
//     on the NI, fixed MAC 02:16:3e:00:00:01, allow-all ACL.
//     VirtualizationMode=HVM (same Xen-PV caveat as TestLocalNI).
//     WaitUntilAppIsRunning, then assert:
//     - app reports one VIF "vif0" with the chosen MAC and exactly one
//     global-unicast IPv4 from the eth0 SDN subnet (172.20.20.0/24).
//     Switch NIs learn the app's IP by capturing DHCPACK / ARP traffic
//     (no internal DHCP), see APP-CONNECTIVITY.md "IP address
//     detection".
//     - DefaultRouters has one entry. (Asserting the exact gateway IP is
//     left out -- see the TODO inline: a known EVE bug currently reports
//     "nil" instead of "172.20.20.1".)
//     - NetworkInstance.Vifs eventually contains the matching VIF
//     "nbu1x1" plus the IP assignment for the app's MAC.
//  5. Inside-app probes (via RunShellScriptInsideApp -- the framework
//     auto-discovers an SSH endpoint on the switch-NI VIF IP):
//     - `ip addr` shows the app's IP with /24 -- proves the app boots
//     with the expected L2 reachability.
//     - `nslookup <controller-hostname>` resolves to the controller IPv4
//     -- DNS path goes via the external SDN DNS server (no per-NI
//     dnsmasq on Switch NI).
//     - `curl -sS http://http-server.test/helloworld` returns "Hello
//     world!" -- proves L2 forwarding through the switch NI plus
//     external HTTP reachability.
//  6. NI metrics: ZMetricNetworkInstance for the NI eventually has
//     non-zero RX/TX TotalPackets.
//  7. Flow / DNS log assertions are commented out for the same reason as
//     in TestLocalNI.
//  8. App teardown: delete the app, wait for ZSwState_INVALID, assert
//     NetworkInstance.Vifs and IpAssignments are empty, then delete the
//     NI.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestApplicationConnectivitySuite.
func TestSwitchNI(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()

	// Set up the test harness and specify the test prerequisites.
	devName := "edge-dev"
	requiredDevice := evetest.RequireEdgeDevice{
		Name:              devName,
		WithHypervisor:    hypervisor,
		DeviceReusePolicy: evetest.ResetDeviceConfig,
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCP,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build and apply the initial device configuration, without including any
	// network instances for now.
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
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	// Try to create switch network instance.
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName:   "switch-ni",
		Port:          "ethernet0",
		EnableFlowlog: false,
		MTU:           1500,
		ForwardLLDP:   false,
	})
	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	device.ApplyConfig(devConfig, false, false)

	timeout := 3 * time.Minute
	var niInfo *eveinfo.ZInfoNetworkInstance
	// Do not stop monitoring the Network Instance state after an error
	// (StopIf(niHasError) is intentionally not used).
	// NI may enter a temporary error condition due to race conditions
	// between zedrouter and NIM, but this is expected to eventually resolve.
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI state is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))

	evetest.Checkpoint("ni-created")

	t.Expect(niInfo.NetworkID).To(Equal(niUUID.String()))
	t.Expect(niInfo.Displayname).To(Equal("switch-ni"))
	t.Expect(niInfo.Activated).To(BeTrue())
	t.Expect(niInfo.NetworkErr).To(BeEmpty())
	t.Expect(niInfo.Ports).To(HaveLen(1))
	t.Expect(niInfo.Ports[0]).To(Equal("ethernet0"))
	t.Expect(niInfo.BridgeIPAddr).To(BeEmpty())
	t.Expect(niInfo.IpAssignments).To(BeEmpty())
	t.Expect(niInfo.AssignedAdapters).To(HaveLen(1))
	t.Expect(niInfo.AssignedAdapters[0].Name).To(Equal("ethernet0"))
	t.Expect(niInfo.AssignedAdapters[0].Type).To(Equal(evecommon.PhyIoType_PhyIoNetEth))
	t.Expect(niInfo.BridgeName).To(Equal("eth0"))
	t.Expect(niInfo.BridgeNum).To(BeEquivalentTo(1))
	t.Expect(niInfo.InstType).To(BeEquivalentTo(1))
	t.Expect(niInfo.Mtu).To(BeEquivalentTo(1500))
	t.Expect(niInfo.Vifs).To(BeEmpty())
	t.Expect(niInfo.IpRoutes).To(BeEmpty())

	// Try to update network instance - make it air-gaped and increase MTU.
	devConfig.UpdateNetworkInstance(niUUID, evetest.SwitchNetworkInstanceConfig{
		DisplayName:   "switch-ni",
		Port:          "",
		EnableFlowlog: false,
		MTU:           2000,
		ForwardLLDP:   false,
	})

	device.ApplyConfig(devConfig, false, false)

	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI has no ports assigned",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return len(info.Ports) == 0 && info.BridgeName != "eth0"
		}).StopIf(niHasError)))

	evetest.Checkpoint("ni-updated")

	t.Expect(niInfo.Activated).To(BeTrue())
	t.Expect(niInfo.NetworkErr).To(BeEmpty())
	t.Expect(niInfo.AssignedAdapters).To(BeEmpty())
	t.Expect(niInfo.BridgeName).To(Equal("bn1"))
	t.Expect(niInfo.BridgeNum).To(BeEquivalentTo(1))
	t.Expect(niInfo.Mtu).To(BeEquivalentTo(2000))

	// Try to delete the network instance.
	devConfig.DeleteNetworkInstance(niUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI state is UNSPECIFIED",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		}).StopIf(niHasError)))
	stopNIWatch()

	evetest.Checkpoint("ni-deleted")

	// Create NI again, this time with an app connected to it.
	niUUID = devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName:   "switch-ni",
		Port:          "ethernet0",
		EnableFlowlog: false,
		MTU:           1500,
		ForwardLLDP:   false,
	})

	const appMACAddr = "02:16:3e:00:00:01"
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "container-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM, // PV does not work in xen, shim VM fails to start
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				MAC:                 evetest.MACAddress(appMACAddr),
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	})

	niUpdates, stopNIWatch = device.WatchNetworkInstanceInfo(niUUID)
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	device.ApplyConfig(devConfig, false, false)

	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)

	evetest.Checkpoint("ni-with-app-created")

	// Wait until application receives IP address from the eth0 subnet
	// (see netmodels.SingleEthWithDHCP).
	var appIPs []net.IP
	var appInfo *eveinfo.ZInfoApp
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App receives IP address",
		func(info *eveinfo.ZInfoApp) bool {
			appInfo = info
			if len(appInfo.Network) == 0 {
				return false
			}
			for _, ipAddr := range appInfo.Network[0].IPAddrs {
				// Ignore link-local (IPv6) addresses.
				appIP := evetest.IPAddress(ipAddr)
				if appIP.IsGlobalUnicast() {
					appIPs = append(appIPs, appIP)
				}
			}
			return len(appIPs) > 0
		}).StopIf(appHasError)))
	t.Expect(appInfo.Network).To(HaveLen(1))
	t.Expect(appInfo.Network[0].DevName).To(Equal("vif0"))
	t.Expect(appInfo.Network[0].MacAddr).To(Equal(appMACAddr))
	t.Expect(appIPs).To(HaveLen(1))
	appIP := appIPs[0]
	subnet := evetest.IPSubnet("172.20.20.0/24")
	t.Expect(subnet.Contains(appIP)).To(BeTrue())
	t.Expect(appInfo.Network[0].DefaultRouters).To(HaveLen(1))
	// TODO: we need to fix this in EVE ("nil" is returned instead)
	// t.Expect(appInfo.Network[0].DefaultRouters[0]).To(Equal("172.20.20.1"))
	t.Expect(appInfo.Network[0].NtpServers).To(BeEmpty())
	t.Expect(appInfo.Network[0].NetworkErr).To(BeNil())
	t.Expect(appInfo.Network[0].Ipv4Up).To(BeTrue())
	t.Expect(appInfo.Network[0].IpAddrMisMatch).To(BeFalse())

	// Confirm that application IP address is (eventually) reported in the network
	// instance status.
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App IP is reported inside the NI status",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			if len(niInfo.Vifs) == 0 || len(niInfo.IpAssignments) == 0 {
				return false
			}
			for _, ipAssignment := range niInfo.IpAssignments {
				if ipAssignment.MacAddress == appMACAddr {
					return generics.ContainsItem(ipAssignment.IpAddress, appIP.String())
				}
			}
			return false
		}).StopIf(niHasError)))
	t.Expect(niInfo.Vifs).To(HaveLen(1))
	t.Expect(niInfo.Vifs[0].VifName).To(Equal("nbu1x1"))
	t.Expect(niInfo.Vifs[0].MacAddress).To(Equal(appMACAddr))
	t.Expect(niInfo.Vifs[0].AppID).To(Equal(appUUID.String()))

	niMetrics, stopNIMetricsWatch := device.WatchNetworkInstanceMetrics(niUUID)

	// Test that application is accessible from outside.
	// RunShellCommandFromApp will try to access <vifIP>:22
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second
	log := evetest.Logger()
	log.Infof("Testing application accessibility from outside.")
	t.Eventually(func(t Gomega) {
		log.Infof("Waiting for app SSH daemon to start and become reachable...")
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"ip addr", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring(appIPs[0].String() + "/24"))
	}, timeout, polling).Should(Succeed())

	// Test DNS provided by the external network (running inside SDN).
	log.Infof("Testing DNS resolution from inside the application")
	output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"nslookup "+evetest.GetControllerHostname(), sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring(evetest.GetControllerIPv4().String()))

	// Test application connectivity initiated from inside the application.
	log.Infof("Testing application connectivity")
	output, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS http://http-server.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring("Hello world!"))

	// Check that NI metrics recorded the traffic that was created.
	t.Eventually(niMetrics, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI metrics have non-zero RX and TX packet counters",
		func(metrics *evemetrics.ZMetricNetworkInstance) bool {
			return metrics.GetNetworkStats().GetRx().GetTotalPackets() != 0 &&
				metrics.GetNetworkStats().GetTx().GetTotalPackets() != 0
		})))
	stopNIMetricsWatch()

	// Flowlog is disabled by default (it is enabled and tested in TestFlowLog).
	t.Expect(device.GetAppFlowLogs(appUUID, evetest.FlowLogMatch{
		VirtualNetAdapter: "vif0",
		NetworkInstance:   niUUID,
	})).To(BeEmpty())
	t.Expect(device.GetAppDNSLogs(appUUID, evetest.DNSLogMatch{
		VirtualNetAdapter: "vif0",
		NetworkInstance:   niUUID,
	})).To(BeEmpty())

	// Undeploy app and check that VIF was disconnected from the network instance.
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App state is UNSPECIFIED",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))
	stopAppWatch()

	evetest.Checkpoint("app-deleted")

	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI has no VIFs attached",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return len(niInfo.Vifs) == 0 && len(niInfo.IpAssignments) == 0
		}).StopIf(niHasError)))

	// Delete the network instance in the end.
	devConfig.DeleteNetworkInstance(niUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI state is UNSPECIFIED",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		}).StopIf(niHasError)))
	stopNIWatch()
}

// TestNIReplace verifies that EVE correctly handles Network Instances being
// rapidly replaced -- deleted and recreated (possibly reusing the same
// subnet, or splitting/merging across a different number of NIs) -- all
// within a single config apply. This exercises internal number/resource
// reuse (bridge number, IPAM state, iptables chains, etc.) inside zedrouter,
// which could otherwise conflict if stale state from the deleted NI is not
// fully torn down before the replacement comes up.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port; no application is
//     deployed, only Local Network Instances are created/replaced.
//
// Phases
// ------
//  1. Create n1 (Local NI, subnet 10.11.12.0/24). Wait for ONLINE.
//  2. Replace n1 with n2 using a *different* subnet (10.11.13.0/24), deleting
//     n1 and adding n2 in one config apply. Wait for n1 -> UNSPECIFIED and
//     n2 -> ONLINE with the new subnet's bridge IP.
//  3. Replace n2 with n3, reusing the *same* subnet (10.11.13.0/24) that n2
//     just released, again in one apply. Wait for n2 -> UNSPECIFIED and
//     n3 -> ONLINE with BridgeIPAddr unchanged (10.11.13.1), proving the
//     just-freed subnet can be immediately reused by a different NI.
//  4. Replace one NI (n3) with two NIs in one apply: n4 (reusing the
//     10.11.12.0/24 subnet that has been free since step 2) and n5 (a fresh
//     subnet). Both come up ONLINE while n3 goes UNSPECIFIED.
//  5. Move the subnet used by n4 to a new one (10.11.14.0/24) and, in the very
//     same apply, add n6 that takes over n4's *former* subnet
//     (10.11.12.0/24). Wait for n6 -> ONLINE with the taken-over subnet's
//     bridge IP and for n4 to keep running with its new bridge IP..
//  6. Cleanup: delete n4, n5 and n6, and wait for all three to report
//     ZNETINST_STATE_UNSPECIFIED.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestApplicationConnectivitySuite.
func TestNIReplace(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

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
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	// localNI builds a Local NI config for a /24 subnet whose gateway is the
	// ".1" address; the DHCP range spans the rest of the subnet (.2-.254).
	localNI := func(displayName, subnetPrefix string) evetest.LocalNetworkInstanceConfig {
		return evetest.LocalNetworkInstanceConfig{
			DisplayName: displayName,
			Port:        "ethernet0",
			Subnet:      evetest.IPSubnet(subnetPrefix + ".0/24"),
			DHCPRange: types.IPRange{
				Start: evetest.IPAddress(subnetPrefix + ".2"),
				End:   evetest.IPAddress(subnetPrefix + ".254"),
			},
			Gateway: evetest.IPAddress(subnetPrefix + ".1"),
			MTU:     1500,
		}
	}

	timeout := 3 * time.Minute
	waitOnline := func(niUUID uuid.UUID, updates <-chan *eveinfo.ZInfoNetworkInstance,
		expectBridgeIP string) *eveinfo.ZInfoNetworkInstance {
		var niInfo *eveinfo.ZInfoNetworkInstance
		t.Eventually(updates, timeout).Should(Receive(matchers.SatisfyPredicate(
			fmt.Sprintf("NI %s is ONLINE with bridge IP %s", niUUID, expectBridgeIP),
			func(info *eveinfo.ZInfoNetworkInstance) bool {
				niInfo = info
				return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE &&
					info.BridgeIPAddr == expectBridgeIP
			})))
		t.Expect(niInfo.NetworkID).To(Equal(niUUID.String()))
		t.Expect(niInfo.NetworkErr).To(BeEmpty())
		return niInfo
	}
	waitGone := func(updates <-chan *eveinfo.ZInfoNetworkInstance) {
		t.Eventually(updates, timeout).Should(Receive(matchers.SatisfyPredicate(
			"NI state is UNSPECIFIED",
			func(info *eveinfo.ZInfoNetworkInstance) bool {
				return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
			}).StopIf(niHasError)))
	}

	// Step 1: create n1.
	n1UUID := devConfig.AddNetworkInstance(localNI("n1", "10.11.12"))
	n1Updates, stopN1Watch := device.WatchNetworkInstanceInfo(n1UUID)
	device.ApplyConfig(devConfig, false, false)
	waitOnline(n1UUID, n1Updates, "10.11.12.1")
	evetest.Checkpoint("n1-created")

	// Step 2: replace n1 with n2, using a different subnet, in a single apply.
	devConfig.DeleteNetworkInstance(n1UUID)
	n2UUID := devConfig.AddNetworkInstance(localNI("n2", "10.11.13"))
	n2Updates, stopN2Watch := device.WatchNetworkInstanceInfo(n2UUID)
	device.ApplyConfig(devConfig, false, false)
	waitGone(n1Updates)
	stopN1Watch()
	waitOnline(n2UUID, n2Updates, "10.11.13.1")
	evetest.Checkpoint("n1-replaced-by-n2")

	// Step 3: replace n2 with n3, reusing the exact same subnet n2 just released.
	devConfig.DeleteNetworkInstance(n2UUID)
	n3UUID := devConfig.AddNetworkInstance(localNI("n3", "10.11.13"))
	n3Updates, stopN3Watch := device.WatchNetworkInstanceInfo(n3UUID)
	device.ApplyConfig(devConfig, false, false)
	waitGone(n2Updates)
	stopN2Watch()
	waitOnline(n3UUID, n3Updates, "10.11.13.1")
	evetest.Checkpoint("n2-replaced-by-n3")

	// Step 4: replace n3 with two NIs -- n4 (reusing the 10.11.12.0/24 subnet
	// that has been free since step 2) and n5 (a brand new subnet).
	devConfig.DeleteNetworkInstance(n3UUID)
	n4UUID := devConfig.AddNetworkInstance(localNI("n4", "10.11.12"))
	n5UUID := devConfig.AddNetworkInstance(localNI("n5", "10.11.15"))
	n4Updates, stopN4Watch := device.WatchNetworkInstanceInfo(n4UUID)
	n5Updates, stopN5Watch := device.WatchNetworkInstanceInfo(n5UUID)
	device.ApplyConfig(devConfig, false, false)
	waitGone(n3Updates)
	stopN3Watch()
	waitOnline(n4UUID, n4Updates, "10.11.12.1")
	waitOnline(n5UUID, n5Updates, "10.11.15.1")
	evetest.Checkpoint("n3-replaced-by-n4-and-n5")

	// Step 5: move n4's subnet elsewhere and let n6 take over the subnet that
	// n4 just vacated -- both changes submitted in the very same apply.
	devConfig.UpdateNetworkInstance(n4UUID, localNI("n4", "10.11.14"))
	n6UUID := devConfig.AddNetworkInstance(localNI("n6", "10.11.12"))
	n6Updates, stopN6Watch := device.WatchNetworkInstanceInfo(n6UUID)
	device.ApplyConfig(devConfig, false, false)
	waitOnline(n4UUID, n4Updates, "10.11.14.1")
	waitOnline(n6UUID, n6Updates, "10.11.12.1")
	evetest.Checkpoint("n4-subnet-moved-to-n6")

	// Cleanup.
	devConfig.DeleteNetworkInstance(n4UUID)
	devConfig.DeleteNetworkInstance(n5UUID)
	devConfig.DeleteNetworkInstance(n6UUID)
	device.ApplyConfig(devConfig, false, false)
	waitGone(n4Updates)
	waitGone(n5Updates)
	waitGone(n6Updates)
	stopN4Watch()
	stopN5Watch()
	stopN6Watch()
}

// TestMoveAppBetweenNIs verifies that moving an application's network
// adapter from one Network Instance to another (i.e. changing which NI a
// VIF is attached to, within an otherwise-unchanged app config) takes
// effect at runtime: the app is redeployed onto the new NI, gets a fresh IP
// from its subnet, loses connectivity with peers on the NI it left, and
// gains connectivity with peers on the NI it joined.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- a single mgmt+app port (ethernet0),
//     shared as the uplink by both Local NIs below (a port can back more
//     than one Local NI at once).
//
// Phases
// ------
//  1. Create two Local NIs on ethernet0: "n1" (10.11.12.0/24) and "n2"
//     (10.11.13.0/24). Wait for both ONLINE.
//  2. Deploy three container apps (lfedge/evetest-ubuntu-ctr:1.0,
//     VirtualizationMode=HVM): "ping1" on n1 (port-fwd 2223->22, ICMP
//     allow-all ACL), "ping2" on n2 (port-fwd 2224->22, ICMP allow-all ACL)
//     and "pong" on n1 (ICMP allow-all ACL, no port-fwd -- nothing ever SSHes
//     into it). WaitUntilAppIsRunning for all three, then read pong's NI IP
//     from its ZInfoApp.
//  3. Same-NI reachability: from ping1 (on n1, same NI as pong), `ping -c 3
//     -W 1 <pong-IP>` succeeds. From ping2 (on n2), the same ping fails --
//     pong's private /24 is not reachable from a different, NAT-isolated
//     Local NI.
//  4. Move pong from n1 to n2: UpdateApplication with pong's
//     VirtualNetworkAdapter now pointing at n2's UUID (same MAC, same ACL).
//     Changing the NI reference changes the app's Interfaces, so EVE purges
//     and redeploys pong. WaitUntilAppIsRunning again, then read pong's new
//     (n2-subnet) IP.
//  5. Switched reachability: ping2 can now reach pong; ping1 can no longer
//     reach it (mirrors step 3, with the roles of ping1/ping2 reversed).
//  6. Move pong back to n1 and repeat the step-3 assertions, confirming the
//     switch is fully reversible.
//  7. Cleanup: delete all three apps and both NIs, waiting for each to be
//     gone.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestApplicationConnectivitySuite.
func TestMoveAppBetweenNIs(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

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
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	n1UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "n1",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
		MTU:     1500,
	})
	n2UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "n2",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.13.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.13.2"),
			End:   evetest.IPAddress("10.11.13.254"),
		},
		Gateway: evetest.IPAddress("10.11.13.1"),
		MTU:     1500,
	})

	n1Updates, stopN1Watch := device.WatchNetworkInstanceInfo(n1UUID)
	n2Updates, stopN2Watch := device.WatchNetworkInstanceInfo(n2UUID)
	device.ApplyConfig(devConfig, false, false)

	timeout := 3 * time.Minute
	t.Eventually(n1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"n1 is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))
	t.Eventually(n2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"n2 is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))
	evetest.Checkpoint("nis-created")

	icmpAllowAny := []evetest.ACLAllowRule{
		{
			Protocol:     evetest.NetworkProtocolICMP,
			RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
		},
	}
	const (
		ping1MAC = "02:16:3e:00:00:01"
		ping2MAC = "02:16:3e:00:00:02"
		pongMAC  = "02:16:3e:00:00:03"
	)
	newApp := func(displayName string, niUUID uuid.UUID, mac string,
		portFwd []evetest.PortFwdRule) evetest.ApplicationInstanceConfig {
		return evetest.ApplicationInstanceConfig{
			DisplayName: displayName,
			Activate:    true,
			Image: evetest.DockerContainer{
				ImageName: "lfedge/evetest-ubuntu-ctr",
				Tag:       "1.0",
			},
			VirtualizationMode: eveconfig.VmMode_HVM,
			CPUs:               1,
			MemoryBytes:        500 * evetest.MiB,
			NetworkAdapters: []evetest.AppNetworkAdapter{
				evetest.VirtualNetworkAdapter{
					LogicalLabel:        "vif0",
					NetworkInstanceUUID: niUUID,
					MAC:                 evetest.MACAddress(mac),
					PortFwdRules:        portFwd,
					ACLAllowRules:       icmpAllowAny,
				},
			},
		}
	}
	ping1UUID := devConfig.AddApplication(newApp("ping1", n1UUID, ping1MAC,
		[]evetest.PortFwdRule{{Protocol: evetest.NetworkProtocolTCP, EdgeNodePort: 2223, AppPort: 22}}))
	ping2UUID := devConfig.AddApplication(newApp("ping2", n2UUID, ping2MAC,
		[]evetest.PortFwdRule{{Protocol: evetest.NetworkProtocolTCP, EdgeNodePort: 2224, AppPort: 22}}))
	pongUUID := devConfig.AddApplication(newApp("pong", n1UUID, pongMAC, nil))

	ping1Updates, stopPing1Watch := device.WatchAppInfo(ping1UUID)
	ping2Updates, stopPing2Watch := device.WatchAppInfo(ping2UUID)
	pongUpdates, stopPongWatch := device.WatchAppInfo(pongUUID)
	device.ApplyConfig(devConfig, false, false)

	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(ping1UUID, timeoutExcludingDownload)
	device.WaitUntilAppIsRunning(ping2UUID, timeoutExcludingDownload)
	device.WaitUntilAppIsRunning(pongUUID, timeoutExcludingDownload)
	evetest.Checkpoint("apps-running")

	// getVifIPInSubnet drains updates until the app reports a VIF IP address
	// that belongs to the given subnet. Requiring subnet membership (rather
	// than accepting any IP) makes this robust against a stale, previously
	// drained IP (from before an NI move) still sitting in the channel.
	getVifIPInSubnet := func(updates <-chan *eveinfo.ZInfoApp, subnet *net.IPNet) string {
		var ip string
		t.Eventually(updates, timeout).Should(Receive(matchers.SatisfyPredicate(
			fmt.Sprintf("App has a VIF IP address from %s", subnet),
			func(info *eveinfo.ZInfoApp) bool {
				if len(info.Network) == 0 {
					return false
				}
				for _, addr := range info.Network[0].IPAddrs {
					if subnet.Contains(evetest.IPAddress(addr)) {
						ip = addr
						return true
					}
				}
				return false
			}).StopIf(appHasError)))
		return ip
	}
	n1Subnet := evetest.IPSubnet("10.11.12.0/24")
	n2Subnet := evetest.IPSubnet("10.11.13.0/24")
	pongIP := getVifIPInSubnet(pongUpdates, n1Subnet)

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second
	log := evetest.Logger()

	waitSSHReady := func(appUUID uuid.UUID) {
		t.Eventually(func(t Gomega) {
			log.Infof("Waiting for app %s SSH daemon to become reachable...", appUUID)
			_, _, err := device.RunShellScriptInsideApp(
				appUUID, appAuth, "hostname", sshTimeout, 0)
			t.Expect(err).ToNot(HaveOccurred())
		}, timeout, polling).Should(Succeed())
	}
	waitSSHReady(ping1UUID)
	waitSSHReady(ping2UUID)

	pingFrom := func(appUUID uuid.UUID, targetIP string) error {
		_, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			fmt.Sprintf("ping -c 3 -W 1 %s", targetIP), sshTimeout, 0)
		return err
	}

	// Phase 1: pong is on n1, same as ping1.
	log.Infof("Testing connectivity before the move: pong is on n1 (with ping1)")
	t.Expect(pingFrom(ping1UUID, pongIP)).ToNot(HaveOccurred())
	t.Expect(pingFrom(ping2UUID, pongIP)).To(HaveOccurred())
	evetest.Checkpoint("pong-on-n1-verified")

	// Move pong from n1 to n2.
	devConfig.UpdateApplication(pongUUID, newApp("pong", n2UUID, pongMAC, nil))
	device.ApplyConfig(devConfig, false, false)
	pongIP = getVifIPInSubnet(pongUpdates, n2Subnet)
	evetest.Checkpoint("pong-moved-to-n2")

	// Phase 2: pong is now on n2, same as ping2.
	log.Infof("Testing connectivity after the move: pong is on n2 (with ping2)")
	t.Expect(pingFrom(ping2UUID, pongIP)).ToNot(HaveOccurred())
	t.Expect(pingFrom(ping1UUID, pongIP)).To(HaveOccurred())
	evetest.Checkpoint("pong-on-n2-verified")

	// Move pong back from n2 to n1.
	devConfig.UpdateApplication(pongUUID, newApp("pong", n1UUID, pongMAC, nil))
	device.ApplyConfig(devConfig, false, false)
	pongIP = getVifIPInSubnet(pongUpdates, n1Subnet)
	evetest.Checkpoint("pong-moved-back-to-n1")

	// Phase 3: pong is back on n1.
	log.Infof("Testing connectivity after moving back: pong is on n1 again")
	t.Expect(pingFrom(ping1UUID, pongIP)).ToNot(HaveOccurred())
	t.Expect(pingFrom(ping2UUID, pongIP)).To(HaveOccurred())

	// Cleanup.
	devConfig.DeleteApplication(ping1UUID)
	devConfig.DeleteApplication(ping2UUID)
	devConfig.DeleteApplication(pongUUID)
	devConfig.DeleteNetworkInstance(n1UUID)
	devConfig.DeleteNetworkInstance(n2UUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(ping1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"ping1 is gone", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
	t.Eventually(ping2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"ping2 is gone", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
	t.Eventually(pongUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"pong is gone", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
	stopPing1Watch()
	stopPing2Watch()
	stopPongWatch()

	t.Eventually(n1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"n1 is gone", func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		}).StopIf(niHasError)))
	t.Eventually(n2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"n2 is gone", func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		}).StopIf(niHasError)))
	stopN1Watch()
	stopN2Watch()
}

// TestPortForwarding exercises port-forwarding (D-NAT) rules of a Local
// Network Instance: hairpin connectivity between two apps reached through
// the edge node's *external* port-forwarded address (rather than directly
// via their NI-internal IPs), across both a shared uplink and two different
// uplink adapters, plus changing a port-forwarding rule's external port at
// runtime.
//
// Network model
// -------------
//   - netmodels.TwoMgmtPorts -- two independent mgmt+app ports (ethernet0,
//     ethernet1), each with its own DHCP subnet and its own external IP.
//     Needed for the cross-adapter hairpin scenario below; the same-adapter
//     scenarios simply ignore ethernet1's NI.
//
// Phases
// ------
//  1. Create two Local NIs: "ni1" on ethernet0 (10.11.12.0/24) and "ni2" on
//     ethernet1 (10.11.13.0/24). Wait for both ONLINE.
//  2. Deploy three container apps (lfedge/evetest-ubuntu-ctr:1.0,
//     VirtualizationMode=HVM, allow-all ACL on every VIF): "app1" and "app2"
//     on ni1 (port-fwd 2223->22 and 2224->22, respectively) and "app3" on
//     ni2 (port-fwd 2226->22). WaitUntilAppIsRunning for all three.
//  3. Same-adapter hairpin: from app1 (reached via its own port-fwd),
//     open a raw TCP connection to <ethernet0-IP>:2224 -- app2's port-fwd
//     address -- and read app2's sshd banner. Repeat in the opposite
//     direction (app2 -> app1's port-fwd). Both must succeed, proving hairpin
//     NAT works when the initiator and the target share both the NI and
//     the uplink adapter.
//  4. Runtime port-fwd rule change: change app1's port-fwd rule from 2223->22
//     to 2225->22 via UpdateApplication (which purges/redeploys app1).
//     After WaitUntilAppIsRunning:
//     - the old external port (2223) must no longer forward (probed from
//     app2: raw TCP connect times out / errors);
//     - the new external port (2225) must forward to app1 (probed from
//     app2: app1's sshd banner is read back);
//     - RunShellScriptInsideApp(app1, ...) -- which re-derives the SSH
//     endpoint from the *current* device config -- keeps working
//     transparently through the port change.
//     Then the rule is switched back to 2223->22 and the same two-sided
//     check (old port dead, new/original port alive) is repeated, proving
//     the change is fully reversible.
//  5. Cross-adapter hairpin: from app1 (on ni1/ethernet0), open a raw TCP
//     connection to <ethernet1-IP>:2226 -- app3's port-fwd address on the
//     *other* uplink adapter -- and read app3's sshd banner. This proves
//     D-NAT is applied correctly per-adapter (the two uplinks have different
//     external IPs) even when initiator and target sit on different Network
//     Instances bound to different ports.
//  6. Cleanup: delete all three apps and both NIs.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestApplicationConnectivitySuite.
func TestPortForwarding(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.TwoMgmtPorts,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4Only})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	ni1UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "ni1",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
		MTU:     1500,
	})
	ni2UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "ni2",
		Port:        "ethernet1",
		Subnet:      evetest.IPSubnet("10.11.13.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.13.2"),
			End:   evetest.IPAddress("10.11.13.254"),
		},
		Gateway: evetest.IPAddress("10.11.13.1"),
		MTU:     1500,
	})
	ni1Updates, stopNI1Watch := device.WatchNetworkInstanceInfo(ni1UUID)
	ni2Updates, stopNI2Watch := device.WatchNetworkInstanceInfo(ni2UUID)
	device.ApplyConfig(devConfig, false, false)

	timeout := 3 * time.Minute
	t.Eventually(ni1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"ni1 is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))
	t.Eventually(ni2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"ni2 is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))
	evetest.Checkpoint("nis-created")

	allowAll := []evetest.ACLAllowRule{
		{
			Protocol:     evetest.NetworkProtocolAny,
			RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
		},
	}
	newPortFwdApp := func(displayName string, niUUID uuid.UUID, mac string,
		edgeNodePort uint16) evetest.ApplicationInstanceConfig {
		return evetest.ApplicationInstanceConfig{
			DisplayName: displayName,
			Activate:    true,
			Image: evetest.DockerContainer{
				ImageName: "lfedge/evetest-ubuntu-ctr",
				Tag:       "1.0",
			},
			VirtualizationMode: eveconfig.VmMode_HVM,
			CPUs:               1,
			MemoryBytes:        500 * evetest.MiB,
			NetworkAdapters: []evetest.AppNetworkAdapter{
				evetest.VirtualNetworkAdapter{
					LogicalLabel:        "vif0",
					NetworkInstanceUUID: niUUID,
					MAC:                 evetest.MACAddress(mac),
					PortFwdRules: []evetest.PortFwdRule{
						{
							Protocol:     evetest.NetworkProtocolTCP,
							EdgeNodePort: edgeNodePort,
							AppPort:      22,
						},
					},
					ACLAllowRules: allowAll,
				},
			},
		}
	}
	const (
		app1MAC = "02:16:3e:00:01:01"
		app2MAC = "02:16:3e:00:01:02"
		app3MAC = "02:16:3e:00:01:03"
	)
	app1UUID := devConfig.AddApplication(newPortFwdApp("app1", ni1UUID, app1MAC, 2223))
	app2UUID := devConfig.AddApplication(newPortFwdApp("app2", ni1UUID, app2MAC, 2224))
	app3UUID := devConfig.AddApplication(newPortFwdApp("app3", ni2UUID, app3MAC, 2226))

	app1Updates, stopApp1Watch := device.WatchAppInfo(app1UUID)
	app2Updates, stopApp2Watch := device.WatchAppInfo(app2UUID)
	app3Updates, stopApp3Watch := device.WatchAppInfo(app3UUID)
	device.ApplyConfig(devConfig, false, false)

	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(app1UUID, timeoutExcludingDownload)
	device.WaitUntilAppIsRunning(app2UUID, timeoutExcludingDownload)
	device.WaitUntilAppIsRunning(app3UUID, timeoutExcludingDownload)
	evetest.Checkpoint("apps-running")

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second
	log := evetest.Logger()

	waitSSHReady := func(appUUID uuid.UUID) {
		t.Eventually(func(t Gomega) {
			log.Infof("Waiting for app %s SSH daemon to become reachable...", appUUID)
			_, _, err := device.RunShellScriptInsideApp(
				appUUID, appAuth, "hostname", sshTimeout, 0)
			t.Expect(err).ToNot(HaveOccurred())
		}, timeout, polling).Should(Succeed())
	}
	waitSSHReady(app1UUID)
	waitSSHReady(app2UUID)
	waitSSHReady(app3UUID)

	// hairpinProbe opens a raw TCP connection from inside srcApp to
	// targetIP:targetPort and returns the first bytes read back (expected to
	// be the target sshd's banner, "SSH-2.0-...", when the port-fwd works).
	hairpinProbe := func(srcApp uuid.UUID, targetIP net.IP, targetPort uint16) (string, error) {
		script := fmt.Sprintf(
			"timeout 5 bash -c 'exec 3<>/dev/tcp/%s/%d; head -c 4 <&3'",
			targetIP, targetPort)
		out, _, err := device.RunShellScriptInsideApp(
			srcApp, appAuth, script, sshTimeout, 0)
		return out, err
	}

	eth0IP := device.GetDeviceIPAddress("ethernet0")
	t.Expect(eth0IP).ToNot(BeEmpty())
	eth1IP := device.GetDeviceIPAddress("ethernet1")
	t.Expect(eth1IP).ToNot(BeEmpty())

	// Phase 1: same-adapter hairpin between app1 and app2 (both on ni1/ethernet0).
	log.Infof("Testing same-adapter hairpin: app1 -> app2's port-fwd")
	out, err := hairpinProbe(app1UUID, eth0IP[0], 2224)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(HavePrefix("SSH-"))

	log.Infof("Testing same-adapter hairpin: app2 -> app1's port-fwd")
	out, err = hairpinProbe(app2UUID, eth0IP[0], 2223)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(HavePrefix("SSH-"))
	evetest.Checkpoint("same-adapter-hairpin-verified")

	// Phase 2: change app1's port-fwd rule at runtime (2223 -> 2225).
	devConfig.UpdateApplication(app1UUID, newPortFwdApp("app1", ni1UUID, app1MAC, 2225))
	device.ApplyConfig(devConfig, false, false)
	waitSSHReady(app1UUID) // re-derives the endpoint from the updated config
	evetest.Checkpoint("app1-portfwd-switched-to-2225")

	log.Infof("Testing that the old port-fwd (2223) no longer forwards to app1")
	_, err = hairpinProbe(app2UUID, eth0IP[0], 2223)
	t.Expect(err).To(HaveOccurred())

	log.Infof("Testing that the new port-fwd (2225) forwards to app1")
	out, err = hairpinProbe(app2UUID, eth0IP[0], 2225)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(HavePrefix("SSH-"))

	// Switch app1's port-fwd rule back to its original port (2225 -> 2223).
	devConfig.UpdateApplication(app1UUID, newPortFwdApp("app1", ni1UUID, app1MAC, 2223))
	device.ApplyConfig(devConfig, false, false)
	waitSSHReady(app1UUID)
	evetest.Checkpoint("app1-portfwd-switched-back-to-2223")

	log.Infof("Testing that the temporary port-fwd (2225) no longer forwards to app1")
	_, err = hairpinProbe(app2UUID, eth0IP[0], 2225)
	t.Expect(err).To(HaveOccurred())

	log.Infof("Testing that the original port-fwd (2223) forwards to app1 again")
	out, err = hairpinProbe(app2UUID, eth0IP[0], 2223)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(HavePrefix("SSH-"))

	// Phase 3: cross-adapter hairpin -- app1 (ni1/ethernet0) reaches app3
	// (ni2/ethernet1) via ethernet1's own external IP.
	log.Infof("Testing cross-adapter hairpin: app1 (ethernet0) -> app3's port-fwd (ethernet1)")
	out, err = hairpinProbe(app1UUID, eth1IP[0], 2226)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(HavePrefix("SSH-"))
	evetest.Checkpoint("cross-adapter-hairpin-verified")

	// Cleanup.
	devConfig.DeleteApplication(app1UUID)
	devConfig.DeleteApplication(app2UUID)
	devConfig.DeleteApplication(app3UUID)
	devConfig.DeleteNetworkInstance(ni1UUID)
	devConfig.DeleteNetworkInstance(ni2UUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(app1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app1 is gone", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
	t.Eventually(app2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app2 is gone", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
	t.Eventually(app3Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app3 is gone", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
	stopApp1Watch()
	stopApp2Watch()
	stopApp3Watch()

	t.Eventually(ni1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"ni1 is gone", func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		}).StopIf(niHasError)))
	t.Eventually(ni2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"ni2 is gone", func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		}).StopIf(niHasError)))
	stopNI1Watch()
	stopNI2Watch()
}

// TestAirGapSwitchNI verifies that EVE can bridge applications over an
// air-gapped (portless) Switch Network Instance and correctly learns, via
// passive packet snooping (there is no internal DHCP server nor an external
// one here -- the NI has no port at all), the (statically assigned) IP address(es)
// each application VIF is using. See APP-CONNECTIVITY.md, "Switch Network
// Instance" / "IP address detection".
//
// This test additionally covers detecting *multiple* IP addresses recorded
// under the same VIF MAC address, by assigning a second IP directly on the
// same air-gapped interface (no new sub-interface).
//
// Note: EVE is also documented to detect multiple IPs per MAC when an
// application places VLAN sub-interfaces on top of its VIF (they share the
// parent interface's MAC) -- but that path was confirmed NOT to work on a
// Switch NI without VLAN-aware bridge config: the switch-NI ARP-snooping BPF
// filter in pkg/pillar/nistate/linux_flow.go (sniffDNSandDHCP) is a
// hand-maintained raw BPF program compiled from a filter string that never
// accounts for an 802.1Q tag, so tagged ARP frames are dropped by the kernel
// filter before EVE's collector ever sees them (verified with tcpdump on the
// EVE bridge: the tagged ARP requests do arrive, EVE just never reports
// them). Left as a known finding rather than exercised here.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port (ethernet0), used
//     only to give each app an SSH-reachable VIF; the actual scenario under
//     test runs entirely over the second, air-gapped VIF.
//
// Phases
// ------
//  1. Config: a Local NI "local-ni" on ethernet0 (10.11.10.0/24, for SSH
//     reachability only) and a Switch NI "switch-ni" with Port="" (air-gapped).
//     Two container apps (lfedge/evetest-ubuntu-ctr:1.0, VirtualizationMode=
//     HVM, EnforceNetIntfOrder=true so vif0=eth0/vif1=eth1 deterministically):
//     "app1" and "app2", each with vif0 on "local-ni" (port-fwd
//     2223/2224->22) and vif1 on "switch-ni" (fixed MAC, ICMP allow-all ACL --
//     Switch NI ACLs are still enforced even though the NI itself is L2-only).
//     WaitUntilAppIsRunning for both.
//  2. Static IP assignment + real traffic: from inside each app,
//     `ip addr add <ip>/24 dev eth1` assigns a static IP on the air-gapped
//     VIF (11.12.13.11 for app1, .12 for app2) -- no DHCP or
//     controller involvement, exactly as APP-CONNECTIVITY.md describes for
//     Switch NIs. `ping -c 3 -W 1 -I eth1 <peer-IP>` between the two
//     confirms real L2 connectivity over the bridge and generates the ARP
//     traffic EVE needs to snoop.
//  3. IP detection: NetworkInstanceInfo for "switch-ni" eventually reports an
//     IpAssignment for each app's MAC address containing the IP it just
//     configured -- proving EVE learned both addresses purely from ARP
//     snooping (no DHCP was ever involved on this NI).
//  4. Multiple IPs per MAC: on app2 only, two more static IPs are added
//     directly on eth1 (`ip addr add <ip>/24 dev eth1`, same interface, same
//     MAC, no sub-interface). A best-effort ping from each new address (the
//     target need not answer -- an ARP request alone is enough for EVE to
//     learn the Sender IP+MAC pair) generates the ARP traffic.
//     NetworkInstanceInfo eventually reports app2's single IpAssignment
//     (still keyed by the one shared VIF MAC) now listing all three IP
//     addresses.
//  5. Cleanup: delete both apps, then both NIs, waiting for each to be gone.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestApplicationConnectivitySuite.
func TestAirGapSwitchNI(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4Only})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	localNIUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.10.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.10.2"),
			End:   evetest.IPAddress("10.11.10.254"),
		},
		Gateway: evetest.IPAddress("10.11.10.1"),
		MTU:     1500,
	})
	switchNIUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "", // air-gapped
		MTU:         1500,
	})
	localNIUpdates, stopLocalNIWatch := device.WatchNetworkInstanceInfo(localNIUUID)
	switchNIUpdates, stopSwitchNIWatch := device.WatchNetworkInstanceInfo(switchNIUUID)
	device.ApplyConfig(devConfig, false, false)

	timeout := 3 * time.Minute
	t.Eventually(localNIUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"local-ni NI is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))
	t.Eventually(switchNIUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"switch-ni NI is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))
	evetest.Checkpoint("nis-created")

	icmpAllowAny := []evetest.ACLAllowRule{
		{
			Protocol:     evetest.NetworkProtocolICMP,
			RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
		},
	}
	const (
		app1MAC = "02:16:3e:00:02:01"
		app2MAC = "02:16:3e:00:02:02"
	)
	newApp := func(displayName, mac string,
		edgeNodePort uint16) evetest.ApplicationInstanceConfig {
		return evetest.ApplicationInstanceConfig{
			DisplayName: displayName,
			Activate:    true,
			Image: evetest.DockerContainer{
				ImageName: "lfedge/evetest-ubuntu-ctr",
				Tag:       "1.0",
			},
			VirtualizationMode:  eveconfig.VmMode_HVM,
			CPUs:                1,
			MemoryBytes:         500 * evetest.MiB,
			EnforceNetIntfOrder: true,
			NetworkAdapters: []evetest.AppNetworkAdapter{
				evetest.VirtualNetworkAdapter{
					LogicalLabel:        "vif0",
					NetworkInstanceUUID: localNIUUID,
					PortFwdRules: []evetest.PortFwdRule{
						{
							Protocol:     evetest.NetworkProtocolTCP,
							EdgeNodePort: edgeNodePort,
							AppPort:      22,
						},
					},
					ACLAllowRules: []evetest.ACLAllowRule{
						{
							Protocol:     evetest.NetworkProtocolAny,
							RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
						},
					},
				},
				evetest.VirtualNetworkAdapter{
					LogicalLabel:        "vif1",
					NetworkInstanceUUID: switchNIUUID,
					MAC:                 evetest.MACAddress(mac),
					ACLAllowRules:       icmpAllowAny,
				},
			},
		}
	}
	app1UUID := devConfig.AddApplication(newApp("app1", app1MAC, 2223))
	app2UUID := devConfig.AddApplication(newApp("app2", app2MAC, 2224))

	app1Updates, stopApp1Watch := device.WatchAppInfo(app1UUID)
	app2Updates, stopApp2Watch := device.WatchAppInfo(app2UUID)
	device.ApplyConfig(devConfig, false, false)

	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(app1UUID, timeoutExcludingDownload)
	device.WaitUntilAppIsRunning(app2UUID, timeoutExcludingDownload)
	evetest.Checkpoint("apps-running")

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second
	log := evetest.Logger()

	waitSSHReady := func(appUUID uuid.UUID) {
		t.Eventually(func(t Gomega) {
			log.Infof("Waiting for app %s SSH daemon to become reachable...", appUUID)
			_, _, err := device.RunShellScriptInsideApp(
				appUUID, appAuth, "hostname", sshTimeout, 0)
			t.Expect(err).ToNot(HaveOccurred())
		}, timeout, polling).Should(Succeed())
	}
	waitSSHReady(app1UUID)
	waitSSHReady(app2UUID)

	const (
		app1IP = "11.12.13.11"
		app2IP = "11.12.13.12"
	)

	log.Infof("Assigning static IP %s to app1's air-gapped VIF", app1IP)
	_, _, err := device.RunShellScriptInsideApp(app1UUID, appAuth,
		fmt.Sprintf("ip addr add %s/24 dev eth1 && ip link set eth1 up", app1IP),
		sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())

	log.Infof("Assigning static IP %s to app2's air-gapped VIF", app2IP)
	_, _, err = device.RunShellScriptInsideApp(app2UUID, appAuth,
		fmt.Sprintf("ip addr add %s/24 dev eth1 && ip link set eth1 up", app2IP),
		sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())

	evetest.Checkpoint("static-ips-assigned")

	log.Infof("Testing connectivity over the air-gapped switch NI")
	_, _, err = device.RunShellScriptInsideApp(app1UUID, appAuth,
		fmt.Sprintf("ping -c 3 -W 1 -I eth1 %s", app2IP), sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	_, _, err = device.RunShellScriptInsideApp(app2UUID, appAuth,
		fmt.Sprintf("ping -c 3 -W 1 -I eth1 %s", app1IP), sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())

	// EVE learns statically-assigned IPs on a Switch NI purely from ARP
	// snooping (see APP-CONNECTIVITY.md, "IP address detection"). The pings
	// above generated the necessary ARP traffic.
	t.Eventually(switchNIUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"switch-ni NI reports both static IP assignments",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			var app1Found, app2Found bool
			for _, a := range info.IpAssignments {
				switch a.MacAddress {
				case app1MAC:
					app1Found = generics.ContainsItem(a.IpAddress, app1IP)
				case app2MAC:
					app2Found = generics.ContainsItem(a.IpAddress, app2IP)
				}
			}
			return app1Found && app2Found
		}).StopIf(niHasError)))
	evetest.Checkpoint("static-ips-detected")

	// Phase 4: multiple IPs under the same MAC. Two more static IPs are
	// added directly on eth1 -- same interface, same MAC, no sub-interface
	// (see the doc comment above for why VLAN sub-interfaces are not used
	// here).
	const (
		extraIP1 = "11.12.16.12"
		extraIP2 = "11.12.17.12"
	)
	log.Infof("Adding two more static IPs on app2's air-gapped VIF")
	_, _, err = device.RunShellScriptInsideApp(app2UUID, appAuth,
		fmt.Sprintf(`set -e
ip addr add %s/24 dev eth1
ip addr add %s/24 dev eth1
set +e
# Best-effort: the targets below need not respond, an outbound ARP request
# alone is enough for EVE to learn the Sender IP+MAC assignment.
ping -c 3 -W 1 -I eth1 11.12.16.99
ping -c 3 -W 1 -I eth1 11.12.17.99
true
`, extraIP1, extraIP2), sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	evetest.Checkpoint("extra-ips-added")

	t.Eventually(switchNIUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"switch-ni NI reports all three IPs for app2's MAC",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			for _, a := range info.IpAssignments {
				if a.MacAddress != app2MAC {
					continue
				}
				return generics.ContainsItem(a.IpAddress, app2IP) &&
					generics.ContainsItem(a.IpAddress, extraIP1) &&
					generics.ContainsItem(a.IpAddress, extraIP2)
			}
			return false
		}).StopIf(niHasError)))
	evetest.Checkpoint("multiple-ips-per-mac-detected")

	// Cleanup.
	devConfig.DeleteApplication(app1UUID)
	devConfig.DeleteApplication(app2UUID)
	devConfig.DeleteNetworkInstance(localNIUUID)
	devConfig.DeleteNetworkInstance(switchNIUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(app1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app1 is gone", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
	t.Eventually(app2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app2 is gone", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
	stopApp1Watch()
	stopApp2Watch()

	t.Eventually(localNIUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"local-ni NI is gone", func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		}).StopIf(niHasError)))
	t.Eventually(switchNIUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"switch-ni NI is gone", func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		}).StopIf(niHasError)))
	stopLocalNIWatch()
	stopSwitchNIWatch()
}

// TestLimitedIPSpace verifies two related IP-allocation edge cases on a
// Local Network Instance whose DHCP range holds only a single free address:
//
//  1. An application deployed onto a NI with no free IP left must fail
//     (report an error), not be silently skipped or crash other apps, and
//     must be automatically redeployed the moment an IP frees up (i.e. once
//     the other application holding it is deleted) -- with no config
//     re-apply needed beyond the one that removed the IP-holding app.
//  2. Replacing one application with another *within a single config
//     apply* (same NI, competing for the same single free IP) must work:
//     EVE has to tear down the obsolete app instance before bringing up the
//     replacement, otherwise the replacement would itself fail to get an IP
//     (exactly the failure mode from point 1, self-inflicted).
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port.
//
// Phases
// ------
//  1. Create a Local NI ("limited-ni") on ethernet0 with subnet
//     10.11.12.0/30. One address is the bridge/gateway (.1) and the DHCP
//     range is deliberately restricted to the single remaining host address,
//     10.11.12.2 (Start == End) -- exactly one IP is available for
//     applications at any given time. Wait for ONLINE.
//  2. Deploy "app1" on limited-ni (container, no static IP, allow-all ACL).
//     It takes the only free IP. WaitUntilAppIsRunning.
//  3. Deploy "app2" on the same NI. There is no free IP left, so zedrouter's
//     IPAM must report the allocation failure as an AppErr with a
//     description containing "no free IP addresses in DHCP range" --
//     the app stays in whatever SwState it reached (INSTALLED here; this is
//     a retryable/pending condition, not a terminal one, so EVE does not
//     move the app to ZSwState_ERROR for it). The app2 watch is opened
//     *before* applying this config change, since WaitUntilAppIsRunning
//     must not be used here -- it treats any ZSwState_ERROR as fatal, and
//     more importantly would never observe this particular failure since
//     the app's SwState never becomes ZSwState_ERROR.
//  4. Delete app1 (freeing its IP) and re-apply. app1's watch confirms it
//     reaches ZSwState_INVALID. Without any further app2-specific config
//     change, app2 must automatically pick up the now-free IP and reach
//     RUNNING -- proving EVE retries pending IP allocations as soon as one
//     becomes available, not just on the next explicit config edit for that
//     app.
//  5. Replace app2 with a new application instance within a single config
//     apply: DeleteApplication(app2) and AddApplication(same DisplayName,
//     same NI) are both applied to the EdgeDeviceConfig before the next
//     ApplyConfig call. The replacement gets a fresh UUID with no prior history,
//     so WaitUntilAppIsRunning is safe to use and confirms it reaches
//     RUNNING -- proving EVE tears down the obsolete instance before deploying
//     the replacement, rather than attempting both at once and failing to
//     allocate a second IP.
//  6. Cleanup: delete the replacement app instance and the NI, waiting for
//     each to be gone.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestApplicationConnectivitySuite.
func TestLimitedIPSpace(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4Only})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "limited-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/30"),
		DHCPRange: types.IPRange{
			// Only one host address is available for allocation: .0 is the
			// network address, .1 is taken by the bridge, .3 is the
			// broadcast address.
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.2"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
		MTU:     1500,
	})
	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	device.ApplyConfig(devConfig, false, false)

	timeout := 3 * time.Minute
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"limited-ni is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))
	evetest.Checkpoint("ni-created")

	allowAll := []evetest.ACLAllowRule{
		{
			Protocol:     evetest.NetworkProtocolAny,
			RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
		},
	}
	newApp := func(displayName string) evetest.ApplicationInstanceConfig {
		return evetest.ApplicationInstanceConfig{
			DisplayName: displayName,
			Activate:    true,
			Image: evetest.DockerContainer{
				ImageName: "lfedge/evetest-ubuntu-ctr",
				Tag:       "1.0",
			},
			VirtualizationMode: eveconfig.VmMode_HVM,
			CPUs:               1,
			MemoryBytes:        500 * evetest.MiB,
			NetworkAdapters: []evetest.AppNetworkAdapter{
				evetest.VirtualNetworkAdapter{
					LogicalLabel:        "vif0",
					NetworkInstanceUUID: niUUID,
					ACLAllowRules:       allowAll,
				},
			},
		}
	}

	// Step 2: app1 takes the only free IP.
	app1UUID := devConfig.AddApplication(newApp("app1"))
	app1Updates, stopApp1Watch := device.WatchAppInfo(app1UUID)
	device.ApplyConfig(devConfig, false, false)
	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(app1UUID, timeoutExcludingDownload)
	evetest.Checkpoint("app1-running")

	// Step 3: app2 has no free IP to allocate. This surfaces as a persistent
	// AppErr on the app while it remains in whatever SwState it reached
	// (INSTALLED here, since the image/volume are fine -- only network
	// activation is blocked) -- it is a retryable/pending condition, not a
	// terminal one, so EVE does not move the app to ZSwState_ERROR for it.
	// The watch is opened before applying, and WaitUntilAppIsRunning is
	// deliberately not used here -- the no-free-IP AppErr is the expected
	// outcome, not a fatal condition.
	app2UUID := devConfig.AddApplication(newApp("app2"))
	app2Updates, stopApp2Watch := device.WatchAppInfo(app2UUID)
	device.ApplyConfig(devConfig, false, false)

	const expectedErrMsg = "no free IP addresses in DHCP range"
	t.Eventually(app2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app2 fails with a no-free-IP error",
		func(info *eveinfo.ZInfoApp) bool {
			for _, appErr := range info.AppErr {
				if strings.Contains(appErr.GetDescription(), expectedErrMsg) {
					return true
				}
			}
			return false
		})))
	evetest.Checkpoint("app2-out-of-ip-error")

	// Step 4: delete app1, freeing its IP. app2 must automatically pick it
	// up and reach RUNNING, without any app2-specific config change.
	devConfig.DeleteApplication(app1UUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(app1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app1 is gone", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
	stopApp1Watch()

	t.Eventually(app2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app2 is RUNNING", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_RUNNING
		}).StopIf(appHasError)))
	stopApp2Watch()
	evetest.Checkpoint("app2-recovered")

	// Step 5: replace app2 with a new application instance within a single
	// config apply -- delete the old one and add the replacement before the
	// next ApplyConfig call.
	devConfig.DeleteApplication(app2UUID)
	newApp2UUID := devConfig.AddApplication(newApp("app2"))
	newApp2Updates, stopNewApp2Watch := device.WatchAppInfo(newApp2UUID)
	device.ApplyConfig(devConfig, false, false)
	device.WaitUntilAppIsRunning(newApp2UUID, timeoutExcludingDownload)
	evetest.Checkpoint("app2-replaced")

	// Cleanup.
	devConfig.DeleteApplication(newApp2UUID)
	devConfig.DeleteNetworkInstance(niUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(newApp2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"replacement app2 is gone", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
	stopNewApp2Watch()

	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"limited-ni is gone", func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_UNSPECIFIED
		}).StopIf(niHasError)))
	stopNIWatch()
}

// TestFlowLog verifies that EVE produces flow log records and DNS request log
// records for application traffic when flow logging is enabled on a Local
// Network Instance, and that those records correctly attribute flows to ACE
// IDs (allowed flows -> matching ACE; dropped flows -> ACE id 0, the implicit
// reject-all).
//
// ACE numbering: EVE assigns ACE ids sequentially in the order rules are
// listed on the VIF, starting at 1 (id 0 is reserved for the implicit
// reject-all) -- see EdgeDeviceConfig's ACL-building code in devconfig.go.
// The app's single VIF below lists, in order: the port-fwd rule (-> ACE 1),
// the HTTP allow rule (-> ACE 2), the ICMP allow rule (-> ACE 3).
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- already has a second HTTP endpoint,
//     http-server2.test:8080, used here as the target that is NOT covered
//     by any allow rule (so it falls through to the implicit reject-all).
//
// Device configuration
// --------------------
//   - ethernet0 (mgmt+app, DHCP).
//   - One Local NI ("flow-ni") with EnableFlowlog=true.
//   - One container app on the NI with one VIF and three ACEs: port-fwd
//     2222->22 (ACE 1), allow TCP:80 to http-server.test (ACE 2), allow ICMP
//     to the NI's own gateway IP (ACE 3). Everything else (in particular
//     http-server2.test:8080) falls through to the implicit reject-all
//     (ACE 0).
//
// Phases
// ------
//  1. Generate distinguishable traffic from inside the app: curl
//     http-server.test/helloworld (allowed, ACE 2); curl --max-time 5
//     http-server2.test:8080/helloworld (must fail, ACE 0); ping -c 3 against
//     the NI gateway IP (allowed, ACE 3); nslookup http-server.test (DNS
//     request log entry).
//  2. Flow log assertions (GetAppFlowLogs, NotBefore the traffic above): EVE
//     tracks one flow record per connection (conntrack-based), not one per
//     packet direction -- Flow.Src is always the app's own VIF IP and
//     Flow.Dest the remote endpoint regardless of direction, so a flow's
//     Tx/Rx counters together cover the whole connection. Eventually there is
//     an outbound (app-initiated) record matching each of:
//     - ACE 2: dst httpServerIP:80/TCP, with TxPkts and RxPkts both > 0
//     (request sent, response received).
//     - ACE 3: dst NI gateway/ICMP, with TxPkts and RxPkts both > 0 (ping
//     requests sent, replies received).
//     - ACE 0 (implicit reject-all): dst httpServer2IP:8080/TCP, with
//     TxPkts > 0 (the app did send it) but RxPkts == 0 (blackholed --
//     see APP-CONNECTIVITY.md -- so nothing ever came back).
//     Plus one inbound (externally-initiated) record for ACE 1, the
//     port-forwarded SSH session already in use to drive the app (src port
//     22 on the app side), with both Tx and Rx counters > 0.
//  3. DNS log assertions (GetAppDNSLogs): eventually there is a DNSRequest
//     record for hostname "http-server.test" whose resolved address matches
//     the SDN http-server endpoint's IP, with a request time within the
//     test window.
//  4. Flow logging disabled: UpdateNetworkInstance sets EnableFlowlog=false;
//     re-apply. Fresh traffic is generated, then GetAppFlowLogs (NotBefore
//     the reapply instant) consistently returns empty over the reporting
//     interval, confirming the runtime toggle actually stops new records
//     from being produced (not just that old ones happen to still be there).
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestFlowLog(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	// ACE ids, per the numbering scheme documented above.
	const (
		portFwdAceID   = int32(1)
		allowHTTPAceID = int32(2)
		allowICMPAceID = int32(3)
		denyAceID      = int32(0)
	)
	// IANA IP protocol numbers, as reported in FlowRecord.Flow.Protocol.
	const (
		ipProtoICMP = int32(1)
		ipProtoTCP  = int32(6)
	)
	// SDN endpoint IPs, as defined in netmodels.SingleEthWithDHCP.
	const (
		httpServerIP  = "10.17.17.25" // http-server.test:80 (allowed)
		httpServer2IP = "10.18.18.25" // http-server2.test:8080 (not allowed -> denied)
	)

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	eth0Net := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4Only})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   eth0Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	const niGatewayIP = "10.50.0.1"
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "flow-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.50.0.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.50.0.2"),
			End:   evetest.IPAddress("10.50.0.254"),
		},
		Gateway:       evetest.IPAddress(niGatewayIP),
		EnableFlowlog: true,
		MTU:           1500,
	})

	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "flowlog-test-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
						AppPort:      22,
					},
				},
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:       evetest.NetworkProtocolTCP,
						RemoteHostname: "http-server.test",
						RemotePort:     80,
					},
					{
						Protocol:     evetest.NetworkProtocolICMP,
						RemoteSubnet: evetest.IPSubnet(niGatewayIP + "/32"),
					},
				},
			},
		},
	})

	device.ApplyConfig(devConfig, false, false)
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	evetest.Checkpoint("app-running")

	log := evetest.Logger()
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second

	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"hostname", sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring(appUUID.String()))
	}, 3*time.Minute, polling).Should(Succeed())

	// Phase 1: generate distinguishable traffic.
	log.Infof("Phase 1: generating traffic for each ACE...")
	trafficStart := time.Now()

	output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS --max-time 10 http://http-server.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring("Hello world!"))

	_, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl --max-time 5 http://http-server2.test:8080/helloworld", 10*time.Second, 0)
	t.Expect(err).To(HaveOccurred(),
		"http-server2.test is not covered by any allow ACE and must be blocked")

	_, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"ping -c 3 "+niGatewayIP, sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())

	_, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"nslookup http-server.test", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	evetest.Checkpoint("phase1-traffic-generated")

	// Phase 2: flow log assertions.
	//
	// EVE tracks one flow record per connection (conntrack-based), not one
	// per packet direction: FlowRecord.Inbound says who *initiated* the
	// connection, while Flow.Src is always the app's own VIF IP and Flow.Dest
	// the remote endpoint, regardless of Inbound -- see
	// protoEncodeAppFlowMonitorProto / nistate/linux_flow.go. So the
	// app-initiated flows (HTTP, ICMP, the denied HTTP) are all Inbound=false
	// with a single record each (already carrying both Tx and Rx counters for
	// the whole connection); the port-forwarded SSH session is the only
	// Inbound=true flow here, since it was initiated from outside the app.
	log.Infof("Phase 2: waiting for flow log records to be reported...")
	appInfo := device.GetAppInfo(appUUID)
	t.Expect(appInfo.GetNetwork()).To(HaveLen(1))
	t.Expect(appInfo.GetNetwork()[0].GetIPAddrs()).ToNot(BeEmpty())
	appIP := appInfo.GetNetwork()[0].GetIPAddrs()[0]

	// pkg/pillar/nistate/linux.go's flowCollectInterval (~108-120s, randomized,
	// hardcoded -- no controller-config override) governs how often the
	// conntrack table is swept and a connection's flow record published, so
	// give it comfortable room for at least one full cycle plus margin.
	flowLogTimeout := 3 * time.Minute
	t.Eventually(func(g Gomega) {
		outbound := device.GetAppFlowLogs(appUUID, evetest.FlowLogMatch{
			VirtualNetAdapter: "vif0",
			NetworkInstance:   niUUID,
			Inbound:           false,
			NotBefore:         trafficStart,
		})

		httpRec := findFlowRecord(outbound, flowRecordMatch{
			aclID: allowHTTPAceID, srcIP: appIP, dstIP: httpServerIP,
			dstPort: 80, protocol: ipProtoTCP,
		})
		g.Expect(httpRec).ToNot(BeNil(),
			"expected an outbound flow record for the allowed HTTP ACE (%d) "+
				"from %s to %s:80", allowHTTPAceID, appIP, httpServerIP)
		g.Expect(httpRec.GetTxPkts()).To(BeNumerically(">", 0),
			"app must have sent the HTTP request")
		g.Expect(httpRec.GetRxPkts()).To(BeNumerically(">", 0),
			"app must have received the HTTP response")

		icmpRec := findFlowRecord(outbound, flowRecordMatch{
			aclID: allowICMPAceID, srcIP: appIP, dstIP: niGatewayIP, protocol: ipProtoICMP,
		})
		g.Expect(icmpRec).ToNot(BeNil(),
			"expected an outbound flow record for the allowed ICMP ACE (%d) "+
				"from %s to %s", allowICMPAceID, appIP, niGatewayIP)
		g.Expect(icmpRec.GetTxPkts()).To(BeNumerically(">", 0),
			"app must have sent ping requests")
		g.Expect(icmpRec.GetRxPkts()).To(BeNumerically(">", 0),
			"app must have received ping replies")

		deniedRec := findFlowRecord(outbound, flowRecordMatch{
			aclID: denyAceID, srcIP: appIP, dstIP: httpServer2IP,
			dstPort: 8080, protocol: ipProtoTCP,
		})
		g.Expect(deniedRec).ToNot(BeNil(),
			"expected an outbound flow record for the denied traffic "+
				"(implicit reject-all, ACE %d) from %s to %s:8080 -- EVE logs "+
				"the flow even though the packet was blackholed",
			denyAceID, appIP, httpServer2IP)
		g.Expect(deniedRec.GetTxPkts()).To(BeNumerically(">", 0),
			"app must have sent connection attempts")
		g.Expect(deniedRec.GetRxPkts()).To(BeNumerically("==", 0),
			"no reply should ever come back for a blackholed connection")

		inbound := device.GetAppFlowLogs(appUUID, evetest.FlowLogMatch{
			VirtualNetAdapter: "vif0",
			NetworkInstance:   niUUID,
			Inbound:           true,
			NotBefore:         trafficStart,
		})
		sshRec := findFlowRecord(inbound, flowRecordMatch{
			aclID: portFwdAceID, inbound: true, srcIP: appIP, protocol: ipProtoTCP,
		})
		g.Expect(sshRec).ToNot(BeNil(),
			"expected an inbound flow record for the port-forwarded SSH "+
				"session (ACE %d) to app %s", portFwdAceID, appIP)
		g.Expect(sshRec.GetFlow().GetSrcPort()).To(Equal(int32(22)),
			"the app's own listening port for the port-forwarded connection must be 22")
		g.Expect(sshRec.GetTxPkts()).To(BeNumerically(">", 0))
		g.Expect(sshRec.GetRxPkts()).To(BeNumerically(">", 0))
	}, flowLogTimeout, 5*time.Second).Should(Succeed())
	evetest.Checkpoint("phase2-flow-logs-verified")

	// Phase 3: DNS log assertions.
	log.Infof("Phase 3: waiting for the DNS request log record...")
	t.Eventually(func(g Gomega) {
		dnsLogs := device.GetAppDNSLogs(appUUID, evetest.DNSLogMatch{
			VirtualNetAdapter: "vif0",
			NetworkInstance:   niUUID,
			NotBefore:         trafficStart,
		})
		req := findDNSRequest(dnsLogs, "http-server.test")
		g.Expect(req).ToNot(BeNil(),
			"expected a DNS request log record for http-server.test")
		g.Expect(req.GetAddrs()).To(ContainElement(httpServerIP),
			"resolved address must match the SDN http-server endpoint")
	}, flowLogTimeout, 5*time.Second).Should(Succeed())
	evetest.Checkpoint("phase3-dns-logs-verified")

	// Phase 4: disable flow logging and confirm no new records appear.
	log.Infof("Phase 4: disabling flow logging and generating fresh traffic...")
	devConfig.UpdateNetworkInstance(niUUID, evetest.LocalNetworkInstanceConfig{
		DisplayName: "flow-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.50.0.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.50.0.2"),
			End:   evetest.IPAddress("10.50.0.254"),
		},
		Gateway:       evetest.IPAddress(niGatewayIP),
		EnableFlowlog: false,
		MTU:           1500,
	})
	device.ApplyConfig(devConfig, false, false)
	reapplyTime := time.Now()

	_, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS --max-time 10 http://http-server.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	evetest.Checkpoint("phase4-flowlog-disabled")

	t.Consistently(func() []*eveflowlog.FlowRecord {
		return device.GetAppFlowLogs(appUUID, evetest.FlowLogMatch{
			VirtualNetAdapter: "vif0",
			NetworkInstance:   niUUID,
			Inbound:           false,
			NotBefore:         reapplyTime,
		})
	}, 3*time.Minute, 10*time.Second).Should(BeEmpty(),
		"no new flow records should be produced after EnableFlowlog is set to false")
	evetest.Checkpoint("phase4-complete")
}

// flowRecordMatch describes the identifying criteria for a single flow log
// record. aclID and inbound are always checked; srcIP, dstIP, dstPort and
// protocol are only checked when non-zero (dstPort and protocol are left
// unset for ICMP, which has neither a meaningful port nor is worth
// double-checking the protocol number for here).
type flowRecordMatch struct {
	aclID    int32
	inbound  bool
	srcIP    string // Flow.Src is always the app's own VIF IP, regardless of direction.
	dstIP    string // Flow.Dest is always the remote endpoint.
	dstPort  int32
	protocol int32
}

// findFlowRecord returns the first record in records matching every
// non-zero-valued field of want, or nil if there is none.
func findFlowRecord(records []*eveflowlog.FlowRecord, want flowRecordMatch) *eveflowlog.FlowRecord {
	for _, rec := range records {
		if rec.GetAclId() != want.aclID || rec.GetInbound() != want.inbound {
			continue
		}
		flow := rec.GetFlow()
		if want.srcIP != "" && flow.GetSrc() != want.srcIP {
			continue
		}
		if want.dstIP != "" && flow.GetDest() != want.dstIP {
			continue
		}
		if want.dstPort != 0 && flow.GetDestPort() != want.dstPort {
			continue
		}
		if want.protocol != 0 && flow.GetProtocol() != want.protocol {
			continue
		}
		return rec
	}
	return nil
}

// findDNSRequest returns the first record in records with the given
// hostname, or nil if there is none.
func findDNSRequest(records []*eveflowlog.DnsRequest, hostname string) *eveflowlog.DnsRequest {
	for _, rec := range records {
		if rec.GetHostName() == hostname {
			return rec
		}
	}
	return nil
}

func niHasError(info *eveinfo.ZInfoNetworkInstance) (string, bool) {
	stop := info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ERROR
	if stop {
		return "Network instance is in error state", true
	}
	return "", false
}

func appHasError(info *eveinfo.ZInfoApp) (string, bool) {
	stop := info.State == eveinfo.ZSwState_ERROR
	if stop {
		return "Application instance is in error state", true
	}
	return "", false
}
