// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test creating, changing, deleting NI. Try to run traffic etc.

package networking_test

import (
	"net"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
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
//     (milan4zededa/evetest-ubuntu-ctr:1.0) with a single
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
//  7. Flow / DNS log assertions are commented out -- GetAppFlowLogs /
//     GetAppDNSLogs are not yet implemented in evetest (see
//     edgedevice.go). The placeholders document the intended check
//     (with flowlog disabled the lists must be empty) and will be enabled
//     once the framework support lands.
//  8. App teardown: delete the app, wait until ZSwState_INVALID, then
//     assert NetworkInstance.Vifs is empty and the bridge-IP assignment
//     persists. Finally delete the NI and wait for UNSPECIFIED.
//
// Test params
// -----------
//   - HYPERVISOR. The test calls evetest.SkipIfHypervisorKubevirt() right
//     after reading the parameter -- Kubevirt is reserved for cluster
//     tests.
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
	// Kubevirt is only supported by cluster tests.
	evetest.SkipIfHypervisorKubevirt()

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
			ImageName: "milan4zededa/evetest-ubuntu-ctr",
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
	/* TODO: GetAppFlowLogs is not yet implemented
	t.Expect(device.GetAppFlowLogs(appUUID, evetest.FlowLogMatch{
		VirtualNetAdapter: "vif0",
		NetworkInstance:   niUUID,
	})).To(BeEmpty())
	t.Expect(device.GetAppDNSLogs(appUUID, evetest.DNSLogMatch{
		VirtualNetAdapter: "vif0",
		NetworkInstance:   niUUID,
	})).To(BeEmpty())
	*/

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
//     (milan4zededa/evetest-ubuntu-ctr:1.0) with one VirtualNetworkAdapter
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
//   - HYPERVISOR. SkipIfHypervisorKubevirt() is called immediately after
//     reading the parameter.
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
	// Kubevirt is only supported by cluster tests.
	evetest.SkipIfHypervisorKubevirt()

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
			ImageName: "milan4zededa/evetest-ubuntu-ctr",
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
	/* TODO: GetAppFlowLogs is not yet implemented
	t.Expect(device.GetAppFlowLogs(appUUID, evetest.FlowLogMatch{
		VirtualNetAdapter: "vif0",
		NetworkInstance:   niUUID,
	})).To(BeEmpty())
	t.Expect(device.GetAppDNSLogs(appUUID, evetest.DNSLogMatch{
		VirtualNetAdapter: "vif0",
		NetworkInstance:   niUUID,
	})).To(BeEmpty())
	*/

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

// TestFlowLog verifies that EVE produces flow log records and DNS request log
// records for application traffic when flow logging is enabled on a Local
// Network Instance, and that those records correctly attribute flows to ACE
// IDs (allowed flows -> matching ACE; dropped flows -> ACE id 0 = implicit
// reject-all).
//
// SKIPPED: app flow logs are not yet supported in evetest. The framework
// provides the API (EdgeDevice.GetAppFlowLogs / GetAppDNSLogs) but its
// implementation depends on AdamClient.IterateAppFlowLogs which is not
// implemented (see edgedevice.go).
//
// When implemented later, the scenario:
//
// Network model
//   - netmodels.SingleEthWithDHCP, plus a second SDN HTTP server
//     (alt-server.test) for an additional differentiable target.
//
// Device configuration
//   - One Local NI with EnableFlowlog=true and a Subnet/DHCPRange.
//   - One container app on the NI with three ACLs:
//   - allow IP+TCP+fport=80 to http-server.test (specific ACE id, e.g. 100)
//   - allow IP+ICMP to NI bridge IP (ACE id 200)
//   - default-deny is implicit (ACE id 0)
//   - Port-fwd 2222->22 on a separate ACE (id 300) to enable test SSH.
//
// Phase 1 — generate distinguishable traffic
//   - From inside the app: curl http-server.test/helloworld (allowed by ACE 100).
//   - From inside the app: curl --max-time 5 alt-server.test/helloworld
//     (must fail; matches the implicit deny -> ACE id 0).
//   - From inside the app: ping -c 3 <NI-bridge-IP> (allowed by ACE 200).
//   - From inside the app: nslookup http-server.test (DNS request log entry).
//
// Phase 2 — flow log assertions (via GetAppFlowLogs)
//   - Wait for the flow log batch (default 2-min interval per
//     APP-CONNECTIVITY.md). Use a generous timeout (3 min).
//   - For ACE id 100: at least one outbound flow with dst IP =
//     http-server.test's IP, dst port 80, proto TCP, packet count > 0.
//   - For ACE id 200: at least one outbound ICMP flow toward the NI
//     bridge IP.
//   - For ACE id 0: at least one outbound flow toward alt-server's IP, dst
//     port 80, proto TCP. The flow record is created because the app sent
//     the packet even though it was dropped (flow logging on Local NI uses
//     the conntrack-based mark-and-blackhole pattern; see APP-CONNECTIVITY.md).
//   - The reverse direction of each flow (Inbound) for the allowed flows is
//     also logged once the response packet is observed.
//
// Phase 3 — DNS log assertions (via GetAppDNSLogs)
//   - At least one DNSRequest record with hostname "http-server.test" and the
//     resolved IP equal to that of the SDN http-server endpoint.
//   - The request time is within the test window.
//
// Phase 4 — flow logging disabled
//   - UpdateNetworkInstance to set EnableFlowlog=false; re-apply.
//   - Generate fresh traffic; after the next reporting interval, assert that
//     no NEW flow records appear (timestamps strictly older than the
//     reapply time). This confirms the runtime toggle works.
//
// Test params
// -----------
//   - HYPERVISOR. The test must call evetest.SkipIfHypervisorKubevirt()
//     after reading the parameter -- Kubevirt is reserved for cluster tests.
func TestFlowLog(test *testing.T) {
	test.Skip("not yet implemented")
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
