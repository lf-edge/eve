// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/proto"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

// TestDeviceIPv6Connectivity verifies that EVE itself can establish and maintain
// controller connectivity over IPv6-only management networking. Application
// connectivity is intentionally out of scope here (see
// TestApplicationIPv6Connectivity for that side).
//
// Network model
// -------------
//   - netmodels.SingleEthIPv6Only -- one eth0 port, IPv6-only segment
//     (fd3f:89fd:78c5::/64). Address assignment is via SLAAC; DNS delivery
//     uses DHCPv6 options. No IPv4 endpoint exists on this network, so
//     controller reachability is forced end-to-end over IPv6. The SDN DNS
//     server is IPv6-only and resolves the controller hostname to
//     evetest.GetControllerIPv6().
//
// Setup
// -----
//   - No RequireInternetConnectivity gate: the EVE<->controller path flows
//     through the SDN tunnel inside the evetest container. In all-in-one
//     mode, IPv6 between EVE and Adam works even when the host has no public
//     IPv6 connectivity, because all probed endpoints live inside SDN.
//
// Phases
// ------
//  1. Apply DHCPNetworkConfig{V6Only} on ethernet0 (mgmt+app).
//  2. Wait until ethernet0 reports a global-unicast IPv6 address and no IPv4
//     address in DevicePortStatus.
//  3. Assert DPC health: SystemAdapterInfo.CurrentIndex==0 and
//     DevicePortStatus.LastError is empty.
//  4. Assert the default router for ethernet0 is a link-local IPv6 address.
//     Per RFC 4861, RA-derived default routes are always announced via the
//     router's link-local address, not its global-unicast address.
//  5. Wait for DevicePortStatus.LastSucceeded to advance past its initial
//     value, confirming ongoing controller reachability.
//  6. SSH checks (ip tooling):
//     - ip -6 addr show dev eth0 contains the reported global-unicast IPv6.
//     - ip -6 route show contains a default route via a fe80:: link-local
//     address (RA-derived routes always use the router's link-local address).
//     - ip -4 addr show dev eth0 contains no "inet" lines (no IPv4).
func TestDeviceIPv6Connectivity(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	devName := "edge-dev"
	// Clone the shared model so we can modify it without side effects.
	// Clear upstream DNS servers: everything this test needs (controller, DNS
	// server) lives inside SDN, so host IPv6 internet access is not required.
	// Keeping unreachable internet resolvers would cause dnsmasq to time out
	// on every unknown-name query, blocking NIM's DNS refresh cycle and
	// causing the controller ping to exceed its 15-second timeout.
	networkModel := proto.Clone(netmodels.SingleEthIPv6Only).(*api.NetworkModel)
	networkModel.Endpoints.DnsServers[0].UpstreamServers = nil
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    evetest.HypervisorKVM,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: networkModel,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V6Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")

	log := evetest.Logger()
	timeout := 5 * time.Minute

	// Wait for ethernet0 to acquire a global-unicast IPv6 and no IPv4.
	var dinfo *eveinfo.ZInfoDevice
	var eth0IPv6 net.IP
	log.Infof("Waiting for ethernet0 to acquire a global-unicast IPv6 (no IPv4)...")
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"ethernet0 has global-unicast IPv6 and no IPv4",
		func(info *eveinfo.ZInfoDevice) bool {
			dinfo = info
			eth0IPv6 = getPortIPv6GlobalAddr("ethernet0", info)
			return eth0IPv6 != nil && getPortIPv4Addr("ethernet0", info) == nil
		})))

	evetest.Checkpoint("ipv6-addr-acquired")

	// DPC must be healthy: first DPC active, no error.
	t.Expect(dinfo.GetSystemAdapter().GetCurrentIndex()).To(BeZero())
	dpc := getCurrentDPC(dinfo)
	t.Expect(dpc).ToNot(BeNil())
	t.Expect(dpc.GetLastError()).To(BeEmpty())

	// Default router must be a link-local IPv6 address. Per RFC 4861,
	// RA-derived default routes are always announced via the router's
	// link-local address, not its global-unicast address.
	port := getDevicePort("ethernet0", dinfo)
	t.Expect(port).ToNot(BeNil())
	defaultRouters := port.GetDefaultRouters()
	t.Expect(defaultRouters).ToNot(BeEmpty())
	routerIP := net.ParseIP(defaultRouters[0])
	t.Expect(routerIP).ToNot(BeNil())
	t.Expect(routerIP.IsLinkLocalUnicast()).To(BeTrue())

	// Wait for LastSucceeded to advance, confirming ongoing controller connectivity.
	firstSucceeded := dpc.GetLastSucceeded().AsTime()
	log.Infof("Waiting for DPC LastSucceeded to advance (periodic connectivity probe)...")
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"DPC LastSucceeded has advanced",
		func(info *eveinfo.ZInfoDevice) bool {
			dpc = getCurrentDPC(info)
			return dpc != nil && dpc.GetLastSucceeded().AsTime().After(firstSucceeded)
		})))

	evetest.Checkpoint("controller-reachable")

	sshTimeout := 20 * time.Second

	// Kernel-side: eth0 must show the reported global-unicast IPv6.
	log.Infof("SSH: verifying eth0 carries the expected global-unicast IPv6...")
	out, _, err := device.RunShellScript("ip -6 addr show dev eth0", 0, sshTimeout)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring(eth0IPv6.String()))

	// Kernel-side: a default IPv6 route must exist via a link-local gateway
	// (RA-derived routes always use the router's link-local address).
	out, _, err = device.RunShellScript("ip -6 route show", 0, sshTimeout)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("default via fe80::"))

	// Negative: no non-link-local IPv4 on eth0.
	log.Infof("SSH: confirming eth0 has no IPv4 address...")
	out, _, err = device.RunShellScript("ip -4 addr show dev eth0", 0, sshTimeout)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).ToNot(ContainSubstring("inet "))
}

// TestApplicationIPv6Connectivity verifies that an application connected to a
// Switch Network Instance on an IPv6-only segment acquires a global-unicast
// IPv6 address, has it reported in EVE info messages, and can communicate with
// external endpoints over IPv6. Device-side IPv6 connectivity is covered by
// TestDeviceIPv6Connectivity; this test focuses on the application side only.
//
// Local NI on IPv6 is intentionally not covered: EVE currently supports IPv6
// for apps only on switch NIs.
//
// Network model
// -------------
//   - netmodels.SingleEthIPv6Only -- one eth0 port, IPv6-only segment
//     (fd3f:89fd:78c5::/64, SLAAC). The SDN HTTP server "http-server.test"
//     is reachable exclusively on its IPv6 address (fdde:55a:74d4::7); the
//     SDN DNS server serves only an AAAA record for that hostname, so the
//     DNS-based curl probe exercises the AAAA-only resolution path
//     end-to-end.
//
// Setup
// -----
//   - RequireInternetConnectivity{RequireIPv6: true}: the device is IPv6-only,
//     so the app image must be pulled over IPv6. The test is skipped when the
//     host has no IPv6 internet connectivity.
//
// Phases
// ------
//  1. Apply DHCPNetworkConfig{V6Only} on ethernet0 (mgmt+app). Add a Switch
//     NI ("switch-ni-v6") on ethernet0 with MTU=1500. Deploy container app
//     (milan4zededa/evetest-ubuntu-ctr:1.0, VmMode_HVM) on the switch NI
//     with a fixed MAC and an allow-all IPv6 ACL (::/0).
//     WaitUntilAppIsRunning.
//  2. Watch app info: the VIF eventually reports at least one global-unicast
//     IPv6 and no IPv4 in ZInfoApp.Network[0].IPAddrs. Switch NIs learn the
//     app's address via SLAAC ICMPv6 / DHCPv6 snooping, so this is the
//     authoritative signal that EVE observed the address come up.
//  3. Assert ZInfoApp.Network[0]: DevName="vif0", MacAddr matches the
//     configured address.
//  4. Watch NI info: IpAssignments for the app's MAC eventually contains the
//     same global-unicast IPv6 reported by the app. Assert Vifs is non-empty.
//  5. Inside-app probes via RunShellScriptInsideApp (SSH over IPv6 to the
//     app's address on the switch NI):
//     - `ip -6 addr show eth0` contains the reported global-unicast IPv6.
//     - Explicitly write the RDNSS server (fd23:131b:6500::1) to
//     /etc/resolv.conf. EVE's initrd (pkg/xen-tools/initrd/init-initrd)
//     should eventually do this automatically from RA RDNSS options; until
//     then the test sets it directly.
//     - `nslookup -type=AAAA http-server.test` resolves to fdde:55a:74d4::7.
//     - `curl -6 -sS http://[fdde:55a:74d4::7]/helloworld` returns
//     "Hello world!" (direct-IP probe, no DNS dependency).
//     - `curl -sS http://http-server.test/helloworld` returns "Hello world!"
//     (AAAA-only DNS resolution path).
//
// Test params
// -----------
//   - HYPERVISOR. evetest.SkipIfHypervisorKubevirt() is called after reading
//     the parameter -- Kubevirt is reserved for cluster tests.
func TestApplicationIPv6Connectivity(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	// Kubevirt is only supported by cluster tests.
	evetest.SkipIfHypervisorKubevirt()

	// IPv6 address of the SDN HTTP server and DNS server defined in netmodels.SingleEthIPv6Only.
	const httpServerIPv6 = "fdde:55a:74d4::7"
	const dnsServerIPv6 = "fd23:131b:6500::1"

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthIPv6Only,
		},
		// IPv6 internet access is required: the device is IPv6-only, so the
		// app image must be pulled over IPv6.
		evetest.RequireInternetConnectivity{RequireIPv6: true},
		// The device has no IPv4 route, so an IPv4-only registry mirror is
		// unreachable; only use mirror addresses that are themselves IPv6.
		evetest.RequireIPv6OnlyRegistryMirrors{},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build and apply device configuration.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V6Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})

	// Switch NI bridges eth0 directly into the IPv6-only segment; the app gets
	// an IPv6 address from SLAAC on the fd3f:89fd:78c5::/64 subnet.
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName:   "switch-ni-v6",
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
		VirtualizationMode: eveconfig.VmMode_HVM,
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
						RemoteSubnet: evetest.IPSubnet("::/0"),
					},
				},
			},
		},
	})

	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	defer stopNIWatch()
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, true, true)

	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("app-running")

	log := evetest.Logger()
	timeout := 5 * time.Minute

	// Wait for the app VIF to report a global-unicast IPv6 address and no IPv4.
	// Switch NIs learn the app's address via SLAAC ICMPv6 / DHCPv6 snooping
	// (APP-CONNECTIVITY.md "IP address detection"), so this is the authoritative
	// signal that EVE saw the address come up.
	var appInfo *eveinfo.ZInfoApp
	var appIPv6 net.IP
	log.Infof("Waiting for app VIF to report a global-unicast IPv6 (no IPv4)...")
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App VIF has global-unicast IPv6 and no IPv4",
		func(info *eveinfo.ZInfoApp) bool {
			appInfo = info
			if len(info.Network) == 0 {
				return false
			}
			vif := info.Network[0]
			var hasGlobalIPv6 bool
			for _, ipStr := range vif.IPAddrs {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					continue
				}
				if ip.To4() != nil {
					return false // IPv4 present — IPv6-only segment not yet enforced
				}
				if ip.IsGlobalUnicast() {
					appIPv6 = ip
					hasGlobalIPv6 = true
				}
			}
			return hasGlobalIPv6
		}).StopIf(appHasError)))

	evetest.Checkpoint("app-ipv6-acquired")

	t.Expect(appInfo.Network).To(HaveLen(1))
	t.Expect(appInfo.Network[0].DevName).To(Equal("vif0"))
	t.Expect(appInfo.Network[0].MacAddr).To(Equal(appMACAddr))
	t.Expect(appIPv6).ToNot(BeNil())

	// Confirm the NI reports the same IPv6 in IpAssignments for the app's MAC.
	var niInfo *eveinfo.ZInfoNetworkInstance
	log.Infof("Waiting for NI to report app's IPv6 in IpAssignments...")
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI IpAssignments contains app's IPv6 for its MAC",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			for _, ipAssignment := range niInfo.IpAssignments {
				if ipAssignment.MacAddress == appMACAddr {
					return generics.ContainsItem(ipAssignment.IpAddress, appIPv6.String())
				}
			}
			return false
		}).StopIf(niHasError)))
	t.Expect(niInfo.Vifs).ToNot(BeEmpty())

	evetest.Checkpoint("ni-app-ip-reported")

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second

	// Wait for the app SSH daemon to start and confirm the expected IPv6 address.
	log.Infof("Waiting for app SSH daemon to become reachable over IPv6...")
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"ip -6 addr show eth0", sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).To(ContainSubstring(appIPv6.String()))
	}, timeout, polling).Should(Succeed())

	evetest.Checkpoint("app-ssh-reachable")

	// TODO: EVE's initrd (pkg/xen-tools/initrd/init-initrd) should pick up
	// the RDNSS server from Router Advertisements and write /etc/resolv.conf
	// automatically. Until that is fixed, set it explicitly here.
	log.Infof("Configuring DNS server inside the app...")
	_, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		fmt.Sprintf("echo 'nameserver %s' > /etc/resolv.conf", dnsServerIPv6), sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())

	// DNS: query AAAA for http-server.test; no A record exists in the SDN DNS.
	log.Infof("Testing AAAA DNS resolution from inside the application...")
	out, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"nslookup -type=AAAA http-server.test", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring(httpServerIPv6))

	// Direct-IP HTTP over IPv6: no DNS dependency.
	log.Infof("Testing direct IPv6 HTTP access from inside the application...")
	out, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		fmt.Sprintf("curl -6 -sS http://[%s]/helloworld", httpServerIPv6), sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("Hello world!"))

	// AAAA-only DNS path: curl resolves http-server.test via AAAA record.
	log.Infof("Testing DNS-based IPv6 HTTP access from inside the application...")
	out, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS http://http-server.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("Hello world!"))
}
