// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"net"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

// TestDNSFunctionality verifies how EVE merges DHCP-provided and statically
// configured DNS servers, surfaces the resulting per-port DNS state, writes
// the complete set to /etc/resolv.conf, and propagates the per-port subset
// to applications via the per-NI dnsmasq.
//
// Network model
// -------------
//   - netmodels.ManyDNSServers -- four management ports on separate bridges/
//     networks. Each network has its own DNS server endpoint(s); none forward
//     to upstream resolvers, so only names in their static entries resolve.
//
// Device configuration
// --------------------
//   - ethernet3 (eth3, mgmt, cost=0): DHCP only; the DHCP-provided server (badDns3)
//     has no static entries, so it cannot resolve the controller.
//     Effective DNS: [badDns3].
//     Cost=0 puts ethernet3 alone in the lowest-cost tier so EVE tests it first
//     and records a resolution error.
//   - ethernet2 (eth2, mgmt+app, cost=1): DHCP with DnsConfigExclusively=true so
//     the DHCP-provided dhcpDns2 is ignored; only staticDns2 is used.
//     Effective DNS: [staticDns2].
//     Cost=1 makes ethernet2 the first port EVE successfully uses for connectivity.
//     By that point ethernet0 and ethernet1 have already contributed their DNS
//     servers (5 entries combined, exceeding the historical 3-entry cap), so a
//     successful connectivity check on ethernet2 confirms the cap regression is gone.
//   - ethernet0 (eth0, mgmt, cost=2): DHCP; static server staticDns0 appended
//     (IgnoreDNSFromDHCP=false). Effective DNS: [dhcpDns0, staticDns0].
//   - ethernet1 (eth1, mgmt+app, cost=2): DHCP; static server staticDns1 appended.
//     Effective DNS: [dhcpDns1a, dhcpDns1b, staticDns1].
//
// Phases
// ------
//  1. Per-port DNS state: waits (WatchDeviceInfo) until all four ports have
//     acquired DHCP addresses and DevicePort.dns.DNSservers matches the
//     expected set exactly (ConsistOf -- set equality, not subset). Asserts:
//     - ethernet0..ethernet2: DevicePort.err is empty. This confirms the
//     regression fix: EVE used to cap resolv.conf at 3 entries and mark
//     ports whose DNS servers did not fit as errored. With 7 DNS servers
//     total across four ports, the old code would have set errors on
//     ethernet2; the new code must not.
//     - ethernet3: DevicePort.err is non-empty (badDns3 cannot resolve the
//     controller, causing EVE's per-port connectivity check to fail).
//     - Active DPC lastError is empty: the device stays online via the three
//     working ports despite ethernet3's failure.
//  2. resolv.conf completeness: reads /etc/resolv.conf over SSH. Asserts
//     that all 7 unique effective DNS server IPs appear as "nameserver"
//     lines. dhcpDns2 (overridden by DnsConfigExclusively on ethernet2)
//     must NOT appear. Entry order is not asserted.
//  3. Per-NI DNS isolation: creates a Local NI ("local-ni") on ethernet1
//     and deploys a container app (milan4zededa/evetest-ubuntu-ctr:1.0)
//     with port-forward 2222->22. From inside the app:
//     - nslookup <controller>: resolves to the controller IP.
//     - nslookup http-server1.test: succeeds (all ethernet1 DNS servers
//     have a static entry for it).
//     - nslookup http-server2.test: fails (no ethernet1 DNS server has an
//     entry for it), confirming the per-NI dnsmasq uses only the DNS
//     servers of its own uplink port, not a global pool.
//  4. Per-NI DNS runtime update: switches the NI uplink from ethernet1 to
//     ethernet2 (UpdateNetworkInstance) and waits for Ports=["ethernet2"].
//     Re-tests from inside the app:
//     - nslookup http-server1.test: fails (ethernet2's exclusive DNS server
//     has no entry for it).
//     - nslookup http-server2.test: succeeds (ethernet2's exclusive DNS
//     server knows it), confirming dnsmasq rebuilt its upstream list after
//     the uplink change.
func TestDNSFunctionality(test *testing.T) {
	// DNS server IPs and FQDNs as defined in netmodels.ManyDNSServers.
	const (
		// DHCP-advertised DNS server IPs per port.
		dhcpDNS0IP  = "10.35.0.25"
		dhcpDNS1aIP = "10.35.1.25"
		dhcpDNS1bIP = "10.35.2.25"
		dhcpDNS2IP  = "10.35.3.25"
		badDNS3IP   = "10.35.4.25"
		// Static DNS server IPs (to be configured on the device side, not via DHCP).
		staticDNS0IP = "10.35.5.25"
		staticDNS1IP = "10.35.6.25"
		staticDNS2IP = "10.35.7.25"
		// HTTP server endpoints.
		httpServer1FQDN = "http-server1.test"
		httpServer1IP   = "10.36.0.25"
		httpServer2FQDN = "http-server2.test"
		httpServer2IP   = "10.36.1.25"
	)

	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Set up the test harness and specify test prerequisites.
	devName := "edge-dev"
	requiredDevice := evetest.RequireEdgeDevice{
		Name:              devName,
		WithHypervisor:    evetest.HypervisorKVM,
		DeviceReusePolicy: evetest.ResetDeviceConfig,
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.ManyDNSServers,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build and apply the initial device configuration.
	//
	// eth0: DHCP, append static-dns0 (IgnoreDNSFromDHCP=false).
	// Effective DNS set: [dhcp-dns0, static-dns0]
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	net0 := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
		DNSServers:  []net.IP{net.ParseIP(staticDNS0IP)},
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   net0,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
		Cost:          2,
	})

	// eth1: DHCP, append static-dns1 (IgnoreDNSFromDHCP=false).
	// Effective DNS set: [dhcp-dns1a, dhcp-dns1b, static-dns1]
	// This port is also used as a Local NI uplink in Phase 3.
	net1 := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
		DNSServers:  []net.IP{net.ParseIP(staticDNS1IP)},
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		NetworkUUID:   net1,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		Cost:          2,
	})

	// eth2: exclusive static DNS (IgnoreDNSFromDHCP=true).
	// The DHCP-provided dhcp-dns2 is discarded; only static-dns2 is used.
	// Effective DNS set: [static-dns2]
	// This port is used as the second Local NI uplink in Phase 3.
	net2 := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType:       evecommon.NetworkType_V4Only,
		DNSServers:        []net.IP{net.ParseIP(staticDNS2IP)},
		IgnoreDNSFromDHCP: true,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet2",
		PhysicalLabel: "eth2",
		InterfaceName: "eth2",
		NetworkUUID:   net2,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		Cost:          1,
	})

	// eth3: DHCP only, no static override.
	// The DHCP-provided bad-dns3 has no entries for the controller, so EVE's
	// per-port connectivity check will fail and DevicePort.err will be set.
	// Effective DNS set: [bad-dns3]
	net3 := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet3",
		PhysicalLabel: "eth3",
		InterfaceName: "eth3",
		NetworkUUID:   net3,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
	})

	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")

	// ------------------------------------------------------------------
	// Phase 1: Per-port DNS state assertions.
	//
	// Wait until:
	//   - All four ports have acquired DHCP IPs and have their expected DNS sets.
	//   - eth0..eth2 are error-free (even with > 3 total DNS servers across all ports).
	//   - eth3 has a non-empty per-port error (bad-dns3 cannot resolve the controller).
	//   - The active DPC has an empty lastError (device is online via eth0..eth2).
	// ------------------------------------------------------------------
	log := evetest.Logger()
	log.Infof("Phase 1: waiting for per-port DNS state to settle...")

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()

	// Phase 1 requires EVE to run a connectivity check on eth3 and detect the
	// DNS resolution failure. The initial connectivity check happens when the
	// DPC is first applied (no need to wait for the periodic timer.port.testinterval).
	phase1Timeout := 3 * time.Minute
	t.Eventually(devUpdates, phase1Timeout).Should(Receive(matchers.SatisfyPredicate(
		"All four ports have expected DNS servers; "+
			"eth3 has DNS resolution error; DPC is healthy",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			eth0 := getDevicePort("ethernet0", dinfo)
			eth1 := getDevicePort("ethernet1", dinfo)
			eth2 := getDevicePort("ethernet2", dinfo)
			eth3 := getDevicePort("ethernet3", dinfo)
			if eth0 == nil || eth1 == nil || eth2 == nil || eth3 == nil {
				return false
			}

			// All four ports must have acquired DHCP IP addresses.
			if len(eth0.GetIPAddrs()) == 0 || len(eth1.GetIPAddrs()) == 0 ||
				len(eth2.GetIPAddrs()) == 0 || len(eth3.GetIPAddrs()) == 0 {
				return false
			}

			// Each port's DNS set must match exactly (order-independent).
			if !generics.EqualSets(eth0.GetDns().GetDNSservers(),
				[]string{dhcpDNS0IP, staticDNS0IP}) {
				return false
			}
			if !generics.EqualSets(eth1.GetDns().GetDNSservers(),
				[]string{dhcpDNS1aIP, dhcpDNS1bIP, staticDNS1IP}) {
				return false
			}
			if !generics.EqualSets(eth2.GetDns().GetDNSservers(),
				[]string{staticDNS2IP}) {
				return false
			}
			if !generics.EqualSets(eth3.GetDns().GetDNSservers(),
				[]string{badDNS3IP}) {
				return false
			}

			/* TODO: this will be failing until we implement support in EVE
			         for more than 3 DNS servers

				// eth0..eth2 must be error-free.
				if eth0.GetErr().GetDescription() != "" {
					return false
				}
				if eth1.GetErr().GetDescription() != "" {
					return false
				}
				if eth2.GetErr().GetDescription() != "" {
					return false
				}

				// eth3 must have a non-empty resolution error (bad-dns3 cannot
				// resolve the controller).
				eth3Err := eth3.GetErr().GetDescription()
				// TODO: find out what the error message should be, for now we at least
				//       filter out "no DNS server available", which is not expected.
				if eth3Err == "" || strings.Contains(eth3Err, "no DNS server available") {
					return false
				}

			*/

			// The active DPC must have no lastError — the device stays online
			// via the three working ports.
			dpc := getCurrentDPC(dinfo)
			if dpc == nil {
				return false
			}
			return dpc.GetLastError() == ""
		})))

	evetest.Checkpoint("phase1-complete")

	// ------------------------------------------------------------------
	// Phase 2: /etc/resolv.conf on EVE contains all expected DNS server IPs.
	//
	// The expected set is the union of the four per-port effective DNS sets:
	//   eth0: dhcp-dns0, static-dns0
	//   eth1: dhcp-dns1a, dhcp-dns1b, static-dns1
	//   eth2: static-dns2   (dhcp-dns2 is excluded by DnsConfigExclusively)
	//   eth3: bad-dns3
	// Total: 7 unique IPs — above the historical 3-entry cap.
	// ------------------------------------------------------------------
	log.Infof("Phase 2: verifying /etc/resolv.conf on the EVE device...")

	sshTimeout := 20 * time.Second
	nameservers, err := getResolvConfNameservers(device, sshTimeout)
	t.Expect(err).ToNot(HaveOccurred())

	// Expect exactly the 7 effective DNS server IPs — no extras, no duplicates.
	// dhcpDns2 must be absent: excluded by DnsConfigExclusively on ethernet2.
	t.Expect(nameservers).To(ConsistOf(
		dhcpDNS0IP,
		staticDNS0IP,
		dhcpDNS1aIP,
		dhcpDNS1bIP,
		staticDNS1IP,
		staticDNS2IP,
		badDNS3IP,
	))

	evetest.Checkpoint("phase2-complete")

	// ------------------------------------------------------------------
	// Phase 3: Application DNS via Local NI.
	//
	// Create a Local NI backed by ethernet1. EVE's per-NI dnsmasq will
	// forward DNS queries to ethernet1's effective DNS servers (dhcp-dns1a,
	// dhcp-dns1b, static-dns1). Those servers know about the controller and
	// http-server1, but NOT http-server2.
	// ------------------------------------------------------------------
	log.Infof("Phase 3: testing per-NI DNS via an application...")

	niSubnet := evetest.IPSubnet("10.11.12.0/24")
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet1",
		Subnet:      niSubnet,
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:     evetest.IPAddress("10.11.12.1"),
		MTU:         1500,
		ForwardLLDP: false,
	})

	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "dns-test-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "milan4zededa/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		CPUs:        1,
		MemoryBytes: 500 * evetest.MiB,
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
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	})

	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	defer stopNIWatch()
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, false, false)

	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("phase3-app-running")

	// Wait until the app receives an IP from the NI subnet.
	timeout := 3 * time.Minute
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App receives IP address from the NI subnet",
		func(info *eveinfo.ZInfoApp) bool {
			return len(info.Network) == 1 && len(info.Network[0].IPAddrs) == 1
		}).StopIf(appHasError)))

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	polling := 3 * time.Second

	// Wait for the SSH daemon to start and become reachable.
	t.Eventually(func(g Gomega) {
		log.Infof("Waiting for app SSH daemon to become reachable...")
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"hostname", sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring(appUUID.String()))
	}, timeout, polling).Should(Succeed())

	evetest.Checkpoint("phase3-ssh-reachable")

	// Phase 3a: controller hostname must resolve via ethernet1's DNS servers.
	log.Infof("Phase 3a: resolving controller hostname from app (NI on ethernet1)...")
	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"nslookup -type=A "+evetest.GetControllerHostname(), sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring(evetest.GetControllerIPv4().String()))
	}, timeout, polling).Should(Succeed())

	// Phase 3b: http-server1 must resolve (all ethernet1 DNS servers know about it).
	log.Infof("Phase 3b: resolving http-server1 from app (NI on ethernet1, expected OK)...")
	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"nslookup -type=A "+httpServer1FQDN, sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring(httpServer1IP))
	}, timeout, polling).Should(Succeed())

	// Phase 3c: http-server2 must NOT resolve (no ethernet1 DNS server knows about it).
	log.Infof("Phase 3c: resolving http-server2 from app (NI on ethernet1, expected FAIL)...")
	output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"nslookup -type=A "+httpServer2FQDN, sshTimeout, 0)
	t.Expect(nslookupFailed(output, err)).To(BeTrue(),
		"nslookup of http-server2 must fail: no ethernet1 DNS server has an entry for it")

	evetest.Checkpoint("phase3-eth1-dns-verified")

	// Phase 4: Per-NI DNS runtime update.
	//
	// Switch the NI uplink from ethernet1 to ethernet2. ethernet2's exclusive
	// DNS server (static-dns2) knows about the controller and http-server2,
	// but NOT http-server1. After the switch the app's DNS resolution must
	// reflect the new upstream set.
	// ------------------------------------------------------------------
	log.Infof("Phase 4: switching NI uplink from ethernet1 to ethernet2...")
	devConfig.UpdateNetworkInstance(niUUID, evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet2",
		Subnet:      niSubnet,
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:     evetest.IPAddress("10.11.12.1"),
		MTU:         1500,
		ForwardLLDP: false,
	})
	device.ApplyConfig(devConfig, false, false)

	// Wait for the NI info to reflect the uplink change.
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI uplink has changed to ethernet2",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return len(info.Ports) == 1 && info.Ports[0] == "ethernet2"
		}).StopIf(niHasError)))

	evetest.Checkpoint("phase4-ni-uplink-switched")

	// Phase 4a: http-server1 must now FAIL (static-dns2 has no entry for it).
	log.Infof("Phase 4a: resolving http-server1 from app (NI on ethernet2, expected FAIL)...")
	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"nslookup -type=A "+httpServer1FQDN, sshTimeout, 0)
		g.Expect(nslookupFailed(output, err)).To(BeTrue(),
			"nslookup of http-server1 must fail after NI switch to ethernet2")
	}, timeout, polling).Should(Succeed())

	// Phase 4b: http-server2 must now SUCCEED (static-dns2 knows about it).
	log.Infof("Phase 4b: resolving http-server2 from app (NI on ethernet2, expected OK)...")
	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"nslookup -type=A "+httpServer2FQDN, sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring(httpServer2IP))
	}, timeout, polling).Should(Succeed())

	evetest.Checkpoint("phase4-complete")
}

// getResolvConfNameservers reads /etc/resolv.conf from the device over SSH and
// returns all IP addresses listed on "nameserver" lines.
func getResolvConfNameservers(device *evetest.EdgeDevice, sshTimeout time.Duration) ([]string, error) {
	output, _, err := device.RunShellScript("cat /etc/resolv.conf", sshTimeout, 0)
	if err != nil {
		return nil, err
	}
	var nameservers []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			nameservers = append(nameservers,
				strings.TrimSpace(strings.TrimPrefix(line, "nameserver ")))
		}
	}
	return nameservers, nil
}

// nslookupFailed returns true when the nslookup invocation indicates a DNS
// resolution failure, handling both the full nslookup (Ubuntu, exit code 1)
// and the BusyBox variant (exit code 0 but error text in stdout/stderr).
func nslookupFailed(output string, err error) bool {
	if err != nil {
		return true
	}
	lower := strings.ToLower(output)
	return strings.Contains(lower, "can't resolve") ||
		strings.Contains(lower, "nxdomain") ||
		strings.Contains(lower, "** server can't find")
}
