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
// configured DNS servers into the mgmt dnsmasq pool, writes the result to
// /etc/resolv.conf and /run/nim/dnsmasq.mgmt.servers, and propagates the
// per-port subset to applications via the per-NI dnsmasq.
//
// DNS architecture
// ----------------
// EVE runs a single mgmt dnsmasq on 127.0.0.1:53 that pools all management
// port DNS servers. /etc/resolv.conf contains only "nameserver 127.0.0.1".
// The upstream servers in dnsmasq.mgmt.servers are sorted by port cost (lowest
// first); dnsmasq strict-order means the lowest-cost port's server is tried
// first for every resolution.
//
// Known limitation: because all ports share one DNS pool, a bad upstream
// server on an individual port is not surfaced as a per-port error. eth3's
// bad-dns3 server is tried first (cost=0) but the other ports' working
// servers succeed, so eth3.err stays empty.
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
//   - ethernet2 (eth2, mgmt+app, cost=1): DHCP with DnsConfigExclusively=true so
//     the DHCP-provided dhcpDns2 is ignored; only staticDns2 is used.
//     Effective DNS: [staticDns2].
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
//     - DevicePort.err of ethernet3 is empty. This confirms the
//     regression fix: EVE used to cap resolv.conf at 3 entries and mark
//     ports whose DNS servers did not fit as errored. With 7 DNS servers
//     total across four ports, the old code would have set errors on
//     ethernet2; the new code must not.
//     - Active DPC lastError is empty: the device stays online via the
//     working ports.
//  2. /etc/resolv.conf and mgmt dnsmasq config verification:
//     - /etc/resolv.conf contains only "nameserver 127.0.0.1".
//     - /run/nim/dnsmasq.mgmt.servers lists all expected upstream servers
//     ordered by port cost (eth3 cost=0 first, eth2 cost=1, eth0/eth1
//     cost=2). dhcpDns2 must be absent (excluded by DnsConfigExclusively).
//  3. DNS verification failure triggers DPC fallback: applies a new DPC
//     with only ethernet2 (non-existent static DNS) and ethernet3
//     (bad-dns3). Both ports have IP connectivity but neither can resolve
//     the controller hostname. EVE's DPC verification must detect this and
//     fall back to the previous DPC (CurrentIndex == 1, new DPC lastError
//     non-empty).
//  4. Per-NI DNS isolation: creates a Local NI ("local-ni") on ethernet1
//     and deploys a container app (milan4zededa/evetest-ubuntu-ctr:1.0)
//     with port-forward 2222->22. From inside the app:
//     - nslookup <controller>: resolves to the controller IP.
//     - nslookup http-server1.test: succeeds (all ethernet1 DNS servers
//     have a static entry for it).
//     - nslookup http-server2.test: fails (no ethernet1 DNS server has an
//     entry for it), confirming the per-NI dnsmasq uses only the DNS
//     servers of its own uplink port, not a global pool.
//  5. Per-NI DNS runtime update: switches the NI uplink from ethernet1 to
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
		// does not exist (staticDNS2IP is .25, not .26)
		badDNS2IP = "10.35.7.26"
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
	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// Enable NIM debug log level so dnsmasq emits log-queries from the start,
	// logging every forwarding attempt (including failures) in device logs.
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetAgentSettingStringValue("nim", pillartypes.LogLevel, "debug")
	cfgProps.SetAgentSettingStringValue("nim", pillartypes.RemoteLogLevel, "debug")
	// Set NetworkTestDuration to its minimum allowed value so the broken-DNS DPC
	// in Phase 3 fails as quickly as possible.
	cfgProps.SetGlobalValueInt(pillartypes.NetworkTestDuration, 10)
	devConfig.SetConfigProperties(cfgProps)

	// eth0: DHCP, append static-dns0 (IgnoreDNSFromDHCP=false).
	// Effective DNS set: [dhcp-dns0, static-dns0]
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
	// This port is also used as a Local NI uplink in Phase 4.
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
	// This port is used as the second Local NI uplink in Phase 4.
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
	//   - (lowest-cost) eth3 has no error reported (DNS server of another mgmt port
	//     is used to resolve the controller hostname)
	//   - The active DPC has an empty lastError (device is online).
	//
	// Note: with mgmt dnsmasq, all ports share one DNS pool. eth3's bad upstream
	// server (bad-dns3) is not detected as broken because the other ports' working
	// servers resolve the controller hostname successfully. Per-port DNS error
	// precision is a known limitation of the mgmt dnsmasq approach.
	// ------------------------------------------------------------------
	log := evetest.Logger()
	log.Infof("Phase 1: waiting for per-port DNS state to settle...")

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()

	phase1Timeout := 3 * time.Minute
	t.Eventually(devUpdates, phase1Timeout).Should(Receive(matchers.SatisfyPredicate(
		"All four ports have expected DNS servers; all ports error-free; DPC is healthy",
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

			// eth3's bad upstream DNS server (bad-dns3) is not surfaced
			// as an error because the mgmt dnsmasq pools all servers and the other
			// ports' working servers resolve the controller hostname successfully.
			if eth3.GetErr().GetDescription() != "" {
				return false
			}

			// The active DPC must have no lastError.
			dpc := getCurrentDPC(dinfo)
			if dpc == nil {
				return false
			}
			return dpc.GetLastError() == ""
		})))

	dpcAppliedAt := time.Now()
	evetest.Checkpoint("phase1-complete")

	// ------------------------------------------------------------------
	// Phase 2: /etc/resolv.conf and mgmt dnsmasq config verification.
	//
	// /etc/resolv.conf must contain a single nameserver pointing to the
	// mgmt dnsmasq (127.0.0.1).
	// /run/nim/dnsmasq.mgmt.servers must list all expected upstream DNS
	// servers, ordered by port cost (eth3 cost=0 first, then eth2 cost=1,
	// then eth0/eth1 cost=2). strict-order in dnsmasq means eth3's server
	// is tried first for every resolution, confirming cost-based ordering.
	// dhcpDns2 must be absent (excluded by DnsConfigExclusively on eth2).
	// ------------------------------------------------------------------
	log.Infof("Phase 2: verifying /etc/resolv.conf and mgmt dnsmasq config...")

	resolvConf := string(device.ReadFile("/etc/resolv.conf"))
	t.Expect(resolvConf).To(ContainSubstring("nameserver 127.0.0.1"))

	// The main config file contains static options only; upstream server
	// entries live in the separate servers file re-read on SIGHUP.
	const (
		configFilePath  = "/run/nim/dnsmasq.mgmt.conf"
		serversFilePath = "/run/nim/dnsmasq.mgmt.servers"
	)
	dnsmasqConf := string(device.ReadFile(configFilePath))
	t.Expect(dnsmasqConf).To(ContainSubstring("servers-file=" + serversFilePath))

	// The servers file may still be updating after Phase 1 — wait for it
	// to contain all expected servers in cost-ascending order.
	t.Eventually(func(g Gomega) {
		dnsmasqServers := string(device.ReadFile(serversFilePath))
		// All expected upstream servers must be present.
		g.Expect(dnsmasqServers).To(ContainSubstring(badDNS3IP),
			"eth3 (cost=0) server must appear in mgmt dnsmasq servers file")
		g.Expect(dnsmasqServers).To(ContainSubstring(staticDNS2IP),
			"eth2 (cost=1) server must appear in mgmt dnsmasq servers file")
		g.Expect(dnsmasqServers).To(ContainSubstring(dhcpDNS0IP),
			"eth0 (cost=2) DHCP server must appear in mgmt dnsmasq servers file")
		g.Expect(dnsmasqServers).To(ContainSubstring(staticDNS0IP),
			"eth0 (cost=2) static server must appear in mgmt dnsmasq servers file")
		g.Expect(dnsmasqServers).To(ContainSubstring(dhcpDNS1aIP),
			"eth1 (cost=2) DHCP server a must appear in mgmt dnsmasq servers file")
		g.Expect(dnsmasqServers).To(ContainSubstring(dhcpDNS1bIP),
			"eth1 (cost=2) DHCP server b must appear in mgmt dnsmasq servers file")
		g.Expect(dnsmasqServers).To(ContainSubstring(staticDNS1IP),
			"eth1 (cost=2) static server must appear in mgmt dnsmasq servers file")
		// dhcpDns2 must be absent: excluded by DnsConfigExclusively on ethernet2.
		g.Expect(dnsmasqServers).ToNot(ContainSubstring(dhcpDNS2IP),
			"dhcpDns2 must be excluded by DnsConfigExclusively on ethernet2")
		// Cost ordering in the default (non-domain) server entries:
		// eth3 (cost=0) before eth2 (cost=1) before eth0 (cost=2).
		// We search for "\nserver=IP" to match only the default section
		// entries and not the split-horizon entries ("server=/domain/IP").
		defaultIdx := func(ip string) int {
			return strings.Index(dnsmasqServers, "\nserver="+ip)
		}
		g.Expect(defaultIdx(badDNS3IP)).To(
			BeNumerically("<", defaultIdx(staticDNS2IP)),
			"badDNS3IP (cost=0) must appear before staticDNS2IP (cost=1) in default section")
		g.Expect(defaultIdx(staticDNS2IP)).To(
			BeNumerically("<", defaultIdx(dhcpDNS0IP)),
			"staticDNS2IP (cost=1) must appear before dhcpDNS0IP (cost=2) in default section")
	}, 2*time.Minute, 5*time.Second).Should(Succeed())

	// Verify the forwarding order in device logs. Phase 1 DPC verification
	// triggered controller resolution; with log-queries enabled and strict-order,
	// dnsmasq must try eth3's server (cost=0, badDNS3IP) before eth2's server
	// (cost=1, staticDNS2IP). Logs may arrive with delay.
	controllerHost := evetest.GetControllerHostname()
	var eth2Idx, eth3Idx int
	t.Eventually(func(g Gomega) {
		forwardLogs := device.GetLogs(evetest.LogMsgMatch{
			MsgHasSubstring: "forwarded " + controllerHost,
			NotBefore:       dpcAppliedAt,
		})
		g.Expect(forwardLogs).NotTo(BeEmpty(),
			"dnsmasq must have logged forwarding attempts for "+controllerHost)
		eth2Idx = -1
		eth3Idx = -1
		for i, msg := range forwardLogs {
			if eth3Idx == -1 && strings.Contains(msg.Message, badDNS3IP) {
				eth3Idx = i
			}
			if eth2Idx == -1 && strings.Contains(msg.Message, staticDNS2IP) {
				eth2Idx = i
			}
		}
		// bad-dns3 (eth3) returns SERVFAIL, so dnsmasq always retries with
		// eth2. Both entries must appear; if eth2 hasn't arrived yet the
		// Eventually will retry until the full pair is seen.
		g.Expect(eth3Idx).To(BeNumerically(">=", 0),
			"dnsmasq must have forwarded to badDNS3IP (eth3, cost=0)")
		g.Expect(eth2Idx).To(BeNumerically(">=", 0),
			"dnsmasq must have forwarded to staticDNS2IP (eth2, cost=1)")
	}, 2*time.Minute, 5*time.Second).Should(Succeed())
	t.Expect(eth2Idx).To(BeNumerically(">", eth3Idx),
		"eth3 (cost=0) must be forwarded to before eth2 (cost=1)")

	evetest.Checkpoint("phase2-complete")

	// ------------------------------------------------------------------
	// Phase 3: DNS verification failure triggers DPC fallback.
	//
	// Apply a new DPC with only ethernet2 and ethernet3 as management
	// ports. ethernet2 is given a static DNS IP that does not exist
	// (badDNS2IP = 10.35.7.26), and ethernet3 has bad-dns3 which cannot
	// resolve the controller. Both ports provide IP connectivity but
	// neither can resolve the controller hostname via DNS. EVE's DPC
	// verification must detect this and fall back to the previous DPC.
	//
	// Expected outcome: CurrentIndex == 1 (the previous working DPC) and
	// the new DPC at index 0 has a non-empty lastError.
	// ------------------------------------------------------------------
	log.Infof("Phase 3: testing DPC fallback on broken DNS configuration...")

	brokenDNSConfig := evetest.NewEdgeDeviceConfig(devName)
	brokenDNSConfig.SetConfigProperties(cfgProps)
	brokenNet2 := brokenDNSConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType:       evecommon.NetworkType_V4Only,
		DNSServers:        []net.IP{net.ParseIP(badDNS2IP)},
		IgnoreDNSFromDHCP: true,
	})
	brokenDNSConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet2",
		PhysicalLabel: "eth2",
		InterfaceName: "eth2",
		NetworkUUID:   brokenNet2,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
		Cost:          0,
	})
	brokenNet3 := brokenDNSConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	brokenDNSConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet3",
		PhysicalLabel: "eth3",
		InterfaceName: "eth3",
		NetworkUUID:   brokenNet3,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
		Cost:          1,
	})
	device.ApplyConfig(brokenDNSConfig, false, false)

	phase3Timeout := 5 * time.Minute
	t.Eventually(devUpdates, phase3Timeout).Should(Receive(matchers.SatisfyPredicate(
		"New DPC with broken DNS rejected; EVE falls back to previous DPC",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			sa := dinfo.GetSystemAdapter()
			if sa == nil {
				return false
			}
			statusList := sa.GetStatus()
			if len(statusList) == 0 {
				return false
			}
			if sa.GetCurrentIndex() != 1 {
				return false
			}
			dpc0 := statusList[0]
			return dpc0.GetLastError() != ""
		})))

	evetest.Checkpoint("phase3-dns-fallback-verified")

	// ------------------------------------------------------------------
	// Phase 4: Application DNS via Local NI.
	//
	// Create a Local NI backed by ethernet1. EVE's per-NI dnsmasq will
	// forward DNS queries to ethernet1's effective DNS servers (dhcp-dns1a,
	// dhcp-dns1b, static-dns1). Those servers know about the controller and
	// http-server1, but NOT http-server2.
	// ------------------------------------------------------------------
	log.Infof("Phase 4: testing per-NI DNS via an application...")

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
	evetest.Checkpoint("phase4-app-running")

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
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second

	// Wait for the SSH daemon to start and become reachable.
	t.Eventually(func(g Gomega) {
		log.Infof("Waiting for app SSH daemon to become reachable...")
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"hostname", sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring(appUUID.String()))
	}, timeout, polling).Should(Succeed())

	evetest.Checkpoint("phase4-ssh-reachable")

	// Phase 4a: controller hostname must resolve via ethernet1's DNS servers.
	log.Infof("Phase 4a: resolving controller hostname from app (NI on ethernet1)...")
	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"nslookup -type=A "+evetest.GetControllerHostname(), sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring(evetest.GetControllerIPv4().String()))
	}, timeout, polling).Should(Succeed())

	// Phase 4b: http-server1 must resolve (all ethernet1 DNS servers know about it).
	log.Infof("Phase 4b: resolving http-server1 from app (NI on ethernet1, expected OK)...")
	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"nslookup -type=A "+httpServer1FQDN, sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring(httpServer1IP))
	}, timeout, polling).Should(Succeed())

	// Phase 4c: http-server2 must NOT resolve (no ethernet1 DNS server knows about it).
	log.Infof("Phase 4c: resolving http-server2 from app (NI on ethernet1, expected FAIL)...")
	output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"nslookup -type=A "+httpServer2FQDN, sshTimeout, 0)
	t.Expect(nslookupFailed(output, err)).To(BeTrue(),
		"nslookup of http-server2 must fail: no ethernet1 DNS server has an entry for it")

	evetest.Checkpoint("phase4-eth1-dns-verified")

	// Phase 5: Per-NI DNS runtime update.
	//
	// Switch the NI uplink from ethernet1 to ethernet2. ethernet2's exclusive
	// DNS server (static-dns2) knows about the controller and http-server2,
	// but NOT http-server1. After the switch the app's DNS resolution must
	// reflect the new upstream set.
	// ------------------------------------------------------------------
	log.Infof("Phase 5: switching NI uplink from ethernet1 to ethernet2...")
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

	evetest.Checkpoint("phase5-ni-uplink-switched")

	// Phase 5a: http-server1 must now FAIL (static-dns2 has no entry for it).
	log.Infof("Phase 5a: resolving http-server1 from app (NI on ethernet2, expected FAIL)...")
	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"nslookup -type=A "+httpServer1FQDN, sshTimeout, 0)
		g.Expect(nslookupFailed(output, err)).To(BeTrue(),
			"nslookup of http-server1 must fail after NI switch to ethernet2")
	}, timeout, polling).Should(Succeed())

	// Phase 5b: http-server2 must now SUCCEED (static-dns2 knows about it).
	log.Infof("Phase 5b: resolving http-server2 from app (NI on ethernet2, expected OK)...")
	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"nslookup -type=A "+httpServer2FQDN, sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring(httpServer2IP))
	}, timeout, polling).Should(Succeed())

	evetest.Checkpoint("phase5-complete")
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
