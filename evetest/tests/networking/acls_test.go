// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const enableFlowlogParamKey = "ENABLE_FLOWLOG"

// TestLocalNetInstanceACLs verifies that per-VIF ACLs (ACEs) on a Local Network
// Instance correctly enforce allow-by-hostname, allow-by-IP+port, allow-by-protocol
// and implicit-deny rules, and that ACL changes take effect at runtime without
// redeploying the application.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port, DNS server, http-server.test
//     on port 80, http-server2.test on port 8080, and a server at netmodels.LongFQDN
//     on port 80. All three endpoints have static DNS entries in the SDN DNS server
//     and active HTTP listeners, so a blocked connection produces a TCP timeout
//     (SYN dropped by EVE), not a connection-refused -- which is how the test
//     distinguishes an ACL drop from a missing listener.
//
// Phases
// ------
//  1. Setup: one Local NI ("local-ni") on ethernet0, subnet 10.11.12.0/24,
//     EnableFlowlog controlled by the ENABLE_FLOWLOG parameter.
//     Two container apps (lfedge/evetest-ubuntu-ctr:1.0) deployed on the
//     same NI, each with a fixed MAC, an SSH port-forward (2222->22 and 2223->22),
//     and distinct ACL rule sets:
//     - acl-app-1: allow FQDN "http-server.test", allow FQDN netmodels.LongFQDN,
//     allow ICMP to the NI gateway /32.
//     - acl-app-2: allow TCP to http-server2's /32 on port 8080,
//     allow FQDN netmodels.LongFQDN.
//     Wait until both apps reach RUNNING and the NI reaches ONLINE. Wait until
//     NetworkInstanceInfo reports both VIFs with IP assignments.
//  2. acl-app-1 traffic checks (via RunShellScriptInsideApp over the 2222->22
//     port-forward):
//     - curl http://http-server.test/helloworld returns "Hello world!" (hostname
//     ACE allows the flow).
//     - curl http://http-server2.test:8080/helloworld fails with a timeout
//     (~5 s elapsed), not a refused connection -- proves EVE drops the SYN.
//     - ping to the NI gateway succeeds (ICMP+/32 ACE).
//     - curl http://<netmodels.LongFQDN>/helloworld returns the expected body
//     (long-FQDN hostname ACE works end-to-end through dnsmasq and iptables).
//  3. acl-app-2 traffic checks (via 2223->22 port-forward):
//     - curl http://http-server2.test:8080/helloworld returns "Hello world from
//     http-server2!" (TCP+IP+port ACE allows the flow).
//     - curl http://http-server.test/helloworld fails with a timeout (~5 s),
//     symmetric proof of implicit deny on EVE's egress path.
//     - curl http://<netmodels.LongFQDN>/helloworld succeeds (long-FQDN ACE
//     is enforced independently per app; no state bleed between apps).
//  4. Cross-app traffic check: ping from acl-app-1 to acl-app-2's NI IP fails,
//     confirming the implicit deny applies within the same Local NI.
//  5. Runtime ACL update: add an allow ACE for "http-server2.test" to acl-app-1
//     via UpdateApplication + ApplyConfig (no app redeploy). Poll until curl from
//     acl-app-1 to http-server2.test:8080 succeeds.
//  6. Teardown: delete both apps and the NI; verify clean removal via
//     WatchAppInfo (INVALID) and WatchNetworkInstanceInfo (UNSPECIFIED).
//
// Test params
// -----------
//   - HYPERVISOR. The test calls evetest.SkipIfHypervisorKubevirt() -- Kubevirt
//     is reserved for cluster tests.
//   - ENABLE_FLOWLOG: enable flow logging on the Local NI (default: false).
func TestLocalNetInstanceACLs(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TestParameterDefinition{
			Key:          enableFlowlogParamKey,
			DefaultValue: false,
			Description: evetest.TestParameterDescription{
				Summary: "Enable flow logging on the Local NI",
				Default: "false",
			},
		},
	)

	hypervisor := evetest.GetHypervisorParameterValue()
	evetest.SkipIfHypervisorKubevirt()
	enableFlowlog := evetest.GetTestParameter[bool](enableFlowlogParamKey)

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
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)

	const (
		niGateway   = "10.11.12.1"
		app1MACAddr = "02:16:3e:00:00:01"
		app2MACAddr = "02:16:3e:00:00:02"
	)

	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:       evetest.IPAddress(niGateway),
		EnableFlowlog: enableFlowlog,
		MTU:           1500,
		ForwardLLDP:   false,
	})

	app1ACLRules := []evetest.ACLAllowRule{
		{
			Protocol:       evetest.NetworkProtocolAny,
			RemoteHostname: "http-server.test",
		},
		{
			Protocol:       evetest.NetworkProtocolAny,
			RemoteHostname: netmodels.LongFQDN,
		},
		{
			Protocol:     evetest.NetworkProtocolICMP,
			RemoteSubnet: evetest.IPSubnet(niGateway + "/32"),
		},
	}
	app1UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "acl-app-1",
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
				MAC:                 evetest.MACAddress(app1MACAddr),
				PortFwdRules: []evetest.PortFwdRule{
					{Protocol: evetest.NetworkProtocolTCP, EdgeNodePort: 2222, AppPort: 22},
				},
				ACLAllowRules: app1ACLRules,
			},
		},
	})

	app2ACLRules := []evetest.ACLAllowRule{
		// IP+port match: allow TCP to http-server2 on port 8080 only.
		{
			Protocol:     evetest.NetworkProtocolTCP,
			RemoteSubnet: evetest.IPSubnet("10.18.18.25/32"),
			RemotePort:   8080,
		},
		{
			Protocol:       evetest.NetworkProtocolAny,
			RemoteHostname: netmodels.LongFQDN,
		},
	}
	app2UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "acl-app-2",
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
				MAC:                 evetest.MACAddress(app2MACAddr),
				PortFwdRules: []evetest.PortFwdRule{
					{Protocol: evetest.NetworkProtocolTCP, EdgeNodePort: 2223, AppPort: 22},
				},
				ACLAllowRules: app2ACLRules,
			},
		},
	})

	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	app1Updates, stopApp1Watch := device.WatchAppInfo(app1UUID)
	app2Updates, stopApp2Watch := device.WatchAppInfo(app2UUID)
	device.ApplyConfig(devConfig, false, false)

	timeout := 5 * time.Minute
	timeoutExcludingDownload := 5 * time.Minute

	// Wait for the NI to come online.
	var niInfo *eveinfo.ZInfoNetworkInstance
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI state is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))

	device.WaitUntilAppIsRunning(app1UUID, timeoutExcludingDownload)
	device.WaitUntilAppIsRunning(app2UUID, timeoutExcludingDownload)
	evetest.Checkpoint("apps-running")

	// Wait for the NI to report both VIFs with IP assignments.
	// Also capture acl-app-2's NI IP for the cross-app ping check.
	var app2NiIP string
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI reports both VIFs with IP assignments",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			if len(niInfo.Vifs) < 2 {
				return false
			}
			var app1IPFound bool
			for _, assignment := range niInfo.IpAssignments {
				switch assignment.MacAddress {
				case app1MACAddr:
					app1IPFound = len(assignment.IpAddress) > 0
				case app2MACAddr:
					if len(assignment.IpAddress) > 0 {
						app2NiIP = assignment.IpAddress[0]
					}
				}
			}
			return app1IPFound && app2NiIP != ""
		}).StopIf(niHasError)))
	t.Expect(niInfo.Vifs).To(HaveLen(2))

	evetest.Checkpoint("apps-with-ips")

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	// Longer timeout for commands that are expected to time out on the ACL boundary
	// (curl --max-time 5 + SSH overhead).
	blockedCurlTimeout := 30 * time.Second
	polling := 3 * time.Second
	log := evetest.Logger()

	// Wait for both app SSH daemons to become reachable via port-forwarding.
	t.Eventually(func(t Gomega) {
		log.Infof("Waiting for acl-app-1 SSH daemon...")
		_, _, err := device.RunShellScriptInsideApp(
			app1UUID, appAuth, "hostname", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
	}, timeout, polling).Should(Succeed())

	t.Eventually(func(t Gomega) {
		log.Infof("Waiting for acl-app-2 SSH daemon...")
		_, _, err := device.RunShellScriptInsideApp(
			app2UUID, appAuth, "hostname", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
	}, timeout, polling).Should(Succeed())

	evetest.Checkpoint("ssh-ready")

	// === acl-app-1 ACL assertions ===

	log.Infof("Testing acl-app-1: allowed traffic to http-server.test")
	out, _, err := device.RunShellScriptInsideApp(app1UUID, appAuth,
		"curl -sS --max-time 15 http://http-server.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("Hello world!"))

	log.Infof("Testing acl-app-1: blocked traffic to http-server2.test:8080 (implicit deny)")
	// http-server2 IS listening on 8080, so the failure must be a TCP timeout
	// (ACL drops the SYN), not a connection refused (no listener).
	start := time.Now()
	_, _, err = device.RunShellScriptInsideApp(app1UUID, appAuth,
		"curl --max-time 5 http://http-server2.test:8080/helloworld", blockedCurlTimeout, 0)
	elapsed := time.Since(start)
	t.Expect(err).To(HaveOccurred())
	t.Expect(elapsed).To(BeNumerically(">=", 4*time.Second),
		"curl should time out (~5 s), not fail instantly with connection refused")

	log.Infof("Testing acl-app-1: ICMP to NI gateway allowed")
	_, _, err = device.RunShellScriptInsideApp(app1UUID, appAuth,
		fmt.Sprintf("ping -c 3 -W 1 %s", niGateway), sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())

	log.Infof("Testing acl-app-1: allowed traffic to long FQDN server")
	out, _, err = device.RunShellScriptInsideApp(app1UUID, appAuth,
		fmt.Sprintf("curl -sS --max-time 15 http://%s/helloworld", netmodels.LongFQDN),
		sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("Hello world from long-fqdn-server!"))

	// === acl-app-2 ACL assertions ===

	log.Infof("Testing acl-app-2: allowed traffic to http-server2.test:8080")
	out, _, err = device.RunShellScriptInsideApp(app2UUID, appAuth,
		"curl -sS --max-time 15 http://http-server2.test:8080/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("Hello world from http-server2!"))

	log.Infof("Testing acl-app-2: blocked traffic to http-server.test (implicit deny)")
	// http-server IS listening on 80, so the failure must be a TCP timeout.
	start = time.Now()
	_, _, err = device.RunShellScriptInsideApp(app2UUID, appAuth,
		"curl --max-time 5 http://http-server.test/helloworld", blockedCurlTimeout, 0)
	elapsed = time.Since(start)
	t.Expect(err).To(HaveOccurred())
	t.Expect(elapsed).To(BeNumerically(">=", 4*time.Second),
		"curl should time out (~5 s), not fail instantly with connection refused")

	log.Infof("Testing acl-app-2: allowed traffic to long FQDN server")
	out, _, err = device.RunShellScriptInsideApp(app2UUID, appAuth,
		fmt.Sprintf("curl -sS --max-time 15 http://%s/helloworld", netmodels.LongFQDN),
		sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("Hello world from long-fqdn-server!"))

	// === Cross-app traffic: ping from acl-app-1 to acl-app-2's NI IP must fail ===

	log.Infof("Testing cross-app traffic (must be blocked)")
	_, _, err = device.RunShellScriptInsideApp(app1UUID, appAuth,
		fmt.Sprintf("ping -c 3 -W 1 %s", app2NiIP), sshTimeout, 0)
	t.Expect(err).To(HaveOccurred())

	// === Runtime ACL update: add allow for http-server2.test on acl-app-1 ===

	log.Infof(
		"Applying runtime ACL update on acl-app-1: adding allow for http-server2.test")
	updatedApp1ACLRules := append(app1ACLRules, evetest.ACLAllowRule{
		Protocol:       evetest.NetworkProtocolAny,
		RemoteHostname: "http-server2.test",
	})
	devConfig.UpdateApplication(app1UUID, evetest.ApplicationInstanceConfig{
		DisplayName: "acl-app-1",
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
				MAC:                 evetest.MACAddress(app1MACAddr),
				PortFwdRules: []evetest.PortFwdRule{
					{Protocol: evetest.NetworkProtocolTCP, EdgeNodePort: 2222, AppPort: 22},
				},
				ACLAllowRules: updatedApp1ACLRules,
			},
		},
	})
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("acl-update-applied")

	// Poll until the new ACL takes effect and the curl succeeds.
	t.Eventually(func(t Gomega) {
		log.Infof("Waiting for updated ACL to allow http-server2.test:8080 from acl-app-1...")
		out, _, err = device.RunShellScriptInsideApp(app1UUID, appAuth,
			"curl -sS --max-time 15 http://http-server2.test:8080/helloworld", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(out).To(ContainSubstring("Hello world from http-server2!"))
	}, timeout, polling).Should(Succeed())

	// === Teardown ===

	devConfig.DeleteApplication(app1UUID)
	devConfig.DeleteApplication(app2UUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(app1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"acl-app-1 state is INVALID",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))
	stopApp1Watch()

	t.Eventually(app2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"acl-app-2 state is INVALID",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))
	stopApp2Watch()

	evetest.Checkpoint("apps-deleted")

	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI has no VIFs attached",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return len(niInfo.Vifs) == 0
		}).StopIf(niHasError)))

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

// TestSwitchNetInstanceACLs verifies that per-VIF ACLs (ACEs) on a Switch Network
// Instance correctly enforce allow-by-IP, allow-by-IP+port, and implicit-deny rules,
// and that ACL changes take effect at runtime without redeploying the application.
// Because switch NIs do not run a per-NI DNS resolver, all ACL matching is IP-based.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port. The SDN-side DHCP server and
//     DNS resolver are shared by apps bridged into the same L2 segment. HTTP servers
//     are at fixed IPs: http-server.test=10.17.17.25:80 and
//     http-server2.test=10.18.18.25:8080. Both listeners are up during the test, so
//     a blocked connection produces a TCP timeout (SYN dropped by EVE), not a
//     connection-refused -- which is how the test distinguishes an ACL drop from a
//     missing listener.
//
// Phases
// ------
//  1. Setup: one Switch NI ("switch-ni") on ethernet0.
//     Two container apps (lfedge/evetest-ubuntu-ctr:1.0) bridged into the same
//     SDN L2 segment (172.20.20.0/24), each with a fixed MAC and distinct ACL rules:
//     - acl-app-1: allow TCP to 10.17.17.25/32 (http-server) on port 80; allow TCP
//     from 172.20.20.1/32 to cover inbound SSH. The SDN SNAT's connections from
//     outside the 172.20.20.0/24 segment to its gateway IP (172.20.20.1) before
//     bridging them in, so the ACL must match 172.20.20.1, not the test framework's
//     real IP.
//     - acl-app-2: allow TCP to 10.18.18.25/32 (http-server2) on port 8080; allow
//     TCP from 172.20.20.1/32 (SSH inbound, same SNAT reasoning).
//     Wait until both apps reach RUNNING and the NI reaches ONLINE. Wait until
//     NetworkInstanceInfo reports both VIFs with IP assignments (learned via DHCP
//     snooping); capture acl-app-2's VIF IP for the cross-app ping assertion.
//  2. acl-app-1 traffic checks (via RunShellScriptInsideApp using the VIF IP):
//     - curl http://http-server.test/helloworld returns "Hello world!" (IP+port ACE
//     allows the flow; DNS resolution uses the SDN DNS server).
//     - curl http://http-server2.test:8080/helloworld fails with a timeout (~5 s
//     elapsed), not a refused connection -- proves EVE drops the SYN.
//     - ping to acl-app-2's VIF IP fails (no ACE allows L2-forwarded ICMP between
//     apps in the same Switch NI).
//  3. acl-app-2 traffic checks (via the VIF IP):
//     - curl http://http-server2.test:8080/helloworld succeeds (IP+port ACE allows
//     the flow).
//     - curl http://http-server.test/helloworld fails with a timeout (~5 s), symmetric
//     proof of implicit deny.
//  4. Runtime ACL update: add an allow ACE for TCP to 10.18.18.25/32 (http-server2)
//     on port 8080 to acl-app-1 via UpdateApplication + ApplyConfig (no app redeploy).
//     Poll until curl from acl-app-1 to http-server2.test:8080 succeeds.
//  5. Teardown: delete both apps and the NI; verify clean removal via WatchAppInfo
//     (INVALID) and WatchNetworkInstanceInfo (UNSPECIFIED).
//
// Test params
// -----------
//   - HYPERVISOR. The test calls evetest.SkipIfHypervisorKubevirt() -- Kubevirt is
//     reserved for cluster tests.
//   - ENABLE_FLOWLOG: enable flow logging on the Switch NI (default: false).
func TestSwitchNetInstanceACLs(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TestParameterDefinition{
			Key:          enableFlowlogParamKey,
			DefaultValue: false,
			Description: evetest.TestParameterDescription{
				Summary: "Enable flow logging on the Switch NI",
				Default: "false",
			},
		},
	)

	hypervisor := evetest.GetHypervisorParameterValue()
	evetest.SkipIfHypervisorKubevirt()
	enableFlowlog := evetest.GetTestParameter[bool](enableFlowlogParamKey)

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
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)

	const (
		app1MACAddr = "02:16:3e:00:00:03"
		app2MACAddr = "02:16:3e:00:00:04"
	)

	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName:   "switch-ni",
		Port:          "ethernet0",
		EnableFlowlog: enableFlowlog,
		MTU:           1500,
		ForwardLLDP:   false,
	})

	// Allow inbound SSH; the SDN SNAT's external connections to the gateway IP
	// (172.20.20.1) before forwarding them into the switch NI's L2 segment.
	sshFromFramework := evetest.ACLAllowRule{
		Protocol:     evetest.NetworkProtocolTCP,
		RemoteSubnet: evetest.IPSubnet("172.20.20.1/32"),
	}

	app1ACLRules := []evetest.ACLAllowRule{
		{
			Protocol:     evetest.NetworkProtocolTCP,
			RemoteSubnet: evetest.IPSubnet("10.17.17.25/32"),
			RemotePort:   80,
		},
		sshFromFramework,
	}
	app1UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "acl-app-1",
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
				MAC:                 evetest.MACAddress(app1MACAddr),
				ACLAllowRules:       app1ACLRules,
			},
		},
	})

	app2ACLRules := []evetest.ACLAllowRule{
		{
			Protocol:     evetest.NetworkProtocolTCP,
			RemoteSubnet: evetest.IPSubnet("10.18.18.25/32"),
			RemotePort:   8080,
		},
		sshFromFramework,
	}
	app2UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "acl-app-2",
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
				MAC:                 evetest.MACAddress(app2MACAddr),
				ACLAllowRules:       app2ACLRules,
			},
		},
	})

	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	app1Updates, stopApp1Watch := device.WatchAppInfo(app1UUID)
	app2Updates, stopApp2Watch := device.WatchAppInfo(app2UUID)
	device.ApplyConfig(devConfig, false, false)

	timeout := 5 * time.Minute
	timeoutExcludingDownload := 5 * time.Minute

	var niInfo *eveinfo.ZInfoNetworkInstance
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI state is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		})))

	device.WaitUntilAppIsRunning(app1UUID, timeoutExcludingDownload)
	device.WaitUntilAppIsRunning(app2UUID, timeoutExcludingDownload)
	evetest.Checkpoint("apps-running")

	// Wait for both VIFs with IP assignments (learned via DHCP snooping).
	// Capture app2VifIP for the cross-app ping assertion.
	var app1VifIP, app2VifIP string
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI reports both VIFs with IP assignments",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			if len(niInfo.Vifs) < 2 {
				return false
			}
			for _, assignment := range niInfo.IpAssignments {
				switch assignment.MacAddress {
				case app1MACAddr:
					if len(assignment.IpAddress) > 0 {
						app1VifIP = assignment.IpAddress[0]
					}
				case app2MACAddr:
					if len(assignment.IpAddress) > 0 {
						app2VifIP = assignment.IpAddress[0]
					}
				}
			}
			return app1VifIP != "" && app2VifIP != ""
		}).StopIf(niHasError)))
	t.Expect(niInfo.Vifs).To(HaveLen(2))
	evetest.Checkpoint("apps-with-ips")

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	// Longer timeout for commands expected to time out at the ACL boundary
	// (curl --max-time 5 + SSH overhead).
	blockedCurlTimeout := 30 * time.Second
	polling := 3 * time.Second
	log := evetest.Logger()

	t.Eventually(func(t Gomega) {
		log.Infof("Waiting for acl-app-1 SSH daemon...")
		_, _, err := device.RunShellScriptInsideApp(
			app1UUID, appAuth, "hostname", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
	}, timeout, polling).Should(Succeed())

	t.Eventually(func(t Gomega) {
		log.Infof("Waiting for acl-app-2 SSH daemon...")
		_, _, err := device.RunShellScriptInsideApp(
			app2UUID, appAuth, "hostname", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
	}, timeout, polling).Should(Succeed())

	evetest.Checkpoint("ssh-ready")

	// === acl-app-1 ACL assertions ===

	log.Infof("Testing acl-app-1: allowed traffic to http-server.test")
	out, _, err := device.RunShellScriptInsideApp(app1UUID, appAuth,
		"curl -sS --max-time 15 http://http-server.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("Hello world!"))

	log.Infof("Testing acl-app-1: blocked traffic to http-server2.test:8080 (implicit deny)")
	// http-server2 IS listening on 8080, so the failure must be a TCP timeout
	// (ACL drops the SYN), not a connection refused (no listener).
	start := time.Now()
	_, _, err = device.RunShellScriptInsideApp(app1UUID, appAuth,
		"curl --max-time 5 http://http-server2.test:8080/helloworld", blockedCurlTimeout, 0)
	elapsed := time.Since(start)
	t.Expect(err).To(HaveOccurred())
	t.Expect(elapsed).To(BeNumerically(">=", 4*time.Second),
		"curl should time out (~5 s), not fail instantly with connection refused")

	log.Infof("Testing acl-app-1: cross-app ping to acl-app-2 blocked")
	_, _, err = device.RunShellScriptInsideApp(app1UUID, appAuth,
		fmt.Sprintf("ping -c 3 -W 1 %s", app2VifIP), sshTimeout, 0)
	t.Expect(err).To(HaveOccurred())

	// === acl-app-2 ACL assertions ===

	log.Infof("Testing acl-app-2: allowed traffic to http-server2.test:8080")
	out, _, err = device.RunShellScriptInsideApp(app2UUID, appAuth,
		"curl -sS --max-time 15 http://http-server2.test:8080/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("Hello world from http-server2!"))

	log.Infof("Testing acl-app-2: blocked traffic to http-server.test (implicit deny)")
	// http-server IS listening on 80, so the failure must be a TCP timeout.
	start = time.Now()
	_, _, err = device.RunShellScriptInsideApp(app2UUID, appAuth,
		"curl --max-time 5 http://http-server.test/helloworld", blockedCurlTimeout, 0)
	elapsed = time.Since(start)
	t.Expect(err).To(HaveOccurred())
	t.Expect(elapsed).To(BeNumerically(">=", 4*time.Second),
		"curl should time out (~5 s), not fail instantly with connection refused")

	// === Runtime ACL update: add http-server2 allow rule to acl-app-1 ===

	log.Infof(
		"Applying runtime ACL update: allowing acl-app-1 to reach http-server2.test:8080")
	updatedApp1ACLRules := append(app1ACLRules, evetest.ACLAllowRule{
		Protocol:     evetest.NetworkProtocolTCP,
		RemoteSubnet: evetest.IPSubnet("10.18.18.25/32"),
		RemotePort:   8080,
	})
	devConfig.UpdateApplication(app1UUID, evetest.ApplicationInstanceConfig{
		DisplayName: "acl-app-1",
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
				MAC:                 evetest.MACAddress(app1MACAddr),
				ACLAllowRules:       updatedApp1ACLRules,
			},
		},
	})
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("acl-update-applied")

	t.Eventually(func(t Gomega) {
		log.Infof("Waiting for updated ACL to allow acl-app-1 to reach http-server2.test:8080...")
		out, _, err = device.RunShellScriptInsideApp(app1UUID, appAuth,
			"curl -sS --max-time 15 http://http-server2.test:8080/helloworld", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(out).To(ContainSubstring("Hello world from http-server2!"))
	}, timeout, polling).Should(Succeed())

	// === Teardown ===

	devConfig.DeleteApplication(app1UUID)
	devConfig.DeleteApplication(app2UUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(app1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"acl-app-1 state is INVALID",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))
	stopApp1Watch()

	t.Eventually(app2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"acl-app-2 state is INVALID",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))
	stopApp2Watch()

	evetest.Checkpoint("apps-deleted")

	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI has no VIFs attached",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return len(niInfo.Vifs) == 0
		}).StopIf(niHasError)))

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
