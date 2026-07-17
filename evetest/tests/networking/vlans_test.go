// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	"google.golang.org/protobuf/proto"
)

// TestAccessVLANs verifies VLAN-aware Switch Network Instances: applications
// connected to the same Switch NI are isolated into different VLANs via
// access-port assignments, each VLAN gets its own DHCP-assigned subnet,
// cross-VLAN traffic is blocked by the bridge, and reassigning an application
// VIF to a different VLAN takes effect at runtime.
//
// Topology
// --------
//
//	                                                +-----------------+
//	                                                | eth0 (EVE mgmt) |---------------------
//	                                                |     (DHCP)      |                    |
//	                                                +-----------------+                    |
//	                     +-----------+                                                     |
//	                     |           |              +-------------------+      +------------------------+
//	                     |           |---<trunk>----| eth1 (app-shared) |------|         router         |
//	                     |           |              | (No IP, L2-only)  |      | (DHCP server per VLAN) |
//	                     | Switch NI |              +-------------------+      +------------------------+
//	                     |           |
//	+------+             |           |              +-------------------+      +---------------+
//	| app1 |--<VLAN 100>-|           |--<VLAN 100>--| eth2 (app-shared) |------| httpserver100 |
//	+------+             |           |              | (No IP, L2-only)  |      +---------------+
//	                     |           |              +-------------------+
//	+------+             |           |
//	| app2 |--<VLAN 200>-|           |              +-------------------+      +---------------+
//	+------+             |           |--<VLAN 200>--| eth3 (app-shared) |------| httpserver200 |
//	                     |           |              | (No IP, L2-only)  |      +---------------+
//	                     +-----------+              +-------------------+
//
// Network model
// -------------
//   - netmodels.ApplicationVLANs: eth0 is on its own management bridge with
//     DHCP and controller access (no VLANs on this path). eth1 connects to an
//     SDN router carrying two VLAN-tagged application networks: VLAN 100
//     (10.203.100.0/24) and VLAN 200 (10.203.200.0/24), each with its own DHCP
//     pool. eth2 and eth3 have no router — each is directly L2-connected to an
//     HTTP server in the corresponding VLAN's subnet (http-server-100.test at
//     10.203.100.10 on bridge2, http-server-200.test at 10.203.200.10 on
//     bridge3). The two servers serve distinct payloads so curl responses are
//     unambiguous.
//
// Device configuration
// --------------------
//   - ethernet0: DHCP, mgmt-only.
//   - ethernet1, ethernet2, ethernet3: L2-only (no DHCP client), all carrying
//     shared label "switch-ports".
//   - Switch NI "vlan-switch" with Port="switch-ports". VlanAccessPort entries:
//     ethernet2 → VLAN 100 (access port, PVID 100), ethernet3 → VLAN 200
//     (access port, PVID 200). ethernet1 has no VlanAccessPort entry and acts
//     as the trunk (carries both VLANs tagged toward the SDN router).
//   - Two container apps (lfedge/evetest-ubuntu-ctr:1.0):
//     app1 with AccessVLAN=100, app2 with AccessVLAN=200, each with an
//     allow-all ACL.
//
// Phases
// ------
//
//  1. DHCP and bridge filtering: both apps start running and the Switch NI
//     reaches ZNETINST_STATE_ONLINE with both VIFs visible. app1 receives an
//     IP from 10.203.100.0/24 via VLAN-100 DHCP; app2 from 10.203.200.0/24
//     via VLAN-200 DHCP. SSH to EVE confirms vlan_filtering=1 on the NI
//     bridge, and `bridge vlan show` shows PVID=100 on eth2 and the app1 VIF,
//     PVID=200 on eth3 and the app2 VIF, and both VLAN 100 and VLAN 200
//     present on eth1 (trunk).
//
//  2. VLAN isolation: from inside app1, curl to http-server-100.test succeeds
//     (bridge forwards VLAN-100 frames out eth2 → SDN bridge2 → server); curl
//     to http-server-200.test fails (eth3 is access-only for VLAN 200, no path
//     from VLAN 100 to bridge3); ping to app2's IP fails (different VLAN and
//     subnet, bridge VLAN-filters the traffic). Symmetric checks from app2:
//     http-server-200.test reachable, http-server-100.test and ping to app1
//     both fail.
//
//  3. Runtime VLAN reassignment: app1's VIF is updated to AccessVLAN=200 via
//     UpdateApplication. The changed interface triggers a purge that restarts
//     the app. Once running again, app1 receives an IP from 10.203.200.0/24.
//     curl to http-server-200.test succeeds; curl to http-server-100.test
//     fails. Ping from app1 to app2 succeeds (both now in VLAN 200).
//
// Test params
// -----------
//   - HYPERVISOR. The test calls evetest.SkipIfHypervisorKubevirt() right
//     after reading the parameter — Kubevirt is reserved for cluster tests.
func TestAccessVLANs(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(evetest.HypervisorParameter())
	hypervisor := evetest.GetHypervisorParameterValue()
	evetest.SkipIfHypervisorKubevirt()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.ApplicationVLANs,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// eth0: management port with DHCP for controller connectivity.
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
	})

	// eth1, eth2, eth3: L2-only app-shared ports for the Switch NI.
	noIPNet := devConfig.AddNetwork(evetest.NoIPNetworkConfig{})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		NetworkUUID:   noIPNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		SharedLabels:  []string{"switch-ports"},
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet2",
		PhysicalLabel: "eth2",
		InterfaceName: "eth2",
		NetworkUUID:   noIPNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		SharedLabels:  []string{"switch-ports"},
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet3",
		PhysicalLabel: "eth3",
		InterfaceName: "eth3",
		NetworkUUID:   noIPNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		SharedLabels:  []string{"switch-ports"},
	})
	device.ApplyConfig(devConfig, true, true)

	// Switch NI: eth1 is trunk (carries VLAN 100 and 200 tagged via the SDN router);
	// eth2 is access port for VLAN 100; eth3 is access port for VLAN 200.
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName:   "vlan-switch",
		Port:          "switch-ports",
		EnableFlowlog: false,
		VlanAccessPorts: []pillartypes.VlanAccessPort{
			{VlanID: 100, PortLabel: "ethernet2"},
			{VlanID: 200, PortLabel: "ethernet3"},
		},
	})

	// app1: VLAN 100. RunShellScriptInsideApp reaches it directly via the Switch NI IP.
	const app1MAC = "02:16:3e:00:00:01"
	app1Vif := evetest.VirtualNetworkAdapter{
		LogicalLabel:        "vif0",
		NetworkInstanceUUID: niUUID,
		MAC:                 evetest.MACAddress(app1MAC),
		AccessVLAN:          100,
		ACLAllowRules: []evetest.ACLAllowRule{
			{
				Protocol:     evetest.NetworkProtocolAny,
				RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
			},
		},
	}
	app1Config := evetest.ApplicationInstanceConfig{
		DisplayName: "vlan100-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters:    []evetest.AppNetworkAdapter{app1Vif},
	}
	app1UUID := devConfig.AddApplication(app1Config)

	// app2: VLAN 200.
	const app2MAC = "02:16:3e:00:00:02"
	app2Vif := evetest.VirtualNetworkAdapter{
		LogicalLabel:        "vif0",
		NetworkInstanceUUID: niUUID,
		MAC:                 evetest.MACAddress(app2MAC),
		AccessVLAN:          200,
		ACLAllowRules: []evetest.ACLAllowRule{
			{Protocol: evetest.NetworkProtocolAny, RemoteSubnet: evetest.IPSubnet("0.0.0.0/0")},
		},
	}
	app2Config := evetest.ApplicationInstanceConfig{
		DisplayName: "vlan200-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters:    []evetest.AppNetworkAdapter{app2Vif},
	}
	app2UUID := devConfig.AddApplication(app2Config)

	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	defer stopNIWatch()
	app1Updates, stopApp1Watch := device.WatchAppInfo(app1UUID)
	defer stopApp1Watch()
	app2Updates, stopApp2Watch := device.WatchAppInfo(app2UUID)
	defer stopApp2Watch()
	device.ApplyConfig(devConfig, false, false)

	timeout := 5 * time.Minute
	sshTimeout := 30 * time.Second
	polling := 5 * time.Second
	log := evetest.Logger()

	vlan100Subnet := evetest.IPSubnet("10.203.100.0/24")
	vlan200Subnet := evetest.IPSubnet("10.203.200.0/24")

	// -----------------------------------------------------------------------
	// Phase 1: DHCP and bridge VLAN filtering
	// -----------------------------------------------------------------------

	// Wait for the NI to come ONLINE.
	var niInfo *eveinfo.ZInfoNetworkInstance
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		}).StopIf(niHasError)))
	bridgeName := niInfo.BridgeName
	t.Expect(bridgeName).ToNot(BeEmpty())

	device.WaitUntilAppIsRunning(app1UUID, timeout)
	device.WaitUntilAppIsRunning(app2UUID, timeout)
	evetest.Checkpoint("apps-running")

	// Wait for app1 to receive an IP from the VLAN 100 subnet.
	var app1IP net.IP
	t.Eventually(app1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App1 receives IP from VLAN 100 subnet",
		func(info *eveinfo.ZInfoApp) bool {
			if len(info.Network) == 0 {
				return false
			}
			for _, ipStr := range info.Network[0].IPAddrs {
				ip := evetest.IPAddress(ipStr)
				if ip.IsGlobalUnicast() && vlan100Subnet.Contains(ip) {
					app1IP = ip
					return true
				}
			}
			return false
		}).StopIf(appHasError)))
	log.Infof("App1 received IP: %s", app1IP)

	// Wait for app2 to receive an IP from the VLAN 200 subnet.
	var app2IP net.IP
	t.Eventually(app2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App2 receives IP from VLAN 200 subnet",
		func(info *eveinfo.ZInfoApp) bool {
			if len(info.Network) == 0 {
				return false
			}
			for _, ipStr := range info.Network[0].IPAddrs {
				ip := evetest.IPAddress(ipStr)
				if ip.IsGlobalUnicast() && vlan200Subnet.Contains(ip) {
					app2IP = ip
					return true
				}
			}
			return false
		}).StopIf(appHasError)))
	log.Infof("App2 received IP: %s", app2IP)

	// Wait for the NI to report both app VIFs.
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI reports both app VIFs",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return len(info.Vifs) == 2
		}).StopIf(niHasError)))
	var vif1Name, vif2Name string
	for _, vif := range niInfo.Vifs {
		switch vif.MacAddress {
		case app1MAC:
			vif1Name = vif.VifName
		case app2MAC:
			vif2Name = vif.VifName
		}
	}
	t.Expect(vif1Name).ToNot(BeEmpty(), "VIF for app1 not found in NI info")
	t.Expect(vif2Name).ToNot(BeEmpty(), "VIF for app2 not found in NI info")

	// SSH check: VLAN filtering is enabled on the NI bridge.
	vlanFilteringPath := "/sys/class/net/" + bridgeName + "/bridge/vlan_filtering"
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScript("cat "+vlanFilteringPath, sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).To(Equal("1"))
	}, timeout, polling).Should(Succeed())

	// SSH check: `bridge vlan show` confirms the PVID assignments.
	// The `bridge` binary is only installed inside the pillar container.
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScript("eve exec pillar bridge vlan show",
			sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(bridgeVlanPortHasPVID(out, "eth2", 100)).To(BeTrue(),
			"eth2 (access port) must have PVID=100")
		g.Expect(bridgeVlanPortHasPVID(out, "eth3", 200)).To(BeTrue(),
			"eth3 (access port) must have PVID=200")
		g.Expect(bridgeVlanPortHasVLAN(out, "eth1", 100)).To(BeTrue(),
			"eth1 (trunk) must carry VLAN 100")
		g.Expect(bridgeVlanPortHasVLAN(out, "eth1", 200)).To(BeTrue(),
			"eth1 (trunk) must carry VLAN 200")
		g.Expect(bridgeVlanPortHasPVID(out, vif1Name, 100)).To(BeTrue(),
			"app1 VIF must have PVID=100")
		g.Expect(bridgeVlanPortHasPVID(out, vif2Name, 200)).To(BeTrue(),
			"app2 VIF must have PVID=200")
	}, timeout, polling).Should(Succeed())

	evetest.Checkpoint("phase1-done")

	// -----------------------------------------------------------------------
	// Phase 2: VLAN isolation enforcement
	// -----------------------------------------------------------------------
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}

	// App1 (VLAN 100): reaches http-server-100, but not http-server-200 or app2.
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(app1UUID, appAuth,
			"curl -sS --max-time 10 http://http-server-100.test/helloworld",
			sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).To(ContainSubstring("Hello world from HTTP server for VLAN 100"))
	}, timeout, polling).Should(Succeed())

	out, _, _ := device.RunShellScriptInsideApp(app1UUID, appAuth,
		"curl -sS --max-time 5 http://http-server-200.test/helloworld || true",
		sshTimeout, 0)
	t.Expect(out).NotTo(ContainSubstring("VLAN 200"),
		"app1 (VLAN 100) must not reach http-server-200")

	out, _, _ = device.RunShellScriptInsideApp(app1UUID, appAuth,
		"ping -c 3 -W 1 "+app2IP.String()+" 2>&1 || true",
		sshTimeout, 0)
	t.Expect(out).To(ContainSubstring("100% packet loss"),
		"app1 (VLAN 100) must not reach app2 (VLAN 200)")

	// App2 (VLAN 200): reaches http-server-200, but not http-server-100 or app1.
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(app2UUID, appAuth,
			"curl -sS --max-time 10 http://http-server-200.test/helloworld",
			sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).To(ContainSubstring("Hello world from HTTP server for VLAN 200"))
	}, timeout, polling).Should(Succeed())

	out, _, _ = device.RunShellScriptInsideApp(app2UUID, appAuth,
		"curl -sS --max-time 5 http://http-server-100.test/helloworld || true",
		sshTimeout, 0)
	t.Expect(out).NotTo(ContainSubstring("VLAN 100"),
		"app2 (VLAN 200) must not reach http-server-100")

	out, _, _ = device.RunShellScriptInsideApp(app2UUID, appAuth,
		"ping -c 3 -W 1 "+app1IP.String()+" 2>&1 || true",
		sshTimeout, 0)
	t.Expect(out).To(ContainSubstring("100% packet loss"),
		"app2 (VLAN 200) must not reach app1 (VLAN 100)")

	evetest.Checkpoint("phase2-done")

	// -----------------------------------------------------------------------
	// Phase 3: Runtime VLAN reassignment (app1: VLAN 100 → VLAN 200)
	// -----------------------------------------------------------------------
	app1ConfigUpdated := app1Config
	app1ConfigUpdated.NetworkAdapters = []evetest.AppNetworkAdapter{
		evetest.VirtualNetworkAdapter{
			LogicalLabel:        "vif0",
			NetworkInstanceUUID: niUUID,
			MAC:                 evetest.MACAddress(app1MAC),
			AccessVLAN:          200,
			ACLAllowRules: []evetest.ACLAllowRule{
				{
					Protocol:     evetest.NetworkProtocolAny,
					RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
				},
			},
		},
	}
	devConfig.UpdateApplication(app1UUID, app1ConfigUpdated)
	device.ApplyConfig(devConfig, false, false)

	device.WaitUntilAppIsRunning(app1UUID, timeout)
	evetest.Checkpoint("app1-restarted-after-vlan-reassignment")

	// Wait for app1 to receive a new IP from the VLAN 200 subnet.
	t.Eventually(app1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App1 receives IP from VLAN 200 subnet after reassignment",
		func(info *eveinfo.ZInfoApp) bool {
			if len(info.Network) == 0 {
				return false
			}
			for _, ipStr := range info.Network[0].IPAddrs {
				ip := evetest.IPAddress(ipStr)
				if ip.IsGlobalUnicast() && vlan200Subnet.Contains(ip) {
					app1IP = ip
					return true
				}
			}
			return false
		}).StopIf(appHasError)))
	log.Infof("App1 new IP after VLAN reassignment: %s", app1IP)

	// App1 is now in VLAN 200: reaches http-server-200, not http-server-100.
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(app1UUID, appAuth,
			"curl -sS --max-time 10 http://http-server-200.test/helloworld",
			sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).To(ContainSubstring("Hello world from HTTP server for VLAN 200"))
	}, timeout, polling).Should(Succeed())

	out, _, _ = device.RunShellScriptInsideApp(app1UUID, appAuth,
		"curl -sS --max-time 5 http://http-server-100.test/helloworld || true",
		sshTimeout, 0)
	t.Expect(out).NotTo(ContainSubstring("VLAN 100"),
		"app1 (now VLAN 200) must not reach http-server-100")

	// App1 and app2 are both in VLAN 200 now; they can ping each other.
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(app1UUID, appAuth,
			"ping -c 3 -W 2 "+app2IP.String()+" 2>&1",
			sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).NotTo(ContainSubstring("100% packet loss"))
	}, timeout, polling).Should(Succeed())

	evetest.Checkpoint("phase3-done")
}

// TestVLANSubinterfaces verifies that VLAN sub-interfaces on a single physical
// port correctly segment traffic: EVE management uses a tagged VLAN sub-interface,
// two applications use separate network instances whose uplinks are a second tagged
// sub-interface and the untagged parent port, and the SDN router enforces that
// each application can only reach the HTTP server on its own segment.
//
// Topology
// --------
//
//	                   +------+  +--------------------+
//	                   | EVE  |--| vlan10 (mgmt uplink)|---+
//	                   +------+  +--------------------+    |
//	                                                       |
//	+------+  +--------------+  +--------------------+  +------+
//	| app1 |--| NI1 (local)  |--| vlan20 (app-shared)|--| eth0 |
//	+------+  +--------------+  +--------------------+  +------+
//	                                                       |
//	+------+  +--------------+                             |
//	| app2 |--| NI2 (local)  |---<untagged>----------------+
//	+------+  +--------------+
//
// Three traffic streams share a single physical port eth0:
//   - vlan10 (VLAN 10, tagged): EVE management only. Not used by any NI or app.
//   - vlan20 (VLAN 20, tagged): uplink for NI1; app1's NAT'd traffic egresses
//     tagged VLAN 20.
//   - ethernet0 (untagged): uplink for NI2; app2's NAT'd traffic egresses
//     untagged.
//
// Network model
// -------------
//   - netmodels.SingleEthWithVLANSubInterfaces: single port eth0 on bridge0.
//     Three networks share the bridge: VLAN 10 (172.22.10.0/24, DHCP,
//     controller-reachable), VLAN 20 (172.22.20.0/24, DHCP, no controller
//     route), untagged (192.168.77.0/24, DHCP, no controller route). A
//     shared DNS server (10.16.16.25) is reachable from all three segments.
//     Each segment has a dedicated HTTP server reachable only from that segment:
//     http-server-10.test (10.16.10.70) on VLAN 10, http-server-20.test
//     (10.16.20.70) on VLAN 20, http-server-untagged.test (10.16.77.70) on
//     the untagged segment. The SDN router has no cross-segment routes, so
//     each HTTP server is isolated to its own VLAN or untagged segment.
//
// Device configuration
// --------------------
//   - ethernet0 (eth0): During the bootstrap phase this is the management path
//     (untagged, DHCP from 172.20.20.0/24 on the initial SingleEthWithDHCP model);
//     after the model switch it obtains a 192.168.77.0/24 address and serves as
//     the port for NI2.
//   - vlan10: VLAN 10 sub-interface on ethernet0, MgmtAndApps. Becomes the
//     primary management uplink once the VLAN model is active and
//     172.22.10.0/24 gains controller reachability.
//   - vlan20: VLAN 20 sub-interface on ethernet0, app-shared. Port for NI1.
//   - NI1 (Local, 10.50.20.0/24) on vlan20. SSH into app1 is forwarded from
//     the NI gateway port 2222 → app port 22.
//   - NI2 (Local, 10.50.77.0/24) on ethernet0. SSH into app2 is forwarded
//     from the NI gateway port 2223 → app port 22.
//   - Two container apps (lfedge/evetest-ubuntu-ctr:1.0): app1 on NI1,
//     app2 on NI2, each with an allow-all ACL.
//
// Bootstrap note
// --------------
// The test starts with netmodels.SingleEthWithDHCP so EVE can onboard before
// VLAN tagging is enabled on the SDN side. The port config (ethernet0,
// vlan10, vlan20) is applied first while the old model is still active;
// ethernet0 (MgmtAndApps) keeps the controller connection alive during the
// transition. The SDN model then switches to SingleEthWithVLANSubInterfaces,
// after which vlan10 becomes the active management path. NIs and apps are
// added only after Phase 1 confirms that all three ports have obtained their
// expected addresses. This is the same bootstrap workaround used by
// TestLACPBond.
//
// Phases
// ------
//
//  1. IP addressing: the port-only config is submitted first. After the SDN
//     model switches, WatchDeviceInfo confirms vlan10 receives an IP from
//     172.22.10.0/24, vlan20 from 172.22.20.0/24, and ethernet0 from
//     192.168.77.0/24.
//
//  2. Application connectivity: NI and app config is added and submitted.
//     Both apps reach RUNNING state. app1 (NI1 on vlan20) curls
//     http-server-20.test successfully; curls to http-server-untagged.test
//     and http-server-10.test both fail — the SDN router has no route from
//     VLAN 20 to those segments. app2 (NI2 on ethernet0 untagged) curls
//     http-server-untagged.test successfully; curls to http-server-20.test
//     and http-server-10.test both fail.
//
// Test params
// -----------
//   - HYPERVISOR. The test calls evetest.SkipIfHypervisorKubevirt() right
//     after reading the parameter — Kubevirt is reserved for cluster tests.
func TestVLANSubinterfaces(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(evetest.HypervisorParameter())
	hypervisor := evetest.GetHypervisorParameterValue()
	evetest.SkipIfHypervisorKubevirt()

	devName := "edge-dev"
	// Clone the bootstrap model and shorten the DHCP lease on the management network.
	// After the SDN switches to the VLAN model, eth0 still holds its old DHCP lease
	// (172.20.20.x). A short lease (120 s) ensures the DHCP client rediscovers quickly
	// and obtains the expected 192.168.77.x address from the new untagged segment.
	bootModel := proto.Clone(netmodels.SingleEthWithDHCP).(*api.NetworkModel)
	bootModel.Networks[0].Ipv4.Dhcp.LeaseTimeSeconds = 120
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: bootModel,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// Single DHCP network shared by all adapters (ethernet0, vlan10, vlan20).
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})

	// ethernet0: used for untagged traffic and as the uplink for NI2.
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})

	// vlan10: VLAN 10 sub-interface, management uplink once the SDN VLAN model
	// is active and network-10 gains controller reachability.
	devConfig.AddVLANSubinterface(evetest.VLANSubinterfaceConfig{
		LogicalLabel:       "vlan10",
		InterfaceName:      "vlan10",
		ParentLogicalLabel: "ethernet0",
		VlanID:             10,
		NetworkUUID:        dhcpNet,
		Usage:              evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})

	// vlan20: VLAN 20 sub-interface, app-shared port for NI1.
	devConfig.AddVLANSubinterface(evetest.VLANSubinterfaceConfig{
		LogicalLabel:       "vlan20",
		InterfaceName:      "vlan20",
		ParentLogicalLabel: "ethernet0",
		VlanID:             20,
		NetworkUUID:        dhcpNet,
		Usage:              evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()

	// Submit port-only config while the old SDN model is still active. EVE can
	// still reach the controller via ethernet0 (untagged, 172.20.20.0/24) since
	// vlan10 has no route to the controller until the SDN side activates VLAN 10.
	// waitUntilConfirmed=false: after the model switch below, EVE may temporarily
	// lose controller connectivity, delaying the LastProcessedConfig metric publish.
	device.ApplyConfig(devConfig, true, false)
	// Give EVE a moment to process the port config (activate vlan interfaces)
	// before switching the SDN side, so the new interfaces are ready to carry
	// traffic as soon as VLAN tagging is enabled.
	time.Sleep(10 * time.Second)
	evetest.Checkpoint("port-config-applied")

	// Switch the SDN side to the VLAN model. From this point VLAN 10 gains
	// controller reachability and becomes the primary management path; VLAN 20
	// carries app1's traffic; untagged carries app2's traffic.
	evetest.UpdateNetworkModel(netmodels.SingleEthWithVLANSubInterfaces)
	evetest.Checkpoint("sdn-vlan-enabled")

	// -----------------------------------------------------------------------
	// Phase 1: IP addressing
	// -----------------------------------------------------------------------

	timeout := 5 * time.Minute
	sshTimeout := 30 * time.Second
	polling := 5 * time.Second
	log := evetest.Logger()

	vlan10Subnet := evetest.IPSubnet("172.22.10.0/24")
	vlan20Subnet := evetest.IPSubnet("172.22.20.0/24")
	untaggedSubnet := evetest.IPSubnet("192.168.77.0/24")

	// Wait until all three interfaces report IPs from their respective subnets.
	var vlan10IP, vlan20IP, eth0IP net.IP
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"vlan10 IP in 172.22.10.0/24, vlan20 IP in 172.22.20.0/24, "+
			"eth0 IP in 192.168.77.0/24",
		func(info *eveinfo.ZInfoDevice) bool {
			vlan10IP = getPortIPv4Addr("vlan10", info)
			vlan20IP = getPortIPv4Addr("vlan20", info)
			eth0IP = getPortIPv4Addr("ethernet0", info)
			return vlan10Subnet.Contains(vlan10IP) &&
				vlan20Subnet.Contains(vlan20IP) &&
				untaggedSubnet.Contains(eth0IP)
		})))
	log.Infof("vlan10 IP: %s, vlan20 IP: %s, ethernet0 IP: %s",
		vlan10IP, vlan20IP, eth0IP)

	evetest.Checkpoint("phase1-done")

	// -----------------------------------------------------------------------
	// Phase 2: Application connectivity
	// -----------------------------------------------------------------------

	const appImage = "lfedge/evetest-ubuntu-ctr"
	const appTag = "1.0"
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}

	// NI1: Local NI on vlan20 — app1's NAT'd traffic egresses VLAN 20.
	ni1UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "ni1-vlan20",
		Port:        "vlan20",
		Subnet:      evetest.IPSubnet("10.50.20.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.50.20.2"),
			End:   evetest.IPAddress("10.50.20.254"),
		},
		Gateway: evetest.IPAddress("10.50.20.1"),
	})

	// NI2: Local NI on ethernet0 (untagged) — app2's NAT'd traffic.
	ni2UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "ni2-untagged",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.50.77.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.50.77.2"),
			End:   evetest.IPAddress("10.50.77.254"),
		},
		Gateway: evetest.IPAddress("10.50.77.1"),
	})

	// app1: on NI1 (vlan20). SSH forwarded from EVE's vlan20 NI gateway port 2222.
	app1UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "vlan20-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: appImage,
			Tag:       appTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: ni1UUID,
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
						AppPort:      22,
					},
				},
			},
		},
	})

	// app2: on NI2 (untagged). SSH forwarded from EVE's ethernet0 NI gateway port 2223.
	app2UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "untagged-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: appImage,
			Tag:       appTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: ni2UUID,
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2223,
						AppPort:      22,
					},
				},
			},
		},
	})

	device.ApplyConfig(devConfig, false, false)

	device.WaitUntilAppIsRunning(app1UUID, timeout)
	device.WaitUntilAppIsRunning(app2UUID, timeout)
	evetest.Checkpoint("apps-running")

	// app1 (NI1, vlan20): reaches http-server-20 only. The SDN router for
	// network-20 routes to http-server-20 but not to the other segments.
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(app1UUID, appAuth,
			"curl -sS --max-time 10 http://http-server-20.test/helloworld",
			sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).To(ContainSubstring("Hello world from HTTP server for VLAN 20"))
	}, timeout, polling).Should(Succeed())

	out, _, _ := device.RunShellScriptInsideApp(app1UUID, appAuth,
		"curl -sS --max-time 5 http://http-server-untagged.test/helloworld || true",
		sshTimeout, 0)
	t.Expect(out).NotTo(ContainSubstring("untagged"),
		"app1 (vlan20) must not reach http-server-untagged")

	out, _, _ = device.RunShellScriptInsideApp(app1UUID, appAuth,
		"curl -sS --max-time 5 http://http-server-10.test/helloworld || true",
		sshTimeout, 0)
	t.Expect(out).NotTo(ContainSubstring("VLAN 10"),
		"app1 (vlan20) must not reach http-server-10")

	// app2 (NI2, ethernet0 untagged): reaches http-server-untagged only.
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(app2UUID, appAuth,
			"curl -sS --max-time 10 http://http-server-untagged.test/helloworld",
			sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).To(ContainSubstring("Hello world from HTTP server for untagged network"))
	}, timeout, polling).Should(Succeed())

	out, _, _ = device.RunShellScriptInsideApp(app2UUID, appAuth,
		"curl -sS --max-time 5 http://http-server-20.test/helloworld || true",
		sshTimeout, 0)
	t.Expect(out).NotTo(ContainSubstring("VLAN 20"),
		"app2 (untagged) must not reach http-server-20")

	out, _, _ = device.RunShellScriptInsideApp(app2UUID, appAuth,
		"curl -sS --max-time 5 http://http-server-10.test/helloworld || true",
		sshTimeout, 0)
	t.Expect(out).NotTo(ContainSubstring("VLAN 10"),
		"app2 (untagged) must not reach http-server-10")

	evetest.Checkpoint("phase2-done")
}

// TestVLANSubinterfacesOnTopOfLAGs verifies VLAN sub-interfaces created on
// top of an LACP bond (802.3ad), used both as management uplink and as uplink
// ports for application network instances.
//
// Topology
// --------
//
//	            +-----+  +----------------+
//	            | EVE |--| VLAN 10 (mgmt) |-----
//	            +-----+  +----------------+    |          +------+      +---------+
//	                                           |      ----| eth0 |......| p0 --+  |
//	+------+  +--------------+  +---------+  +-----+  |   +------+      |      |  |
//	| app1 |--| NI1 (local)  |--| VLAN 20 |--| LAG |--|                 |    LAG  |
//	+------+  +--------------+  +---------+  +-----+  |   +------+      |      |  |  VLAN20  +---------------+
//	                                           |      ----| eth1 |......| p1 --+  |..........| httpserver-20 |
//	+------+  +--------------+  +---------+    |          +------+      |         |          +---------------+
//	| app2 |--| NI2 (switch) |--| VLAN 30 |-----                        |         |
//	+------+  +--------------+  +---------+                             | SWITCH  |  VLAN30  +---------------+
//	                                                                    |         |..........| httpserver-30 |
//	+------+                    +--------------+          +------+      |         |          +---------------+
//	| app3 |--<access VLAN 30>--| NI3 (switch) |----------| eth2 |......| p2      |
//	+------+                    +--------------+          +------+      |         |
//	                                                                    +---------+
//
// Network model
// -------------
//   - netmodels.BondWithVLANs: eth0 and eth1 are members of an SDN-side LACP
//     bond; eth2 is a standalone trunk port. A single SDN bridge spans both the
//     LACP bond and eth2 and carries VLANs 10, 20 and 30. VLAN 10 has controller
//     reachability; VLAN 20 and 30 each have a dedicated HTTP server
//     (httpserver-20 / httpserver-30) and a DNS server.
//   - EVE is bootstrapped via netmodels.TwoMgmtPortsOneBridge (with eth2 added)
//     so the device can onboard before the LACP peer is present; the SDN model
//     is switched to BondWithVLANs after EVE has applied the bond config
//     (same pattern as TestLACPBond and TestVLANSubinterfaces).
//
// Device configuration
// --------------------
//   - eth0, eth1: PhysicalIO adapters, bond members; no SystemAdapter.
//   - eth2: PhysicalIO adapter, no-IP SystemAdapter, uplink for NI3.
//   - "lacp-bond": BondConfig aggregating eth0+eth1 in 802.3ad mode with
//     LacpRate=FAST; no link monitor (Linux rejects ARPMonitor on 802.3ad
//     bonds, and MIIMonitor is ineffective with virtio NICs — failover is
//     detected via LACP PDU timeouts); no SystemAdapter.
//   - VLAN sub-interfaces on the bond (all DHCP):
//     vlan10-on-bond (mgmt+app) — controller uplink.
//     vlan20-on-bond (app-shared) — uplink port for NI1.
//     vlan30-on-bond (app-shared) — uplink port for NI2.
//   - NI1: Local NI on vlan20-on-bond; subnet 10.50.0.0/24.
//   - NI2: Switch NI on vlan30-on-bond.
//   - NI3: Switch NI on ethernet2; app3's VIF carries AccessVLAN=30 so the NI
//     bridge assigns PVID 30 and the SDN switch delivers VLAN-30 frames.
//   - app1 on NI1 — NAT'd IP from 10.50.0.0/24.
//   - app2 on NI2 — IP from SDN VLAN-30 DHCP (172.22.30.0/24).
//   - app3 on NI3 — IP from SDN VLAN-30 DHCP (172.22.30.0/24).
//
// Phases
// ------
//
//  1. Bond + VLAN convergence: wait for all three VLAN sub-interfaces on the
//     bond to acquire IPs (vlan10 from 172.22.10.0/24, vlan20 from
//     172.22.20.0/24, vlan30 from 172.22.30.0/24) and for the LACP bond to
//     report a non-zero partner MAC, confirming LACP negotiation with the SDN
//     peer succeeded. Verify both members report MiiUp and belong to the same
//     active aggregator (no split aggregation).
//
//  2. Application connectivity: app1 reaches http-server-20 and is blocked
//     from http-server-30 (VLAN isolation). app2 and app3 each reach
//     http-server-30 and are blocked from http-server-20. app2 and app3 can
//     ping each other because both are in VLAN 30 and the SDN bridge connects
//     the LACP bond path and the eth2 path.
//
// Test params
// -----------
//   - HYPERVISOR. The test calls evetest.SkipIfHypervisorKubevirt() right
//     after reading the parameter — Kubevirt is reserved for cluster tests.
func TestVLANSubinterfacesOnTopOfLAGs(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(evetest.HypervisorParameter())
	hypervisor := evetest.GetHypervisorParameterValue()
	evetest.SkipIfHypervisorKubevirt()

	devName := "edge-dev"

	// Bootstrap with a 3-port flat model so the VM gets three virtual NICs.
	// Clone TwoMgmtPortsOneBridge and add eth2 port.
	bootModel := proto.Clone(netmodels.TwoMgmtPortsOneBridge).(*api.NetworkModel)
	bootModel.Ports = append(bootModel.Ports,
		&api.Port{LogicalLabel: "eth2", AdminUp: true})
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: bootModel,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// dhcpNet is shared by all three VLAN sub-interfaces on the bond.
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	// noIPNet is assigned to ethernet2, which is only used as uplink
	// for switch NI (no IP on the port itself).
	noIPNet := devConfig.AddNetwork(evetest.NoIPNetworkConfig{})

	// Physical adapters. ethernet0+ethernet1 become bond members; ethernet2 is
	// the trunk uplink for NI3 (app3 gets VLAN 30 access via its VIF AccessVLAN).
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet2",
		PhysicalLabel: "eth2",
		InterfaceName: "eth2",
		NetworkUUID:   noIPNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})

	// LACP bond aggregating ethernet0+ethernet1. No NetworkUUID — no
	// SystemAdapter entry for the bond itself; EVE still reports it in
	// DevicePortStatus as the parent of the VLAN sub-interfaces.
	// No link monitor: Linux rejects ARPMonitor on 802.3ad bonds, and
	// MIIMonitor is ineffective with virtio NICs. Failover is detected via
	// LACP PDU timeouts (~3 s with LacpRate=FAST).
	devConfig.AddBond(evetest.BondConfig{
		LogicalLabel:  "lacp-bond",
		InterfaceName: "bond1", // bond0 is reserved in Linux
		MemberLabels:  []string{"ethernet0", "ethernet1"},
		BondMode:      evecommon.BondMode_BOND_MODE_802_3AD,
		LACPRate:      evecommon.LacpRate_LACP_RATE_FAST,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})

	// VLAN sub-interfaces on the bond.
	devConfig.AddVLANSubinterface(evetest.VLANSubinterfaceConfig{
		LogicalLabel:       "vlan10-on-bond",
		InterfaceName:      "vlan10",
		ParentLogicalLabel: "lacp-bond",
		VlanID:             10,
		NetworkUUID:        dhcpNet,
		Usage:              evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	devConfig.AddVLANSubinterface(evetest.VLANSubinterfaceConfig{
		LogicalLabel:       "vlan20-on-bond",
		InterfaceName:      "vlan20",
		ParentLogicalLabel: "lacp-bond",
		VlanID:             20,
		NetworkUUID:        dhcpNet,
		Usage:              evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})
	devConfig.AddVLANSubinterface(evetest.VLANSubinterfaceConfig{
		LogicalLabel:       "vlan30-on-bond",
		InterfaceName:      "vlan30bond",
		ParentLogicalLabel: "lacp-bond",
		VlanID:             30,
		NetworkUUID:        dhcpNet,
		Usage:              evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()

	// Submit port-only config while the bootstrap SDN model is still active.
	// EVE can still reach the controller through eth0/eth1. waitUntilConfirmed=false
	// because after the SDN model switch below, EVE may temporarily lose controller
	// connectivity while LACP negotiates.
	device.ApplyConfig(devConfig, true, false)
	// Give EVE a moment to create the bond and VLAN sub-interfaces before switching
	// the SDN side, so the interfaces are ready to carry traffic immediately.
	time.Sleep(10 * time.Second)
	evetest.Checkpoint("port-config-applied")

	// Switch the SDN side to BondWithVLANs. This activates the SDN LACP bond;
	// once LACP negotiation completes, the VLAN sub-interfaces can obtain IPs.
	evetest.UpdateNetworkModel(netmodels.BondWithVLANs)
	evetest.Checkpoint("sdn-bond-vlan-enabled")

	// -----------------------------------------------------------------------
	// Phase 1: Bond + VLAN convergence
	// -----------------------------------------------------------------------

	timeout := 5 * time.Minute
	sshTimeout := 30 * time.Second
	polling := 5 * time.Second
	log := evetest.Logger()

	vlan10Subnet := evetest.IPSubnet("172.22.10.0/24")
	vlan20Subnet := evetest.IPSubnet("172.22.20.0/24")
	vlan30Subnet := evetest.IPSubnet("172.22.30.0/24")

	// Wait until all three VLAN sub-interfaces on the bond have IPs from their
	// respective subnets AND the LACP bond reports a non-zero partner MAC (i.e.
	// LACP negotiation with the SDN peer has completed).
	var vlan10IP, vlan20IP, vlan30BondIP net.IP
	var bondStatus *eveinfo.BondStatus
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"All VLAN IPs assigned and LACP partner MAC non-zero",
		func(info *eveinfo.ZInfoDevice) bool {
			vlan10IP = getPortIPv4Addr("vlan10-on-bond", info)
			vlan20IP = getPortIPv4Addr("vlan20-on-bond", info)
			vlan30BondIP = getPortIPv4Addr("vlan30-on-bond", info)
			if !vlan10Subnet.Contains(vlan10IP) ||
				!vlan20Subnet.Contains(vlan20IP) ||
				!vlan30Subnet.Contains(vlan30BondIP) {
				return false
			}
			port := getDevicePort("lacp-bond", info)
			if port == nil {
				return false
			}
			bs := port.GetBondStatus()
			if bs == nil || bs.GetLacp() == nil {
				return false
			}
			partnerMac, err := net.ParseMAC(bs.GetLacp().GetPartnerMac())
			if err != nil {
				return false
			}
			for _, b := range partnerMac {
				if b != 0 {
					bondStatus = bs
					return true
				}
			}
			return false
		})))
	log.Infof("VLAN IPs: vlan10=%s vlan20=%s vlan30bond=%s",
		vlan10IP, vlan20IP, vlan30BondIP)

	// Verify both members are in the active aggregator.
	activeAggID := bondStatus.GetLacp().GetActiveAggregatorId()
	t.Expect(activeAggID).ToNot(BeZero())
	t.Expect(bondStatus.GetMode()).To(Equal(evecommon.BondMode_BOND_MODE_802_3AD))
	for _, member := range bondStatus.GetMembers() {
		t.Expect(member.GetLogicallabel()).To(BeElementOf("ethernet0", "ethernet1"))
		t.Expect(member.GetMiiUp()).To(BeTrue())
		t.Expect(member.GetLacp().GetAggregatorId()).To(Equal(activeAggID))
	}

	evetest.Checkpoint("phase1-done")

	// -----------------------------------------------------------------------
	// Phase 2: Application connectivity
	// -----------------------------------------------------------------------

	const appImage = "lfedge/evetest-ubuntu-ctr"
	const appTag = "1.0"
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}

	// NI1: Local NI on vlan20-on-bond. app1 receives a NAT'd IP from 10.50.0.0/24.
	ni1UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "ni1-vlan20",
		Port:        "vlan20-on-bond",
		Subnet:      evetest.IPSubnet("10.50.0.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.50.0.2"),
			End:   evetest.IPAddress("10.50.0.254"),
		},
		Gateway: evetest.IPAddress("10.50.0.1"),
	})

	// NI2: Switch NI on vlan30-on-bond. app2 gets L2 access to VLAN 30 directly.
	ni2UUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "ni2-vlan30-bond",
		Port:        "vlan30-on-bond",
	})

	// NI3: Switch NI directly on ethernet2. app3's VIF has AccessVLAN=30 so the
	// NI bridge tags/untags VLAN 30 frames on that VIF; eth2 carries tagged traffic.
	ni3UUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "ni3-eth2",
		Port:        "ethernet2",
	})

	// app1: on NI1 (Local, vlan20-on-bond). SSH forwarded from vlan20 NI gateway port 2222.
	app1UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "vlan20-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: appImage,
			Tag:       appTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: ni1UUID,
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
						AppPort:      22,
					},
				},
			},
		},
	})

	// app2: on NI2 (Switch, vlan30-on-bond). Gets IP from 172.22.30.0/24.
	const app2MAC = "02:16:3e:00:00:02"
	app2UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "vlan30-bond-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: appImage,
			Tag:       appTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: ni2UUID,
				MAC:                 evetest.MACAddress(app2MAC),
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	})

	// app3: on NI3 (Switch, ethernet2). AccessVLAN=30 so the NI bridge assigns
	// PVID 30 to app3's VIF; gets IP from 172.22.30.0/24.
	const app3MAC = "02:16:3e:00:00:03"
	app3UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "vlan30-eth2-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: appImage,
			Tag:       appTag,
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: ni3UUID,
				MAC:                 evetest.MACAddress(app3MAC),
				AccessVLAN:          30,
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	})

	app2Updates, stopApp2Watch := device.WatchAppInfo(app2UUID)
	defer stopApp2Watch()
	app3Updates, stopApp3Watch := device.WatchAppInfo(app3UUID)
	defer stopApp3Watch()
	device.ApplyConfig(devConfig, false, false)

	device.WaitUntilAppIsRunning(app1UUID, timeout)
	device.WaitUntilAppIsRunning(app2UUID, timeout)
	device.WaitUntilAppIsRunning(app3UUID, timeout)
	evetest.Checkpoint("apps-running")

	// Wait for app2 to receive an IP from the VLAN 30 subnet.
	var app2IP net.IP
	t.Eventually(app2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App2 receives IP from VLAN 30 subnet",
		func(info *eveinfo.ZInfoApp) bool {
			if len(info.Network) == 0 {
				return false
			}
			for _, ipStr := range info.Network[0].IPAddrs {
				ip := evetest.IPAddress(ipStr)
				if ip.IsGlobalUnicast() && vlan30Subnet.Contains(ip) {
					app2IP = ip
					return true
				}
			}
			return false
		}).StopIf(appHasError)))
	log.Infof("App2 IP: %s", app2IP)

	// Wait for app3 to receive an IP from the VLAN 30 subnet.
	var app3IP net.IP
	t.Eventually(app3Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App3 receives IP from VLAN 30 subnet",
		func(info *eveinfo.ZInfoApp) bool {
			if len(info.Network) == 0 {
				return false
			}
			for _, ipStr := range info.Network[0].IPAddrs {
				ip := evetest.IPAddress(ipStr)
				if ip.IsGlobalUnicast() && vlan30Subnet.Contains(ip) {
					app3IP = ip
					return true
				}
			}
			return false
		}).StopIf(appHasError)))
	log.Infof("App3 IP: %s", app3IP)

	// app1 (NI1 Local, vlan20-on-bond): reaches http-server-20 only.
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(app1UUID, appAuth,
			"curl -sS --max-time 10 http://http-server-20.test/helloworld",
			sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).To(ContainSubstring("Hello world from HTTP server for VLAN 20"))
	}, timeout, polling).Should(Succeed())

	out, _, _ := device.RunShellScriptInsideApp(app1UUID, appAuth,
		"curl -sS --max-time 5 http://http-server-30.test/helloworld || true",
		sshTimeout, 0)
	t.Expect(out).NotTo(ContainSubstring("VLAN 30"),
		"app1 (vlan20) must not reach http-server-30")

	// app2 (NI2 Switch, vlan30-on-bond): reaches http-server-30 only.
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(app2UUID, appAuth,
			"curl -sS --max-time 10 http://http-server-30.test/helloworld",
			sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).To(ContainSubstring("Hello world from HTTP server for VLAN 30"))
	}, timeout, polling).Should(Succeed())

	out, _, _ = device.RunShellScriptInsideApp(app2UUID, appAuth,
		"curl -sS --max-time 5 http://http-server-20.test/helloworld || true",
		sshTimeout, 0)
	t.Expect(out).NotTo(ContainSubstring("VLAN 20"),
		"app2 (vlan30/bond) must not reach http-server-20")

	// app3 (NI3 Switch, vlan30-on-eth2): reaches http-server-30 only.
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(app3UUID, appAuth,
			"curl -sS --max-time 10 http://http-server-30.test/helloworld",
			sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).To(ContainSubstring("Hello world from HTTP server for VLAN 30"))
	}, timeout, polling).Should(Succeed())

	out, _, _ = device.RunShellScriptInsideApp(app3UUID, appAuth,
		"curl -sS --max-time 5 http://http-server-20.test/helloworld || true",
		sshTimeout, 0)
	t.Expect(out).NotTo(ContainSubstring("VLAN 20"),
		"app3 (vlan30/eth2) must not reach http-server-20")

	// app2 and app3 are in the same VLAN 30 segment (one via the bond, one via
	// eth2); the SDN bridge connects both paths, so they can ping each other.
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(app2UUID, appAuth,
			"ping -c 3 -W 2 "+app3IP.String()+" 2>&1",
			sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).NotTo(ContainSubstring("100% packet loss"))
	}, timeout, polling).Should(Succeed())

	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScriptInsideApp(app3UUID, appAuth,
			"ping -c 3 -W 2 "+app2IP.String()+" 2>&1",
			sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).NotTo(ContainSubstring("100% packet loss"))
	}, timeout, polling).Should(Succeed())

	evetest.Checkpoint("phase2-done")
}

// bridgeVlanPortHasPVID returns true if portName has the given VLAN ID as its PVID
// in the output of `bridge vlan show`.
func bridgeVlanPortHasPVID(output, portName string, vid int) bool {
	vidStr := strconv.Itoa(vid)
	inPortSection := false
	for _, line := range strings.Split(output, "\n") {
		if len(line) == 0 {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			fields := strings.Fields(line)
			inPortSection = len(fields) > 0 && fields[0] == portName
			if inPortSection && len(fields) > 1 && vlanFieldsHavePVID(fields[1:], vidStr) {
				return true
			}
		} else if inPortSection {
			if vlanFieldsHavePVID(strings.Fields(line), vidStr) {
				return true
			}
		}
	}
	return false
}

// bridgeVlanPortHasVLAN returns true if portName has the given VLAN ID (with any flags)
// in the output of `bridge vlan show`.
func bridgeVlanPortHasVLAN(output, portName string, vid int) bool {
	vidStr := strconv.Itoa(vid)
	inPortSection := false
	for _, line := range strings.Split(output, "\n") {
		if len(line) == 0 {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			fields := strings.Fields(line)
			inPortSection = len(fields) > 0 && fields[0] == portName
			if inPortSection && len(fields) > 1 && fields[1] == vidStr {
				return true
			}
		} else if inPortSection {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == vidStr {
				return true
			}
		}
	}
	return false
}

// vlanFieldsHavePVID returns true if fields (from one `bridge vlan show` line, with the
// port name stripped) contain vidStr followed by the "PVID" flag.
func vlanFieldsHavePVID(fields []string, vidStr string) bool {
	for i, f := range fields {
		if f == vidStr {
			for _, f2 := range fields[i+1:] {
				if f2 == "PVID" {
					return true
				}
			}
			break
		}
	}
	return false
}
