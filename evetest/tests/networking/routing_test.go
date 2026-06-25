// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
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
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// TestPropagatedRoutes verifies that EVE delivers connected port-subnet routes
// and statically-configured routes to applications via DHCP option 121, and
// that the resulting routing table steers application traffic through the
// correct NI and uplink port. It also covers the negative case: when
// PropagateConnectedRoutes is false the port subnet is withheld, while static
// routes on the same NI are still delivered.
//
// Topology
// --------
//
//	          +---------+    +-------------+     +--------------+
//	   ------>| ni-eth0 |----| eth0 (mgmt) | ... | http-server-0|
//	   |      +---------+    +-------------+     +--------------+
//	   |
//	+-----+   +---------+    +-------------------------+     +--------------+
//	| app |-->| ni-eth1 |----|    eth1 (app-shared)    | ... | http-server-1|
//	+-----+   +---------+    | (static, no def. route) |     +--------------+
//	   |                     +-------------------------+
//	   |
//	   |      +---------+    +-------------------------+     +--------------+
//	   ------>| ni-eth2 |----|    eth2 (app-shared)    | ... | http-server-2|
//	          +---------+    |  (DHCP, no def. route)  |     +--------------+
//	                         +-------------------------+
//
// Network model
// -------------
//   - netmodels.ThreeIsolatedPorts -- three ports each on its own bridge
//     and SDN network with strictly isolated routing: eth0 (DHCP,
//     controller-reachable, dns-server and http-server-0.test at 10.20.20.70
//     reachable), eth1 (no DHCP, http-server-1.test at 10.21.21.70 only),
//     eth2 (DHCP without router option, http-server-2.test at 10.22.22.70
//     only). A single DNS server (10.16.16.25, reachable via eth0) resolves
//     the controller hostname and all three HTTP server FQDNs.
//
// Phases
// ------
//  1. Device config: eth0 as management DHCP (PhyIoUsageMgmtAndApps),
//     eth1 as app-shared static 192.168.55.2/24 with gateway=0.0.0.0 (no
//     default route installed on EVE), eth2 as app-shared DHCP (the SDN
//     suppresses the router DHCP option so no default route is installed).
//     Three Local NIs are created -- one per port:
//     - ni-eth0 (10.50.0.0/24, bridge 10.50.0.1): PropagateConnectedRoutes=true,
//     static route 10.20.20.0/24 via 10.50.0.1.
//     - ni-eth1 (10.50.1.0/24, bridge 10.50.1.1): PropagateConnectedRoutes=true,
//     static route 10.21.21.0/24 via 192.168.55.1 (EVE normalises this to
//     the NI bridge IP 10.50.1.1 when advertising via DHCP option 121).
//     - ni-eth2 (10.50.2.0/24, bridge 10.50.2.1): PropagateConnectedRoutes=false,
//     static route 10.22.22.0/24 via 10.50.2.1.
//     One container app (milan4zededa/evetest-ubuntu-ctr:1.0) with three
//     VIFs (vif0..vif2), one per NI, EnforceNetIntfOrder=true for
//     deterministic vif-to-interface mapping inside the app, default-allow
//     ACL on each VIF, and a TCP 2222->22 port-forward on vif0.
//  2. VIF IPs: WatchAppInfo waits until the app reports all three VIFs, each
//     with exactly one IP from its respective NI subnet and the correct MAC.
//  3. Route table (RunShellScriptInsideApp via port-fwd 2222->22 on vif0):
//     `ip route` inside the app must contain:
//     - default via 10.50.0.1 -- the mgmt port (eth0) is the only uplink that
//     contributes a default route; eth1 and eth2 are app-shared.
//     - 10.20.20.0/24 via 10.50.0.1 -- static route on ni-eth0.
//     - 172.22.12.0/24 -- eth0 port subnet, propagated by ni-eth0.
//     - 10.21.21.0/24 via 10.50.1.1 -- static route on ni-eth1, gateway
//     normalised to the NI bridge IP.
//     - 192.168.55.0/24 -- eth1 port subnet, propagated by ni-eth1.
//     - 10.22.22.0/24 via 10.50.2.1 -- static route on ni-eth2.
//     - 10.140.2.0/24 must NOT appear -- eth2 port subnet is withheld
//     because PropagateConnectedRoutes=false on ni-eth2.
//  4. HTTP connectivity: `curl` to http-server-0.test, http-server-1.test,
//     and http-server-2.test from inside the app must each succeed. Because
//     each HTTP server is reachable only via its dedicated SDN port, a
//     misrouted packet is silently dropped by the SDN router, making these
//     curls the decisive check that the propagated routes are used correctly.
//
// Test params
// -----------
//   - HYPERVISOR. SkipIfHypervisorKubevirt() is called immediately after
//     reading the parameter -- Kubevirt is reserved for cluster tests.
func TestPropagatedRoutes(test *testing.T) {
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
			NetworkModel: netmodels.ThreeIsolatedPorts,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// eth0: management DHCP.
	eth0Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   eth0Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})

	// eth1: app-shared, static IP, gateway=0.0.0.0 so EVE installs no default route.
	eth1Net := devConfig.AddNetwork(evetest.StaticNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
		Subnet:      evetest.IPSubnet("192.168.55.0/24"),
		Gateway:     evetest.IPAddress("0.0.0.0"),
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		NetworkUUID:   eth1Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		StaticIP:      evetest.IPAddress("192.168.55.2"),
	})

	// eth2: app-shared, DHCP. The SDN suppresses the router option so EVE
	// does not install a default route via this port.
	eth2Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet2",
		PhysicalLabel: "eth2",
		InterfaceName: "eth2",
		NetworkUUID:   eth2Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})

	device.ApplyConfig(devConfig, true, true)

	// ni-eth0: PropagateConnectedRoutes=true so the eth0 port subnet (172.22.12.0/24)
	// is delivered to the app. Static route to http-server-0's subnet.
	ni0UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "ni-eth0",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.50.0.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.50.0.2"),
			End:   evetest.IPAddress("10.50.0.254"),
		},
		Gateway:                  evetest.IPAddress("10.50.0.1"),
		PropagateConnectedRoutes: true,
		StaticRoutes: []pillartypes.IPRouteConfig{
			{
				DstNetwork: evetest.IPSubnet("10.20.20.0/24"),
				Gateway:    evetest.IPAddress("10.50.0.1"),
			},
		},
		MTU: 1500,
	})

	// ni-eth1: PropagateConnectedRoutes=true so the eth1 port subnet (192.168.55.0/24)
	// is delivered to the app. Static route to http-server-1's subnet; EVE normalizes
	// the gateway (192.168.55.1) to the NI bridge IP (10.50.1.1) when advertising via
	// DHCP option 121.
	ni1UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "ni-eth1",
		Port:        "ethernet1",
		Subnet:      evetest.IPSubnet("10.50.1.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.50.1.2"),
			End:   evetest.IPAddress("10.50.1.254"),
		},
		Gateway:                  evetest.IPAddress("10.50.1.1"),
		PropagateConnectedRoutes: true,
		StaticRoutes: []pillartypes.IPRouteConfig{
			{
				DstNetwork: evetest.IPSubnet("10.21.21.0/24"),
				Gateway:    evetest.IPAddress("192.168.55.1"),
			},
		},
		MTU: 1500,
	})

	// ni-eth2: PropagateConnectedRoutes=false (negative case — the eth2 port subnet
	// 10.140.2.0/24 must NOT reach the app). Static routes are propagated regardless
	// of PropagateConnectedRoutes, so the app still receives the route to http-server-2.
	ni2UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "ni-eth2",
		Port:        "ethernet2",
		Subnet:      evetest.IPSubnet("10.50.2.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.50.2.2"),
			End:   evetest.IPAddress("10.50.2.254"),
		},
		Gateway:                  evetest.IPAddress("10.50.2.1"),
		PropagateConnectedRoutes: false,
		StaticRoutes: []pillartypes.IPRouteConfig{
			{
				DstNetwork: evetest.IPSubnet("10.22.22.0/24"),
				Gateway:    evetest.IPAddress("10.50.2.1"),
			},
		},
		MTU: 1500,
	})

	const (
		vif0MAC = "02:16:3e:00:01:00"
		vif1MAC = "02:16:3e:00:01:01"
		vif2MAC = "02:16:3e:00:01:02"
	)
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "multi-ni-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "milan4zededa/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode:  eveconfig.VmMode_HVM,
		CPUs:                1,
		MemoryBytes:         500 * evetest.MiB,
		EnforceNetIntfOrder: true,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: ni0UUID,
				MAC:                 evetest.MACAddress(vif0MAC),
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
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif1",
				NetworkInstanceUUID: ni1UUID,
				MAC:                 evetest.MACAddress(vif1MAC),
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif2",
				NetworkInstanceUUID: ni2UUID,
				MAC:                 evetest.MACAddress(vif2MAC),
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	})

	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	device.ApplyConfig(devConfig, false, false)

	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	evetest.Checkpoint("app-running")

	// Wait until app reports all 3 VIFs with IPs from their respective NI subnets.
	ni0Subnet := evetest.IPSubnet("10.50.0.0/24")
	ni1Subnet := evetest.IPSubnet("10.50.1.0/24")
	ni2Subnet := evetest.IPSubnet("10.50.2.0/24")
	timeout := 3 * time.Minute
	var appInfo *eveinfo.ZInfoApp
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App reports 3 VIFs each with an IP",
		func(info *eveinfo.ZInfoApp) bool {
			appInfo = info
			if len(info.Network) != 3 {
				return false
			}
			for _, vif := range info.Network {
				if len(vif.IPAddrs) == 0 {
					return false
				}
			}
			return true
		}).StopIf(appHasError)))
	stopAppWatch()

	t.Expect(appInfo.Network[0].DevName).To(Equal("vif0"))
	t.Expect(appInfo.Network[0].MacAddr).To(Equal(vif0MAC))
	t.Expect(appInfo.Network[0].IPAddrs).To(HaveLen(1))
	t.Expect(ni0Subnet.Contains(evetest.IPAddress(appInfo.Network[0].IPAddrs[0]))).To(BeTrue())

	t.Expect(appInfo.Network[1].DevName).To(Equal("vif1"))
	t.Expect(appInfo.Network[1].MacAddr).To(Equal(vif1MAC))
	t.Expect(appInfo.Network[1].IPAddrs).To(HaveLen(1))
	t.Expect(ni1Subnet.Contains(evetest.IPAddress(appInfo.Network[1].IPAddrs[0]))).To(BeTrue())

	t.Expect(appInfo.Network[2].DevName).To(Equal("vif2"))
	t.Expect(appInfo.Network[2].MacAddr).To(Equal(vif2MAC))
	t.Expect(appInfo.Network[2].IPAddrs).To(HaveLen(1))
	t.Expect(ni2Subnet.Contains(evetest.IPAddress(appInfo.Network[2].IPAddrs[0]))).To(BeTrue())

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second
	log := evetest.Logger()

	// Wait for SSH to be ready; also serves as the first route check.
	log.Infof("Waiting for SSH and checking default route...")
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"ip route", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("default via 10.50.0.1"))
	}, timeout, polling).Should(Succeed())

	evetest.Checkpoint("ssh-ready")

	// Assert that the routing table inside the app reflects:
	//   - default route via ni-eth0 bridge IP (only the mgmt port contributes one),
	//   - static route to http-server-0 subnet via ni-eth0 bridge IP,
	//   - propagated connected route for eth0 port subnet,
	//   - static route to http-server-1 subnet (gateway normalised to ni-eth1 bridge IP),
	//   - propagated connected route for eth1 port subnet,
	//   - static route to http-server-2 subnet via ni-eth2 bridge IP,
	//   - NO connected route for eth2 port subnet (PropagateConnectedRoutes=false).
	output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"ip route", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring("default via 10.50.0.1"))
	t.Expect(output).To(ContainSubstring("10.20.20.0/24 via 10.50.0.1"))
	t.Expect(output).To(ContainSubstring("172.22.12.0/24"))
	// EVE normalises the static-route gateway (192.168.55.1) to the NI bridge IP.
	t.Expect(output).To(ContainSubstring("10.21.21.0/24 via 10.50.1.1"))
	t.Expect(output).To(ContainSubstring("192.168.55.0/24"))
	t.Expect(output).To(ContainSubstring("10.22.22.0/24 via 10.50.2.1"))
	t.Expect(output).NotTo(ContainSubstring("10.140.2.0/24"))

	// Verify that each HTTP server is reachable only via its dedicated port. If EVE
	// misroutes the traffic the SDN router drops it and curl fails, making this the
	// strongest check that propagated routes are both present and used.
	log.Infof("Testing HTTP connectivity via ni-eth0 -> http-server-0")
	output, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS --max-time 10 http://http-server-0.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring("Hello from HTTP server 0!"))

	log.Infof("Testing HTTP connectivity via ni-eth1 -> http-server-1")
	output, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS --max-time 10 http://http-server-1.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring("Hello from HTTP server 1!"))

	log.Infof("Testing HTTP connectivity via ni-eth2 -> http-server-2")
	output, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS --max-time 10 http://http-server-2.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring("Hello from HTTP server 2!"))
}

// TestLocalNIWithMultiplePorts verifies a Local Network Instance configured
// with multiple uplink ports referenced via the predefined shared label "all".
// It checks that EVE selects the working, lowest-cost port for each multi-path
// static route, propagates connected routes for all port subnets, restricts
// port-forwarding to the ports carrying a specific shared label, and fails over
// both routes to the next eligible port when the current one loses connectivity.
//
// Topology
// --------
//
//	                         +-------------------+
//	              ---------->|    eth0 (mgmt)    |---------------
//	              |          |  (DHCP, portfwd)  |              |
//	              |          +-------------------+              |
//	              |                                             |
//	+-----+   +----------+   +-------------------+              |
//	| app |-->| Local NI |-->| eth1 (app-shared) |              |
//	+-----+   +----------+   | (static, portfwd) |              |
//	              |          +-------------------+              |
//	              |                                             |
//	              |          +-------------------+          +--------+  +-------------+
//	              ---------->| eth2 (app-shared) |----------| router |--| http-server |
//	              |          |  (DHCP, portfwd)  |          +--------+  +-------------+
//	              |          +-------------------+               |
//	              |                                              |
//	              |          +-------------------+               |
//	              ---------->|    eth3 (mgmt)    |----------------
//	                         |    (static IP)    |
//	                         +-------------------+
//
// Note: eth1 does NOT have a line to the router -- the SDN has no route to
// http-server.test from that port, so any traffic EVE sends via eth1 toward
// 10.88.88.0/24 is silently dropped.
//
// Network model
// -------------
//   - netmodels.FourPortsMixedAccess -- four ports each on its own bridge and
//     SDN network. eth0 (DHCP, controller-reachable, dns-server at 10.16.16.25
//     and http-server.test at 10.88.88.70 reachable), eth1 (no DHCP, no
//     controller path; only dns-server reachable, http-server NOT reachable
//     from this port), eth2 (DHCP, no controller path; dns-server and
//     http-server.test reachable), eth3 (no DHCP, controller-reachable;
//     dns-server and http-server.test reachable).
//
// Phases
// ------
//  1. Device config: eth0 as management DHCP with shared labels
//     ["internet","httpserver","portfwd"] (cost=0); eth1 as app-shared static
//     172.28.20.10/24 with DNS=10.16.16.25 and shared label ["portfwd"]
//     (cost=0); eth2 as app-shared DHCP with shared labels
//     ["httpserver","portfwd"] (cost=3); eth3 as management static
//     10.40.40.30/24 with DNS=10.16.16.25 and shared labels
//     ["internet","httpserver"] (cost=5, no "portfwd"). One Local NI
//     ("multi-port-ni", subnet 10.50.0.0/24, gateway 10.50.0.1) with
//     port="all" and PropagateConnectedRoutes=true. Two static routes on the
//     NI: 0.0.0.0/0 via label "internet" with gateway ping (GwPingMaxCost=5,
//     PreferLowerCost=true); 10.88.88.0/24 via label "httpserver" with TCP
//     probe to 10.88.88.70:80 (PreferLowerCost=true). One container app
//     (milan4zededa/evetest-ubuntu-ctr:1.0) with a VIF on the NI, a TCP
//     2222->22 port-forward scoped to shared label "portfwd" (eth3 lacks
//     "portfwd" and does not forward), and a default-allow ACL.
//  2. Initial routing: WatchNetworkInstanceInfo waits until the NI is ONLINE
//     with both the default route (0.0.0.0/0) and the http-server route
//     (10.88.88.0/24) resolved via ethernet0 (cost=0, lowest in each label
//     set). All four port subnets (172.22.10.0/24, 172.28.20.0/24,
//     192.168.30.0/24, 10.40.40.0/24) must appear as connected routes in
//     IpRoutes. App VIF receives an IP from 10.50.0.0/24. Both
//     `curl http://http-server.test/helloworld` and
//     `curl http://10.88.88.70/helloworld` from inside the app succeed.
//  3. Failover: UpdateNetworkModel sets eth0 AdminUp=false. EVE detects the
//     loss and reassigns: the default route moves to ethernet3 (next
//     "internet" port, cost=5); the http-server route moves to ethernet2
//     (cheapest remaining "httpserver" port, cost=3). HTTP server remains
//     reachable from inside the app via the new route.
//  4. Restoration: UpdateNetworkModel restores eth0 AdminUp=true. Both routes
//     converge back to ethernet0 (lowest cost). HTTP server remains reachable.
//
// Test params
// -----------
//   - HYPERVISOR. SkipIfHypervisorKubevirt() is called immediately after
//     reading the parameter -- Kubevirt is reserved for cluster tests.
func TestLocalNIWithMultiplePorts(test *testing.T) {
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
			NetworkModel: netmodels.FourPortsMixedAccess,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// eth0: management DHCP, shared labels: internet + httpserver + portfwd, cost=0.
	eth0Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   eth0Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		SharedLabels:  []string{"internet", "httpserver", "portfwd"},
		Cost:          0,
	})

	// eth1: app-shared, static IP 172.28.20.10/24, shared labels: portfwd only,
	// cost=0. The SDN has no route to the HTTP server from this port.
	eth1Net := devConfig.AddNetwork(evetest.StaticNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
		Subnet:      evetest.IPSubnet("172.28.20.0/24"),
		Gateway:     evetest.IPAddress("172.28.20.1"),
		DNSServers:  []net.IP{evetest.IPAddress("10.16.16.25")},
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		NetworkUUID:   eth1Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		StaticIP:      evetest.IPAddress("172.28.20.10"),
		SharedLabels:  []string{"portfwd"},
		Cost:          0,
	})

	// eth2: app-shared, DHCP, shared labels: httpserver + portfwd, cost=3.
	eth2Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet2",
		PhysicalLabel: "eth2",
		InterfaceName: "eth2",
		NetworkUUID:   eth2Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		SharedLabels:  []string{"httpserver", "portfwd"},
		Cost:          3,
	})

	// eth3: management, static IP 10.40.40.30/24, shared labels: internet + httpserver,
	// cost=5. No portfwd label, so port-forwarding rules do not apply here.
	eth3Net := devConfig.AddNetwork(evetest.StaticNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
		Subnet:      evetest.IPSubnet("10.40.40.0/24"),
		Gateway:     evetest.IPAddress("10.40.40.1"),
		DNSServers:  []net.IP{evetest.IPAddress("10.16.16.25")},
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet3",
		PhysicalLabel: "eth3",
		InterfaceName: "eth3",
		NetworkUUID:   eth3Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		StaticIP:      evetest.IPAddress("10.40.40.30"),
		SharedLabels:  []string{"internet", "httpserver"},
		Cost:          5,
	})

	device.ApplyConfig(devConfig, true, true)

	// Local NI spanning all 4 ports (port="all").
	// Static routes use shared labels with probing:
	//   - default: "internet" label (eth0+eth3), gw ping, prefer lower cost.
	//   - http-server subnet: "httpserver" label (eth0+eth2+eth3), TCP probe, prefer lower cost.
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "multi-port-ni",
		Port:        "all",
		Subnet:      evetest.IPSubnet("10.50.0.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.50.0.2"),
			End:   evetest.IPAddress("10.50.0.254"),
		},
		Gateway:                  evetest.IPAddress("10.50.0.1"),
		PropagateConnectedRoutes: true,
		StaticRoutes: []pillartypes.IPRouteConfig{
			{
				DstNetwork:      evetest.IPSubnet("0.0.0.0/0"),
				OutputPortLabel: "internet",
				PortProbe: pillartypes.NIPortProbe{
					EnabledGwPing: true,
					GwPingMaxCost: 5,
				},
				PreferLowerCost: true,
			},
			{
				DstNetwork:      evetest.IPSubnet("10.88.88.0/24"),
				OutputPortLabel: "httpserver",
				PortProbe: pillartypes.NIPortProbe{
					EnabledGwPing: true,
					UserDefinedProbe: pillartypes.ConnectivityProbe{
						Method:    pillartypes.ConnectivityProbeMethodTCP,
						ProbeHost: "10.88.88.70",
						ProbePort: 80,
					},
				},
				PreferLowerCost: true,
			},
		},
		MTU: 1500,
	})

	const vifMAC = "02:16:3e:00:02:00"
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "multi-port-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "milan4zededa/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode:  eveconfig.VmMode_HVM,
		CPUs:                1,
		MemoryBytes:         500 * evetest.MiB,
		EnforceNetIntfOrder: true,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				MAC:                 evetest.MACAddress(vifMAC),
				// Port-forwarding is scoped to the "portfwd" label:
				// eth0, eth1, eth2 forward; eth3 (no "portfwd" label) does not.
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
						AppPort:      22,
						AdapterLabel: "portfwd",
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
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	device.ApplyConfig(devConfig, false, false)

	// Phase 1: verify initial routing state.
	// NI should be ONLINE with both static routes selecting ethernet0 (lowest cost).
	timeout := 3 * time.Minute
	var niInfo *eveinfo.ZInfoNetworkInstance
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI ONLINE with default route via ethernet0",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			if info.State != eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE {
				return false
			}
			route := findRoute(info.IpRoutes, "0.0.0.0/0")
			return route != nil && route.Port == "ethernet0"
		}).StopIf(niHasError)))
	stopNIWatch()
	t.Expect(niInfo.NetworkErr).To(BeEmpty())

	evetest.Checkpoint("ni-online")

	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)

	evetest.Checkpoint("app-running")

	// Both static routes should be resolved via ethernet0 (cost=0, lowest).
	defaultRoute := findRoute(niInfo.IpRoutes, "0.0.0.0/0")
	t.Expect(defaultRoute).NotTo(BeNil())
	t.Expect(defaultRoute.Port).To(Equal("ethernet0"))

	httpRoute := findRoute(niInfo.IpRoutes, "10.88.88.0/24")
	t.Expect(httpRoute).NotTo(BeNil())
	t.Expect(httpRoute.Port).To(Equal("ethernet0"))

	// All four port subnets must appear as connected routes (PropagateConnectedRoutes=true).
	t.Expect(findRoute(niInfo.IpRoutes, "172.22.10.0/24")).NotTo(BeNil())
	t.Expect(findRoute(niInfo.IpRoutes, "172.28.20.0/24")).NotTo(BeNil())
	t.Expect(findRoute(niInfo.IpRoutes, "192.168.30.0/24")).NotTo(BeNil())
	t.Expect(findRoute(niInfo.IpRoutes, "10.40.40.0/24")).NotTo(BeNil())

	// Wait for the app VIF to receive an IP from the NI subnet.
	niSubnet := evetest.IPSubnet("10.50.0.0/24")
	var appInfo *eveinfo.ZInfoApp
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App VIF has IP from NI subnet",
		func(info *eveinfo.ZInfoApp) bool {
			appInfo = info
			if len(info.Network) != 1 {
				return false
			}
			return len(info.Network[0].IPAddrs) > 0
		}).StopIf(appHasError)))
	stopAppWatch()

	t.Expect(appInfo.Network[0].MacAddr).To(Equal(vifMAC))
	t.Expect(niSubnet.Contains(evetest.IPAddress(appInfo.Network[0].IPAddrs[0]))).To(BeTrue())

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second
	log := evetest.Logger()

	// Verify HTTP server is reachable from inside the app (port-fwd through any
	// of eth0/eth1/eth2 -- all carry the "portfwd" label).
	log.Infof("Phase 1: waiting for SSH and testing HTTP connectivity...")
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"curl -sS --max-time 10 http://http-server.test/helloworld", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("Hello from HTTP server!"))
	}, 5*time.Minute, polling).Should(Succeed())

	evetest.Checkpoint("http-reachable")

	// Verify per-port port-forwarding: eth0, eth1, eth2 carry the "portfwd" shared
	// label and must forward port 2222; eth3 lacks "portfwd" and must not.
	log.Infof("Phase 1: verifying per-port port-forwarding (TCP dial to port 2222)...")
	portFwdDialTimeout := 3 * time.Second
	tryConnect := func(ipStr string) error {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ipStr, "2222"), portFwdDialTimeout)
		if err == nil {
			conn.Close()
		}
		return err
	}
	eth0IPs := device.GetDeviceIPAddress("ethernet0")
	t.Expect(eth0IPs).NotTo(BeEmpty())
	t.Expect(tryConnect(eth0IPs[0].String())).To(Succeed()) // eth0: portfwd label
	t.Expect(tryConnect("172.28.20.10")).To(Succeed())      // eth1: portfwd label (static)
	eth2IPs := device.GetDeviceIPAddress("ethernet2")
	t.Expect(eth2IPs).NotTo(BeEmpty())
	t.Expect(tryConnect(eth2IPs[0].String())).To(Succeed()) // eth2: portfwd label
	t.Expect(tryConnect("10.40.40.30")).NotTo(Succeed())    // eth3: no portfwd label

	evetest.Checkpoint("portfwd-checked")

	// Also verify by raw IP (bypasses DNS, exercises the forwarding table directly).
	output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS --max-time 10 http://10.88.88.70/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring("Hello from HTTP server!"))

	// Phase 2: failover. Bring eth0 AdminUp=false.
	// Expected outcome:
	//   - default route (0.0.0.0/0): fails over to ethernet3 (next "internet" port, cost=5).
	//   - http-server route (10.88.88.0/24): fails over to ethernet2 (cheapest "httpserver"
	//     port other than the failing eth0, cost=3).
	log.Infof("Phase 2: bringing eth0 AdminUp=false to trigger failover...")
	updatedModel := proto.Clone(netmodels.FourPortsMixedAccess).(*api.NetworkModel)
	for _, p := range updatedModel.Ports {
		if p.LogicalLabel == "eth0" {
			p.AdminUp = false
		}
	}
	evetest.UpdateNetworkModel(updatedModel)
	// Ensure the model is restored on exit even if the test fails mid-phase.
	defer evetest.UpdateNetworkModel(netmodels.FourPortsMixedAccess)

	failoverTimeout := 10 * time.Minute

	niUpdates, stopNIWatch = device.WatchNetworkInstanceInfo(niUUID)
	t.Eventually(niUpdates, failoverTimeout).Should(Receive(matchers.SatisfyPredicate(
		"Default route fails over to ethernet3",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			route := findRoute(info.IpRoutes, "0.0.0.0/0")
			return route != nil && route.Port == "ethernet3"
		})))
	stopNIWatch()

	niUpdates, stopNIWatch = device.WatchNetworkInstanceInfo(niUUID)
	t.Eventually(niUpdates, failoverTimeout).Should(Receive(matchers.SatisfyPredicate(
		"HTTP server route fails over to ethernet2",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			route := findRoute(info.IpRoutes, "10.88.88.0/24")
			return route != nil && route.Port == "ethernet2"
		})))
	stopNIWatch()

	evetest.Checkpoint("failover-done")

	// HTTP server must still be reachable after failover (now via ethernet2).
	log.Infof("Phase 2: verifying HTTP connectivity after failover (via ethernet2)...")
	output, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS --max-time 10 http://http-server.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring("Hello from HTTP server!"))

	// Phase 3: restore eth0. Both routes must converge back to ethernet0.
	log.Infof("Phase 3: restoring eth0, expecting routes to converge back to ethernet0...")
	evetest.UpdateNetworkModel(netmodels.FourPortsMixedAccess)

	niUpdates, stopNIWatch = device.WatchNetworkInstanceInfo(niUUID)
	t.Eventually(niUpdates, failoverTimeout).Should(Receive(matchers.SatisfyPredicate(
		"Both routes converge back to ethernet0",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			dr := findRoute(info.IpRoutes, "0.0.0.0/0")
			hr := findRoute(info.IpRoutes, "10.88.88.0/24")
			return dr != nil && dr.Port == "ethernet0" &&
				hr != nil && hr.Port == "ethernet0"
		})))
	stopNIWatch()

	evetest.Checkpoint("routes-restored")

	log.Infof("Phase 3: verifying HTTP connectivity after route restoration...")
	output, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		"curl -sS --max-time 10 http://http-server.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(output).To(ContainSubstring("Hello from HTTP server!"))
}

// findRoute returns the first IPRoute in routes whose DestinationNetwork matches dst,
// or nil if no such route exists.
func findRoute(routes []*eveinfo.IPRoute, dst string) *eveinfo.IPRoute {
	for _, r := range routes {
		if r.DestinationNetwork == dst {
			return r
		}
	}
	return nil
}

// TestApplicationGateway verifies the “application gateway” topology, where
// one application (app-gw) functions as an IP router, NAT device, and firewall
// for two client applications. The clients are connected through air-gapped
// Local Network Interfaces (NIs), and DHCP option 121 is used to distribute
// static routes that direct client traffic through the gateway application.
//
// Topology
// --------
//
//	+-------------+   +---------+   +-------------------+   +---------------+
//	| app-client1 |-->| ni-eth0 |---| eth0 (mgmt, DHCP) |...| http-server-1 |
//	+------+------+   +---------+   +-------------------+   +---------------+
//	       |
//	       |  airgap1 (172.28.1.0/24)
//	       |  static rt: 10.21.21.0/24 via 172.28.1.2
//	       +----------------------------> +--------+   +-----------+   +------------------+   +---------------+
//	                                      | app-gw |-->| ni-eth1   |---| eth1 (app, DHCP) |...| http-server-2 |
//	       +----------------------------> +--------+   | (Switch)  |   +------------------+   +---------------+
//	       |                                           +-----------+
//	       |  airgap2 (172.28.2.0/24)
//	       |  default route via 172.28.2.2
//	+------+------+
//	| app-client2 |
//	+-------------+
//
// Network model
// -------------
//   - netmodels.AppGatewayTopology -- two ports: eth0 (DHCP, 172.22.12.0/24,
//     controller-reachable; dns-server at 10.16.16.25 and http-server-1.test
//     at 10.20.20.70 reachable) and eth1 (DHCP, 10.203.10.0/24, app-shared
//     Switch NI target; same DNS server as eth0 and http-server-2.test reachable
//     at 10.21.21.70, but NOT http-server-1.test). A static DHCP reservation on
//     the eth1 SDN network assigns IP 10.203.10.150 to MAC 02:16:3e:01:00:00
//     (app-gw's WAN VIF). RoutesTowardsEve on the eth1 router covers
//     172.28.1.0/24 and 172.28.2.0/24 via 10.203.10.150, so that the SDN
//     router can deliver return traffic to the air-gap subnets via app-gw.
//
// Phases
// ------
//  1. Device config: ethernet0 as management DHCP (PhyIoUsageMgmtAndApps);
//     ethernet1 as app-shared with NoIPNetworkConfig (PhyIoUsageShared; EVE
//     needs no host IP on a Switch NI uplink). Four NIs: ni-eth0 (Local,
//     10.50.0.0/24, gateway 10.50.0.1) on ethernet0; ni-eth1 (Switch) on
//     ethernet1; airgap1 (Local, no uplink, 172.28.1.0/24, StaticRoute
//     10.21.21.0/24 via 172.28.1.2, DNSServers=[10.16.16.25]); airgap2
//     (Local, no uplink, 172.28.2.0/24, StaticRoute 0.0.0.0/0 via 172.28.2.2,
//     DNSServers=[172.28.2.1], StaticDNSEntries=[http-server-2.test, http-server-1.test]).
//     Three container apps (milan4zededa/evetest-ubuntu-ctr:1.0) with
//     default-allow ACLs: app-gw (3 VIFs: vif0→ni-eth1 MAC 02:16:3e:01:00:00,
//     vif1→airgap1 static 172.28.1.2, vif2→airgap2 static 172.28.2.2);
//     app-client1 (2 VIFs: vif0→ni-eth0 portfwd 2222→22, vif1→airgap1 static
//     172.28.1.3); app-client2 (1 VIF: vif0→airgap2 static 172.28.2.3;
//     reachable only via app-gw).
//  2. NI and app readiness: WatchNetworkInstanceInfo waits for all four NIs to
//     reach ONLINE; WaitUntilAppIsRunning waits for all three apps to reach
//     RUNNING; WatchAppInfo verifies each app reports all VIFs with IPs --
//     in particular app-gw vif0=10.203.10.150 (MAC-matched DHCP reservation).
//  3. Gateway setup (RunShellScriptInsideApp on app-gw via Switch NI IP
//     10.203.10.150): enable IP forwarding and add
//     `POSTROUTING -o eth0 MASQUERADE` on the WAN VIF. Once IP forwarding is
//     active, app-client2 (172.28.2.3) becomes reachable via the SDN
//     RoutesTowardsEve (172.28.2.0/24 → 10.203.10.150).
//  4. app-client1 assertions (RunShellScriptInsideApp via portfwd 2222→22):
//     `ip route` must contain `default via 10.50.0.1`, `10.50.0.0/24`
//     (ni-eth0), `172.28.1.0/24` (airgap1), and `10.21.21.0/24 via 172.28.1.2`
//     (propagated static route). `curl http://http-server-1.test/helloworld`
//     succeeds via the default route (ni-eth0 → eth0). `curl
//     http://http-server-2.test/helloworld` succeeds via the propagated static
//     route (airgap1 → app-gw → ni-eth1 → eth1).
//  5. app-client2 assertions (RunShellScriptInsideApp via RoutesTowardsEve,
//     app IP 172.28.2.3):
//     `ip route` must contain `default via 172.28.2.2` and `172.28.2.0/24`.
//     `curl http://http-server-2.test/helloworld` succeeds (airgap2 → app-gw
//     → ni-eth1 → eth1). `curl http://http-server-1.test/helloworld` FAILS
//     with timeout: app-gw has no route to http-server-1's subnet because
//     the SDN eth1 router does not expose 10.20.20.0/24. On app-gw,
//     `iptables -t nat -L POSTROUTING -nv` is parsed to confirm the
//     MASQUERADE rule has a non-zero packet counter.
//
// Test params
// -----------
//   - HYPERVISOR. SkipIfHypervisorKubevirt() is called immediately after
//     reading the parameter -- Kubevirt is reserved for cluster tests.
func TestApplicationGateway(test *testing.T) {
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
			NetworkModel: netmodels.AppGatewayTopology,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// eth0: management, DHCP.
	eth0Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   eth0Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})

	// eth1: app-shared, no EVE host IP needed (Switch NI takes the full bridge).
	noIPNet := devConfig.AddNetwork(evetest.NoIPNetworkConfig{})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		NetworkUUID:   noIPNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})

	device.ApplyConfig(devConfig, true, true)

	// ni-eth0: Local NI on eth0 — used by app-client1 for its default route
	// and SSH access (portfwd 2222→22).
	niEth0UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "ni-eth0",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.50.0.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.50.0.2"),
			End:   evetest.IPAddress("10.50.0.99"),
		},
		Gateway: evetest.IPAddress("10.50.0.1"),
		MTU:     1500,
	})

	// ni-eth1: Switch NI on eth1 — app-gw's WAN egress leg.
	niEth1UUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "ni-eth1",
		Port:        "ethernet1",
		MTU:         1500,
	})

	// airgap1: air-gap Local NI (no uplink) — LAN between app-gw and app-client1.
	// Propagates static route 10.21.21.0/24 (http-server-2 subnet) via app-gw (172.28.1.2).
	airgap1UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "airgap1",
		Port:        "",
		Subnet:      evetest.IPSubnet("172.28.1.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("172.28.1.10"),
			End:   evetest.IPAddress("172.28.1.100"),
		},
		Gateway: evetest.IPAddress("172.28.1.1"),
		StaticRoutes: []pillartypes.IPRouteConfig{
			{
				DstNetwork: evetest.IPSubnet("10.21.21.0/24"),
				Gateway:    evetest.IPAddress("172.28.1.2"),
			},
		},
		MTU: 1500,
	})

	// airgap2: air-gap Local NI (no uplink) — LAN between app-gw and app-client2.
	// Propagates a default route via app-gw (172.28.2.2) so all client2 traffic
	// flows through app-gw. DNSServers must point to the bridge IP so that EVE
	// advertises dnsmasq itself as the DNS server; StaticDNSEntries are then
	// served from hostsdir without upstream forwarding (no uplink available).
	// Both servers are listed so the negative curl fails at TCP, not DNS.
	airgap2UUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "airgap2",
		Port:        "",
		Subnet:      evetest.IPSubnet("172.28.2.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("172.28.2.10"),
			End:   evetest.IPAddress("172.28.2.100"),
		},
		Gateway:    evetest.IPAddress("172.28.2.1"),
		DNSServers: []net.IP{evetest.IPAddress("172.28.2.1")},
		StaticDNSEntries: []pillartypes.DNSNameToIP{
			{HostName: "http-server-2.test", IPs: []net.IP{evetest.IPAddress("10.21.21.70")}},
			{HostName: "http-server-1.test", IPs: []net.IP{evetest.IPAddress("10.20.20.70")}},
		},
		StaticRoutes: []pillartypes.IPRouteConfig{
			{
				DstNetwork: evetest.IPSubnet("0.0.0.0/0"),
				Gateway:    evetest.IPAddress("172.28.2.2"),
			},
		},
		MTU: 1500,
	})

	const (
		// app-gw VIF MACs.
		// vif0 MAC must match the SDN DHCP static reservation → 10.203.10.150.
		appGwVif0MAC = "02:16:3e:01:00:00"
		appGwVif1MAC = "02:16:3e:01:00:01"
		appGwVif2MAC = "02:16:3e:01:00:02"
		// app-client1 VIF MACs.
		appC1Vif0MAC = "02:16:3e:01:01:00"
		appC1Vif1MAC = "02:16:3e:01:01:01"
		// app-client2 VIF MAC.
		appC2Vif0MAC = "02:16:3e:01:02:00"
	)

	appImage := evetest.DockerContainer{
		ImageName: "milan4zededa/evetest-ubuntu-ctr",
		Tag:       "1.0",
	}

	// app-gw: 3 VIFs.
	//   eth0 (vif0) = ni-eth1 Switch NI — WAN egress; MASQUERADE applied here.
	//   eth1 (vif1) = airgap1           — LAN facing app-client1 (172.28.1.2).
	//   eth2 (vif2) = airgap2           — LAN facing app-client2 (172.28.2.2).
	// SSH access is via the Switch NI IP (10.203.10.150) directly.
	allowAll := []evetest.ACLAllowRule{
		{
			Protocol:     evetest.NetworkProtocolAny,
			RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
		},
	}
	appGwUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName:         "app-gw",
		Activate:            true,
		Image:               appImage,
		VirtualizationMode:  eveconfig.VmMode_HVM,
		CPUs:                1,
		MemoryBytes:         500 * evetest.MiB,
		EnforceNetIntfOrder: true,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niEth1UUID,
				MAC:                 evetest.MACAddress(appGwVif0MAC),
				ACLAllowRules:       allowAll,
			},
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif1",
				NetworkInstanceUUID: airgap1UUID,
				MAC:                 evetest.MACAddress(appGwVif1MAC),
				StaticIP:            evetest.IPAddress("172.28.1.2"),
				ACLAllowRules:       allowAll,
			},
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif2",
				NetworkInstanceUUID: airgap2UUID,
				MAC:                 evetest.MACAddress(appGwVif2MAC),
				StaticIP:            evetest.IPAddress("172.28.2.2"),
				ACLAllowRules:       allowAll,
			},
		},
	})

	// app-client1: 2 VIFs.
	//   eth0 (vif0) = ni-eth0  — default route + SSH (portfwd 2222→22).
	//   eth1 (vif1) = airgap1  — receives static route 10.21.21.0/24 via app-gw.
	appC1UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName:         "app-client1",
		Activate:            true,
		Image:               appImage,
		VirtualizationMode:  eveconfig.VmMode_HVM,
		CPUs:                1,
		MemoryBytes:         500 * evetest.MiB,
		EnforceNetIntfOrder: true,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niEth0UUID,
				MAC:                 evetest.MACAddress(appC1Vif0MAC),
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
						AppPort:      22,
					},
				},
				ACLAllowRules: allowAll,
			},
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif1",
				NetworkInstanceUUID: airgap1UUID,
				MAC:                 evetest.MACAddress(appC1Vif1MAC),
				StaticIP:            evetest.IPAddress("172.28.1.3"),
				ACLAllowRules:       allowAll,
			},
		},
	})

	// app-client2: 1 VIF.
	//   eth0 (vif0) = airgap2  — receives propagated default route via app-gw
	//                            (172.28.2.2); reachable via RoutesTowardsEve
	//                            once app-gw has IP forwarding enabled.
	appC2UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName:         "app-client2",
		Activate:            true,
		Image:               appImage,
		VirtualizationMode:  eveconfig.VmMode_HVM,
		CPUs:                1,
		MemoryBytes:         500 * evetest.MiB,
		EnforceNetIntfOrder: true,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: airgap2UUID,
				MAC:                 evetest.MACAddress(appC2Vif0MAC),
				StaticIP:            evetest.IPAddress("172.28.2.3"),
				ACLAllowRules:       allowAll,
			},
		},
	})

	ni0Updates, stopNI0Watch := device.WatchNetworkInstanceInfo(niEth0UUID)
	ni1Updates, stopNI1Watch := device.WatchNetworkInstanceInfo(niEth1UUID)
	ag1Updates, stopAG1Watch := device.WatchNetworkInstanceInfo(airgap1UUID)
	ag2Updates, stopAG2Watch := device.WatchNetworkInstanceInfo(airgap2UUID)
	appGwUpdates, stopAppGwWatch := device.WatchAppInfo(appGwUUID)
	appC1Updates, stopAppC1Watch := device.WatchAppInfo(appC1UUID)
	appC2Updates, stopAppC2Watch := device.WatchAppInfo(appC2UUID)
	device.ApplyConfig(devConfig, false, false)

	niTimeout := 3 * time.Minute

	t.Eventually(ni0Updates, niTimeout).Should(Receive(matchers.SatisfyPredicate(
		"ni-eth0 is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		}).StopIf(niHasError)))
	stopNI0Watch()

	t.Eventually(ni1Updates, niTimeout).Should(Receive(matchers.SatisfyPredicate(
		"ni-eth1 is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		}).StopIf(niHasError)))
	stopNI1Watch()

	t.Eventually(ag1Updates, niTimeout).Should(Receive(matchers.SatisfyPredicate(
		"airgap1 is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		}).StopIf(niHasError)))
	stopAG1Watch()

	t.Eventually(ag2Updates, niTimeout).Should(Receive(matchers.SatisfyPredicate(
		"airgap2 is ONLINE",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		}).StopIf(niHasError)))
	stopAG2Watch()

	evetest.Checkpoint("nis-online")

	device.WaitUntilAppIsRunning(appGwUUID, 5*time.Minute)
	device.WaitUntilAppIsRunning(appC1UUID, 5*time.Minute)
	device.WaitUntilAppIsRunning(appC2UUID, 5*time.Minute)

	evetest.Checkpoint("apps-running")

	// Wait until each app reports all its VIFs with IP addresses.
	appTimeout := 3 * time.Minute
	var appGwInfo, appC1Info, appC2Info *eveinfo.ZInfoApp

	t.Eventually(appGwUpdates, appTimeout).Should(Receive(matchers.SatisfyPredicate(
		"app-gw reports 3 VIFs with IPs",
		func(info *eveinfo.ZInfoApp) bool {
			appGwInfo = info
			if len(info.Network) != 3 {
				return false
			}
			for _, vif := range info.Network {
				if len(vif.IPAddrs) == 0 {
					return false
				}
			}
			return true
		}).StopIf(appHasError)))
	stopAppGwWatch()

	t.Eventually(appC1Updates, appTimeout).Should(Receive(matchers.SatisfyPredicate(
		"app-client1 reports 2 VIFs with IPs",
		func(info *eveinfo.ZInfoApp) bool {
			appC1Info = info
			if len(info.Network) != 2 {
				return false
			}
			for _, vif := range info.Network {
				if len(vif.IPAddrs) == 0 {
					return false
				}
			}
			return true
		}).StopIf(appHasError)))
	stopAppC1Watch()

	t.Eventually(appC2Updates, appTimeout).Should(Receive(matchers.SatisfyPredicate(
		"app-client2 reports 1 VIF with IP",
		func(info *eveinfo.ZInfoApp) bool {
			appC2Info = info
			if len(info.Network) != 1 {
				return false
			}
			for _, vif := range info.Network {
				if len(vif.IPAddrs) == 0 {
					return false
				}
			}
			return true
		}).StopIf(appHasError)))
	stopAppC2Watch()

	// Verify VIF IPs.
	ni0Subnet := evetest.IPSubnet("10.50.0.0/24")

	// app-gw: vif0 on Switch NI gets static DHCP → 10.203.10.150.
	t.Expect(appGwInfo.Network[0].DevName).To(Equal("vif0"))
	t.Expect(appGwInfo.Network[0].MacAddr).To(Equal(appGwVif0MAC))
	t.Expect(appGwInfo.Network[0].IPAddrs).To(ContainElement("10.203.10.150"))
	t.Expect(appGwInfo.Network[1].DevName).To(Equal("vif1"))
	t.Expect(appGwInfo.Network[1].IPAddrs).To(ContainElement("172.28.1.2"))
	t.Expect(appGwInfo.Network[2].DevName).To(Equal("vif2"))
	t.Expect(appGwInfo.Network[2].IPAddrs).To(ContainElement("172.28.2.2"))

	// app-client1: vif0 gets a DHCP IP from ni-eth0 subnet; vif1 is static 172.28.1.3.
	t.Expect(appC1Info.Network[0].DevName).To(Equal("vif0"))
	t.Expect(appC1Info.Network[0].MacAddr).To(Equal(appC1Vif0MAC))
	t.Expect(appC1Info.Network[0].IPAddrs).To(HaveLen(1))
	t.Expect(ni0Subnet.Contains(evetest.IPAddress(appC1Info.Network[0].IPAddrs[0]))).To(BeTrue())
	t.Expect(appC1Info.Network[1].DevName).To(Equal("vif1"))
	t.Expect(appC1Info.Network[1].IPAddrs).To(ContainElement("172.28.1.3"))

	// app-client2: vif0 is static 172.28.2.3 (airgap2).
	t.Expect(appC2Info.Network[0].DevName).To(Equal("vif0"))
	t.Expect(appC2Info.Network[0].IPAddrs).To(ContainElement("172.28.2.3"))

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second
	log := evetest.Logger()

	// Wait for app-gw SSH (via Switch NI IP 10.203.10.150), then enable IP
	// forwarding and add MASQUERADE on eth0 (the ni-eth1/WAN vif) so air-gap
	// client traffic exits with app-gw's IP, making return traffic flow back
	// through app-gw.
	log.Infof("Waiting for app-gw SSH...")
	t.Eventually(func(gt Gomega) {
		_, _, err := device.RunShellScriptInsideApp(appGwUUID, appAuth,
			"echo ok", sshTimeout, 0)
		gt.Expect(err).ToNot(HaveOccurred())
	}, 5*time.Minute, polling).Should(Succeed())

	evetest.Checkpoint("app-gw-ssh-ready")

	log.Infof("Configuring app-gw: IP forwarding + MASQUERADE on eth0 (WAN)")
	_, _, err := device.RunShellScriptInsideApp(appGwUUID, appAuth,
		"sysctl -w net.ipv4.ip_forward=1; "+
			"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
		sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())

	evetest.Checkpoint("apps-configured")

	// Verify app-client1 route table and wait for SSH readiness in one pass.
	log.Infof("Waiting for app-client1 SSH and checking route table...")
	var c1Routes string
	t.Eventually(func(gt Gomega) {
		out, _, err := device.RunShellScriptInsideApp(appC1UUID, appAuth,
			"ip route", sshTimeout, 0)
		gt.Expect(err).ToNot(HaveOccurred())
		gt.Expect(out).To(ContainSubstring("default via 10.50.0.1"))
		c1Routes = out
	}, 3*time.Minute, polling).Should(Succeed())

	evetest.Checkpoint("client1-ssh-ready")

	t.Expect(c1Routes).To(ContainSubstring("10.50.0.0/24"))
	t.Expect(c1Routes).To(ContainSubstring("172.28.1.0/24"))
	t.Expect(c1Routes).To(ContainSubstring("10.21.21.0/24 via 172.28.1.2"))

	// app-client1: curl http-server-1 (direct via ni-eth0 → eth0).
	log.Infof("app-client1: curl http-server-1.test (direct via ni-eth0)...")
	out, _, err := device.RunShellScriptInsideApp(appC1UUID, appAuth,
		"curl -sS --max-time 10 http://http-server-1.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("Hello from HTTP server 1!"))

	// app-client1: curl http-server-2 (via airgap1 static route → app-gw → ni-eth1).
	log.Infof("app-client1: curl http-server-2.test (via airgap1 → app-gw → ni-eth1)...")
	out, _, err = device.RunShellScriptInsideApp(appC1UUID, appAuth,
		"curl -sS --max-time 10 http://http-server-2.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("Hello from HTTP server 2!"))

	// Verify app-client2 route table.
	out, _, err = device.RunShellScriptInsideApp(appC2UUID, appAuth,
		"ip route", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("default via 172.28.2.2"))
	t.Expect(out).To(ContainSubstring("172.28.2.0/24"))

	// app-client2: curl http-server-2 (via airgap2 default route → app-gw → ni-eth1).
	log.Infof("app-client2: curl http-server-2.test (via airgap2 → app-gw → ni-eth1)...")
	out, _, err = device.RunShellScriptInsideApp(appC2UUID, appAuth,
		"curl -sS --max-time 10 http://http-server-2.test/helloworld", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("Hello from HTTP server 2!"))

	// Negative test: app-client2 cannot reach http-server-1.
	// Traffic goes via the default route (app-gw on airgap2); app-gw forwards
	// via ni-eth1 (WAN), but the SDN eth1 router has no route to http-server-1's
	// subnet (10.20.20.0/24), so the packet is dropped.
	log.Infof("app-client2: curl http-server-1.test (expected timeout)...")
	out, _, err = device.RunShellScriptInsideApp(appC2UUID, appAuth,
		"curl --max-time 5 http://http-server-1.test/helloworld",
		30*time.Second, 0)
	t.Expect(err).To(HaveOccurred())

	// Confirm MASQUERADE is active on app-gw: extract the packet counter from
	// the MASQUERADE rule and verify it is non-zero (traffic from both clients
	// traversed app-gw's WAN VIF above).
	log.Infof("app-gw: verifying MASQUERADE rule has non-zero packet counters...")
	out, _, err = device.RunShellScriptInsideApp(appGwUUID, appAuth,
		"cnt=$(iptables -t nat -L POSTROUTING -nv | awk '/MASQUERADE/{print $1; exit}'); "+
			"[ \"${cnt:-0}\" -gt 0 ] && echo MASQUERADE_ACTIVE:$cnt || echo MASQUERADE_ZERO",
		sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(out).To(ContainSubstring("MASQUERADE_ACTIVE:"))
}

// TestMgmtTrafficRoutedViaApp : TODO replicate github.com/lf-edge/eden/examples/mgmt-over-app
func TestMgmtTrafficRoutedViaApp(test *testing.T) {
	test.Skip("not yet implemented")
}
