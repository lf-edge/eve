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

// TestSwitchNIWithMultiplePorts verifies a Switch Network Instance configured
// with MULTIPLE physical ports forming redundant L2 links. Spanning Tree
// Protocol (STP) must converge to a loop-free topology, the bridge must
// enable BPDU guard on application VIFs and on user-tagged
// "ports_with_bpdu_guard", and a forwarding-port failure must cause STP to
// re-converge so that previously blocked links carry traffic.
//
// Replicates the eden SDN example:
//
//	github.com/lf-edge/eden/sdn/examples/switch-ni-multiple-ports
//	(redundant-links subdirectory)
//
// Topology
// --------
//
//	                          +-----------------+
//	                          | eth0 (EVE mgmt) |----------------------------
//	                          |     (DHCP)      |                           |
//	                          +-----------------+                           |
//	                                                                        |
//	+-----+   +-----------+   +-------------------+                         |
//	| app |-->| Switch NI |-->| eth1 (app-shared) |      +--------+      +--------+   +------------+
//	+-----+   +-----------+   | (No IP, L2-only)  |------| switch |------| router |---| httpserver |
//	              |           +-------------------+      | (STP)  |      +--------+   +------------+
//	              |                                      +--------+
//	              |           +-------------------+           |
//	              |---------->| eth2 (app-shared) |-----------+
//	              |           | (No IP, L2-only)  |
//	              |           +-------------------+
//	              |
//	              |           +-------------------+      +--------+   +-------------------+
//	              |---------->| eth3 (app-shared) |------| bridge |---| leaf-httpserver   |
//	                          | "edge-port" label |      | no STP |   +-------------------+
//	                          | (No IP, L2-only)  |      +--------+
//	                          +-------------------+
//
// eth1 + eth2 form redundant L2 paths into the STP-running SDN bridge, so
// the SDN bridge and EVE's switch NI bridge together form a loop that STP
// must resolve by blocking one of the two ports.
//
// Network model
// -------------
//   - netmodels.FourPortsWithSTPBridge: eth0 is on its own DHCP management
//     bridge. eth1 and eth2 are both connected to a single STP-enabled bridge
//     (WithStp=true) that in turn connects to an SDN router providing DHCP
//     (10.51.0.0/24) and routing to http-server.test -- the loop between
//     EVE's NI bridge and this SDN bridge is what STP must resolve. eth3 is
//     on a separate non-STP bridge (bridge2) connecting only leaf-httpserver.test
//     directly on L2. It is expected that eth1, eth2 and eth3 are bridged together
//     inside EVE, therefore leaf-httpserver.test uses IP from the 10.51.0.0/24
//     subnet.
//
// Device configuration
// --------------------
//   - ethernet0: DHCP, mgmt+apps.
//   - ethernet1, ethernet2, ethernet3: L2-only, no DHCP client. All three carry
//     the shared label "switch-ports"; ethernet3 additionally carries "edge-port".
//   - Switch NI "switch-ni" with Port="switch-ports" (resolves to ethernet1,
//     ethernet2, ethernet3). BPDU enabled for ethernet3 by referencing
//     the "edge-port" label.
//   - One container app (lfedge/evetest-ubuntu-ctr:1.0) with one VIF
//     on the NI and allow-all ACL. The SDN router on bridge1 provides DHCP,
//     so the app obtains an IP from 10.51.0.0/24.
//
// Phases
// ------
//
//  1. NI and app creation: the Switch NI "switch-ni" and the container app
//     are deployed together. The NI reaches ZNETINST_STATE_ONLINE with 3
//     AssignedAdapters (ethernet1, ethernet2, ethernet3) and an empty
//     BridgeIPAddr. The app obtains a DHCP address from 10.51.0.0/24 via
//     the SDN router; the NI publishes VIF "nbu1x1" with the expected MAC
//     and AppID.
//
//  2. STP convergence: `brctl showstp <NI bridge>` is polled over SSH until
//     among eth1 and eth2 exactly one reports "forwarding" and the other
//     "blocking" -- the loop between the two bridges requires STP to block
//     one redundant link. eth3 reports "forwarding" because bridge2 has no
//     STP peer. BPDU guard sysfs is then read: nbu1x1 (the app VIF) has
//     bpdu_guard=1 (always on for app VIFs); eth3 has bpdu_guard=1
//     (PortsWithBpduGuard="edge-port"); eth1 and eth2 have bpdu_guard=0
//     (active STP participants). From inside the app,
//     `curl http://http-server.test/helloworld` succeeds via whichever port
//     STP chose as forwarding. A second curl to
//     `leaf-httpserver.test/helloworld` confirms L2 reachability to the
//     directly-connected endpoint on bridge2 (eth3 path, same L2 segment).
//
//  3. STP failover: the forwarding port identified in Phase 2 has its AdminUp
//     set to false in the SDN model. `brctl showstp` is polled until the
//     previously-blocking port transitions to "forwarding" (STP
//     re-convergence; up to 2 minutes for standard STP, seconds for RSTP).
//     App connectivity is re-confirmed via curl after re-convergence. The
//     SDN model is then restored to bring the failed port back up.
//
// Test params
// -----------
//   - HYPERVISOR. The test calls evetest.SkipIfHypervisorKubevirt() right
//     after reading the parameter -- Kubevirt is reserved for cluster tests.
func TestSwitchNIWithMultiplePorts(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	// Kubevirt is only supported by cluster tests.
	evetest.SkipIfHypervisorKubevirt()

	devName := "edge-dev"
	requiredDevice := evetest.RequireEdgeDevice{
		Name:              devName,
		WithHypervisor:    hypervisor,
		DeviceReusePolicy: evetest.ResetDeviceConfig,
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.FourPortsWithSTPBridge,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build the device configuration.
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
	// Each gets no-IP network config (no static IP, no DHCP client).
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
		SharedLabels:  []string{"switch-ports", "edge-port"},
	})

	// Apply the base adapter configuration.
	device.ApplyConfig(devConfig, true, true)

	// Add Switch NI with all three app-shared ports.
	// BPDU guard is enabled on eth3 ("edge-port" label).
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName:   "switch-ni",
		Port:          "switch-ports",
		STPConfig:     pillartypes.STPConfig{PortsWithBpduGuard: "edge-port"},
		EnableFlowlog: false,
	})

	// Add one container app connected to the Switch NI. Since it's a Switch NI,
	// the SDN router on bridge1 serves DHCP for the app.
	const appMACAddr = "02:16:3e:00:00:01"
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "container-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM, // PV does not work in xen
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

	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	defer stopNIWatch()
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, false, false)

	timeout := 3 * time.Minute
	stpConvergenceTimeout := 2 * time.Minute
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second
	log := evetest.Logger()

	// Wait for NI to come ONLINE with all three adapters assigned.
	var niInfo *eveinfo.ZInfoNetworkInstance
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI is ONLINE with 3 assigned adapters",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE &&
				len(info.AssignedAdapters) == 3
		})))

	evetest.Checkpoint("ni-online")

	t.Expect(niInfo.Activated).To(BeTrue())
	t.Expect(niInfo.NetworkErr).To(BeEmpty())
	t.Expect(niInfo.Ports).To(ConsistOf("ethernet1", "ethernet2", "ethernet3"))
	t.Expect(niInfo.BridgeIPAddr).To(BeEmpty())
	bridgeName := niInfo.BridgeName
	t.Expect(bridgeName).ToNot(BeEmpty())

	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	evetest.Checkpoint("app-running")

	// Wait for the app to receive an IP from the SDN DHCP server (10.51.0.0/24).
	appSubnet := evetest.IPSubnet("10.51.0.0/24")
	var appIPs []net.IP
	var appInfo *eveinfo.ZInfoApp
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App receives IP from app-network subnet",
		func(info *eveinfo.ZInfoApp) bool {
			appInfo = info
			appIPs = nil
			if len(info.Network) == 0 {
				return false
			}
			for _, ipAddr := range info.Network[0].IPAddrs {
				ip := evetest.IPAddress(ipAddr)
				if ip.IsGlobalUnicast() && appSubnet.Contains(ip) {
					appIPs = append(appIPs, ip)
				}
			}
			return len(appIPs) > 0
		}).StopIf(appHasError)))
	t.Expect(appIPs).To(HaveLen(1))
	appIP := appIPs[0]
	log.Infof("App received IP: %s", appIP)
	t.Expect(appInfo.Network[0].Ipv4Up).To(BeTrue())
	t.Expect(appInfo.Network[0].IpAddrMisMatch).To(BeFalse())

	// Wait for the NI to report the app VIF.
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI reports the app VIF",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			niInfo = info
			return len(niInfo.Vifs) == 1
		}).StopIf(niHasError)))
	vifName := niInfo.Vifs[0].VifName
	t.Expect(vifName).To(Equal("nbu1x1"))
	t.Expect(niInfo.Vifs[0].MacAddress).To(Equal(appMACAddr))
	t.Expect(niInfo.Vifs[0].AppID).To(Equal(appUUID.String()))

	// readBpduGuard reads the BPDU guard sysfs flag for a named bridge port.
	// Returns "0", "1", or "" if the path cannot be read.
	readBpduGuard := func(portName string) string {
		path := "/sys/class/net/" + bridgeName + "/brif/" + portName + "/bpdu_guard"
		output, _, err := device.RunShellScript("cat "+path, sshTimeout, 0)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(output)
	}

	// -----------------------------------------------------------------------
	// Phase 1: STP convergence
	// -----------------------------------------------------------------------
	// Among eth1/eth2: exactly one must be "forwarding" and the other "blocking".
	// eth3 (on a separate stub SDN bridge with no STP) must be "forwarding".
	var forwardingPort string
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScript(
			"brctl showstp "+bridgeName, sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		state1 := getBridgePortSTPState(output, "eth1")
		state2 := getBridgePortSTPState(output, "eth2")
		state3 := getBridgePortSTPState(output, "eth3")
		t.Expect([]string{state1, state2}).To(ConsistOf("forwarding", "blocking"))
		t.Expect(state3).To(Equal("forwarding"))
		if state1 == "forwarding" {
			forwardingPort = "eth1"
		} else {
			forwardingPort = "eth2"
		}
	}, stpConvergenceTimeout, polling).Should(Succeed())

	log.Infof("STP forwarding port after convergence: %s", forwardingPort)
	evetest.Checkpoint("stp-converged")

	// BPDU guard: app VIF and eth3 ("edge-port") have it on; eth1/eth2 are
	// active STP participants and must have it off.
	t.Expect(readBpduGuard(vifName)).To(Equal("1"),
		"BPDU guard must be on for app VIF")
	t.Expect(readBpduGuard("eth1")).To(Equal("0"),
		"BPDU guard must be off for eth1")
	t.Expect(readBpduGuard("eth2")).To(Equal("0"),
		"BPDU guard must be off for eth2")
	t.Expect(readBpduGuard("eth3")).To(Equal("1"),
		"BPDU guard must be on for eth3 (edge-port)")

	// App connectivity: curl through whichever port STP chose as forwarding.
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	log.Infof("Phase 1: testing app connectivity via the forwarding port")
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"curl -sS --max-time 10 http://http-server.test/helloworld",
			sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("Hello world!"))
	}, timeout, polling).Should(Succeed())

	// Confirm L2 reachability to the leaf endpoint on bridge2 (eth3 path).
	// leaf-httpserver shares the app subnet (10.51.0.0/24) because EVE's
	// Switch NI bridges eth3 together with eth1+eth2 into one L2 domain.
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"curl -sS --max-time 10 http://leaf-httpserver.test/helloworld",
			sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("Hello from leaf!"))
	}, timeout, polling).Should(Succeed())

	// -----------------------------------------------------------------------
	// Phase 2: STP failover
	// -----------------------------------------------------------------------
	// Take the currently-forwarding port AdminUp=false in the SDN model.
	// Map the forwarding port logical name to its index in FourPortsWithSTPBridge.Ports.
	// FourPortsWithSTPBridge.Ports = [eth0(0), eth1(1), eth2(2), eth3(3)].
	var downPortIdx int
	switch forwardingPort {
	case "eth1":
		downPortIdx = 1
	case "eth2":
		downPortIdx = 2
	}
	blockingPort := "eth2"
	if forwardingPort == "eth2" {
		blockingPort = "eth1"
	}

	updatedModel := proto.Clone(netmodels.FourPortsWithSTPBridge).(*api.NetworkModel)
	updatedModel.Ports[downPortIdx].AdminUp = false
	evetest.UpdateNetworkModel(updatedModel)
	// Do not forget to restore the original network model.
	defer evetest.UpdateNetworkModel(netmodels.FourPortsWithSTPBridge)

	evetest.Checkpoint("forwarding-port-down")
	log.Infof("Phase 2: took %s AdminUp=false; expecting %s to become forwarding",
		forwardingPort, blockingPort)

	// Wait for the previously-blocking port to transition to "forwarding".
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScript(
			"brctl showstp "+bridgeName, sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		state := getBridgePortSTPState(output, blockingPort)
		t.Expect(state).To(Equal("forwarding"))
	}, stpConvergenceTimeout, polling).Should(Succeed())

	evetest.Checkpoint("stp-reconverged")

	// App traffic must continue to flow via the newly-forwarding port.
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"curl -sS --max-time 10 http://http-server.test/helloworld",
			sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("Hello world!"))
	}, timeout, polling).Should(Succeed())
}

// getBridgePortSTPState extracts the STP state of a named port from the output
// of `brctl showstp <bridge>`. Returns the state string (e.g. "forwarding",
// "blocking", "disabled") or an empty string if the port section is not found.
func getBridgePortSTPState(stpOutput, portName string) string {
	lines := strings.Split(stpOutput, "\n")
	inPortSection := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !inPortSection {
			// Port section headers look like: "eth1 (1)" or just "eth1".
			if trimmed == portName || strings.HasPrefix(trimmed, portName+" (") {
				inPortSection = true
			}
			continue
		}
		// "state" may share a line with "port id":
		// " port id        8002            state             forwarding"
		if strings.Contains(trimmed, "state") {
			parts := strings.Fields(trimmed)
			for i, p := range parts {
				if p == "state" && i+1 < len(parts) {
					return parts[i+1]
				}
			}
		}
		// A non-indented non-empty line signals the start of another section.
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			inPortSection = false
		}
	}
	return ""
}
