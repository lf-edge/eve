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

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// TestSwitchNIPortConfigRace is a regression test for a class of races
// between NIM (device-port reconciler) and zedrouter (network-instance
// reconciler), fixed by IfInstanceID (see pkg/pillar/types/dns.go,
// nireconciler and dpcreconciler). NIM renames a physical or VLAN interface
// to "k<ifname>" and creates a bridge "<ifname>" over it whenever the port
// becomes a DHCP client, static, or a VLAN parent
// (isAdapterBridgedByNIM in dpcreconciler/linuxitems/adapter.go). Switching a
// port's config so that this bridging decision is recreated -- even when the
// end result is unchanged -- previously could: leave a stale tc-ingress
// qdisc behind after a rename ("Exclusivity flag on, cannot modify"),
// silently miss reapplying VLAN filtering after a same-named bridge was torn
// down and recreated, or leave the application VIF un-re-enslaved.
//
// Topology
// --------
//
//	                    +------------------+              +--------+
//	                    | eth0 (EVE mgmt)  |--------------| switch |----(router, controller reachable)
//	                    |      (DHCP)      |              +--------+
//	                    +------------------+
//
//	+-----+  +----------------+  +-------------------+
//	| app |->| multiswitch-ni |->| eth1 (app-shared) |    +--------+
//	|     |  +----------------+  | (no IP, L2-only)  |----| switch |----(router)
//	|     |                 |    +-------------------+    | (STP)  |
//	|     |                 |    +-------------------+    +--------+
//	|     |                 ---->| eth2 (app-shared) |         |
//	|     |                      | (no IP, L2-only)  |---------+
//	|     |                      +-------------------+
//	|     |
//	|     |  +----------------+  +-------------------+    +--------+
//	+-----+->| vlan-switch-ni |->| vlan100 on eth3   |----| switch |----(router, VLAN 100)
//	         +----------------+  | (VLAN sub-if)     |    +--------+
//	                             +-------------------+
//
// eth3 itself carries no traffic of its own -- it exists only as the VLAN
// parent of vlan100.
//
// Network model
// -------------
//   - netmodels.MultiPortSwitchAndVLANTrunk: eth0 is on its own DHCP
//     management bridge. eth1 and eth2 share a single STP-enabled SDN bridge
//     with a router serving an untagged application network (10.53.20.0/24).
//     eth3 is a VLAN trunk toward a router serving a VLAN 100 application
//     network (10.53.100.0/24).
//
// Device configuration
// --------------------
//   - ethernet0: DHCP, mgmt only. Never changed for the rest of the test.
//   - ethernet1, ethernet2: initially no IP, L2-only, shared label
//     "multiswitch-ports". Both ports of the multi-port Switch NI
//     "multiswitch-ni" (STP is mandatory for any multi-port Switch NI, hence
//     the SDN-side loop above). A port cannot be individually bridged by NIM
//     while still a raw member of this multi-port bridge -- it cannot be a
//     member of two different bridges at once -- so ethernet1 never changes
//     for the rest of the test, and its continued reachability confirms
//     that churning the *other* ports (ethernet2, vlan100) never disrupts
//     it. ethernet2 is itself churned in Phase E below: it leaves
//     multiswitch-ports' membership and becomes an individually
//     NIM-bridged DHCP client, then rejoins -- BPDU guard is enabled on it
//     (rather than on ethernet1) so that Phase E's rejoin actually exercises
//     the BPDUGuard fix, since it forces the guard to be deleted and
//     reapplied, not just set once and left alone.
//   - ethernet3: VLAN parent, no IP of its own, through Phase E. vlan100:
//     VLAN 100 sub-interface of ethernet3, initially a DHCP client. Sole
//     port of the single-port Switch NI "vlan-switch-ni" through Phase E --
//     the port the race scenarios in Phases A-D are applied to. Phase F
//     deletes vlan100 and moves vlan-switch-ni directly onto ethernet3
//     instead, with VLAN filtering enabled (see Phases F-G).
//   - One container app (lfedge/evetest-ubuntu-ctr:1.0) with two VIFs: vif0
//     on multiswitch-ni, vif1 on vlan-switch-ni. Phase F gives vif1 an
//     access VLAN, which restarts the app.
//
// Phases
// ------
//
//  1. NI and app creation: both Switch NIs reach ZNETINST_STATE_ONLINE with
//     their expected port count (AssignedAdapters for multiswitch-ni's
//     physical ports; Ports for vlan-switch-ni's VLAN sub-interface, which
//     is not a physical IO bundle), and the app receives a DHCP address on
//     each VIF from its respective SDN router.
//
//  2. Baseline connectivity: from inside the app, ping the gateway of each
//     of the two application networks (10.53.20.1 via vif0, 10.53.100.1 via
//     vif1).
//
//  3. A sequence of live vlan100 config changes previously prone to the
//     NIM/zedrouter races described above, each followed by re-verifying
//     step 2's connectivity check (wrapped in Eventually, to allow for the
//     brief reconciliation that a genuine config change causes):
//     a. DHCP client -> static IP. vlan100 stays bridged by NIM throughout
//     (Static, like DHCP client, satisfies isAdapterBridgedByNIM), so this
//     recreates the *same* bridge without ever changing whether it's
//     bridged -- the case that needed the VLANBridge/BridgePort recreate
//     fix, in addition to the original Port/Bridge/TCIngress fix.
//     b. Static IP -> DHCP client (same, other direction).
//     c. DHCP client -> no IP: this flips vlan100 from bridged-by-NIM to
//     not bridged at all -- NIM releases it and zedrouter's own switch-NI
//     bridging takes over the same interface directly.
//     d. No IP -> DHCP client: the reverse transition, bridged-by-NIM again.
//
//  4. ethernet2's membership in multiswitch-ni is itself churned, again
//     followed each time by re-verifying step 2's connectivity check:
//     a. ethernet2 leaves the "multiswitch-ports" label and becomes an
//     individually NIM-bridged DHCP client -- multiswitch-ni shrinks to
//     ethernet1 alone (and drops out of STP, being down to one port).
//     b. ethernet2 rejoins "multiswitch-ports" as a no-IP member again --
//     multiswitch-ni recovers its second port (and STP re-engages), and
//     BPDU guard must read back "1" on ethernet2 (sysfs), confirming it was
//     correctly reapplied rather than lost.
//
//  5. vlan-switch-ni's port is switched from vlan100 (deleted) directly to
//     ethernet3, its former VLAN parent. vif1 is given an access VLAN
//     (which restarts the app), enabling VLAN filtering on the NI --
//     exercising VLANPort, which none of the scenarios above ever
//     construct. ethernet3 itself is left as an (automatic) trunk port,
//     matching its physical link, which genuinely carries 802.1Q-tagged
//     traffic for the SDN's VLAN 100 router.
//
//  6. With VLAN filtering active, ethernet3's own IP config is churned
//     between no IP and static IP and back, again followed each time by
//     re-verifying step 2's connectivity check: the same NIM/zedrouter
//     bridge-ownership race as step 3c/3d, now exercised through a
//     VLANPort (trunk config) instead of a plain BridgePort.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestSwitchNIPortConfigRace(test *testing.T) {
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
			NetworkModel: netmodels.MultiPortSwitchAndVLANTrunk,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// eth0: management port, DHCP. Never touched again.
	mgmtNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   mgmtNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
	})

	// eth1, eth2: no-IP, L2-only members of multiswitch-ni. ethernet1 never
	// changes, so it shares the same no-IP network config as eth3. ethernet2
	// gets its own dedicated network, since Phase E below mutates it
	// independently.
	noIPNet := devConfig.AddNetwork(evetest.NoIPNetworkConfig{})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		NetworkUUID:   noIPNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		SharedLabels:  []string{"multiswitch-ports"},
	})
	eth2Net := devConfig.AddNetwork(evetest.NoIPNetworkConfig{})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet2",
		PhysicalLabel: "eth2",
		InterfaceName: "eth2",
		NetworkUUID:   eth2Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		SharedLabels:  []string{"multiswitch-ports"},
	})

	// eth3: VLAN parent, no IP of its own; not used directly by any NI.
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet3",
		PhysicalLabel: "eth3",
		InterfaceName: "eth3",
		NetworkUUID:   noIPNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})

	// vlan100: VLAN 100 sub-interface of eth3, DHCP client. Sole port of
	// vlan-switch-ni, and the subject of every race scenario below.
	vlan100Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddVLANSubinterface(evetest.VLANSubinterfaceConfig{
		LogicalLabel:       "vlan100",
		InterfaceName:      "vlan100",
		ParentLogicalLabel: "ethernet3",
		VlanID:             100,
		NetworkUUID:        vlan100Net,
		Usage:              evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})

	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("port-config-applied")

	// multiswitch-ni: Switch NI spanning ethernet1 + ethernet2. STP is
	// mandatory for any multi-port Switch NI. BPDU guard is enabled on
	// ethernet2 rather than the never-changing ethernet1: ethernet2's
	// BridgePort (and therefore its BPDUGuard) is deleted and recreated by
	// Phase E below, which is what actually exercises the BPDUGuard fix --
	// on a port that never changes, BPDU guard would only ever be applied
	// once and never need to be reapplied.
	multiNIUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "multiswitch-ni",
		Port:        "multiswitch-ports",
		STPConfig:   pillartypes.STPConfig{PortsWithBpduGuard: "ethernet2"},
	})

	// vlan-switch-ni: single-port Switch NI directly on the vlan100
	// sub-interface.
	vlanNIUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "vlan-switch-ni",
		Port:        "vlan100",
	})

	const appMultiMAC = "02:16:3e:00:00:01"
	const appVlanMAC = "02:16:3e:00:00:02"
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
				NetworkInstanceUUID: multiNIUUID,
				MAC:                 evetest.MACAddress(appMultiMAC),
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif1",
				NetworkInstanceUUID: vlanNIUUID,
				MAC:                 evetest.MACAddress(appVlanMAC),
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	})

	multiNIUpdates, stopMultiNIWatch := device.WatchNetworkInstanceInfo(multiNIUUID)
	defer stopMultiNIWatch()
	vlanNIUpdates, stopVlanNIWatch := device.WatchNetworkInstanceInfo(vlanNIUUID)
	defer stopVlanNIWatch()
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, false, false)

	// STP convergence for multiswitch-ni can take up to ~2 minutes (standard
	// STP, not RSTP); every timeout below is sized with enough margin for
	// both that and the ordinary Switch NI bring-up delay.
	timeout := 3 * time.Minute
	sshTimeout := 20 * time.Second
	polling := 5 * time.Second
	log := evetest.Logger()

	var multiNIInfo *eveinfo.ZInfoNetworkInstance
	t.Eventually(multiNIUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"multiswitch-ni is ONLINE with 2 assigned adapters",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			multiNIInfo = info
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE &&
				len(info.AssignedAdapters) == 2
		}).StopIf(niHasError)))
	multiBridgeName := multiNIInfo.BridgeName
	t.Expect(multiBridgeName).ToNot(BeEmpty())
	t.Eventually(vlanNIUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"vlan-switch-ni is ONLINE with 1 port",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			// AssignedAdapters ([]*ZioBundle) reports assigned physical IO
			// bundles only -- vlan100 is a VLAN sub-interface, not a distinct
			// physical IO bundle (its underlying ethernet3 is never itself
			// assigned to any NI), so AssignedAdapters is always empty here.
			// Ports (logical port names) is the field that's actually
			// populated for it.
			return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE &&
				len(info.Ports) == 1
		}).StopIf(niHasError)))
	evetest.Checkpoint("nis-online")

	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	evetest.Checkpoint("app-running")

	multiSubnet := evetest.IPSubnet("10.53.20.0/24")
	vlanSubnet := evetest.IPSubnet("10.53.100.0/24")
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app has IPs from both application subnets",
		func(info *eveinfo.ZInfoApp) bool {
			if len(info.Network) != 2 {
				return false
			}
			var hasMulti, hasVlan bool
			for _, vif := range info.Network {
				for _, ipAddr := range vif.IPAddrs {
					ip := evetest.IPAddress(ipAddr)
					if multiSubnet.Contains(ip) {
						hasMulti = true
					}
					if vlanSubnet.Contains(ip) {
						hasVlan = true
					}
				}
			}
			return hasMulti && hasVlan
		}).StopIf(appHasError)))
	evetest.Checkpoint("app-connected")

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	const multiGwIP = "10.53.20.1"
	const vlanGwIP = "10.53.100.1"

	// pingGateways verifies that the app can still reach both Switch NI
	// gateways. Called after every config change below; Eventually allows
	// for the brief reconciliation delay a genuine config change causes
	// (and, for multiswitch-ni, for STP to reconverge if disturbed).
	// checkNINotInError aborts the enclosing Eventually immediately, via
	// gomega.StopTrying, if the NI's last recorded info reports the ERROR
	// state -- instead of letting it blindly retry ping/SSH for the full
	// timeout. Reads GetNetworkInstanceInfo (the device's own last-recorded
	// state) rather than the watch channel, so it doesn't compete with
	// waitForMultiNIAdapterCount (or anything else) for the same messages.
	checkNINotInError := func(name string, niUUID uuid.UUID) {
		info := device.GetNetworkInstanceInfo(niUUID)
		if info == nil {
			return
		}
		if reason, isErr := niHasError(info); isErr {
			StopTrying(fmt.Sprintf("%s: %s\n%s", name, reason, info.String())).Now()
		}
	}

	pingGateways := func(reason string) {
		log.Infof("Pinging gateways (%s)...", reason)
		t.Eventually(func(g Gomega) {
			checkNINotInError("multiswitch-ni", multiNIUUID)
			_, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
				"ping -c 3 -W 2 "+multiGwIP, sshTimeout, 0)
			g.Expect(err).ToNot(HaveOccurred(), "ping to multiswitch-ni gateway")
		}, timeout, polling).Should(Succeed())
		t.Eventually(func(g Gomega) {
			checkNINotInError("vlan-switch-ni", vlanNIUUID)
			_, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
				"ping -c 3 -W 2 "+vlanGwIP, sshTimeout, 0)
			g.Expect(err).ToNot(HaveOccurred(), "ping to vlan-switch-ni gateway")
		}, timeout, polling).Should(Succeed())
	}

	pingGateways("baseline")
	evetest.Checkpoint("baseline-connectivity-ok")

	dnsServerIP := evetest.IPAddress("10.16.16.25")

	// -----------------------------------------------------------------------
	// Phase A: vlan100, DHCP client -> static IP. Stays bridged by NIM
	// throughout (Static also satisfies isAdapterBridgedByNIM), so this
	// recreates the same bridge without ever changing whether it's bridged.
	// -----------------------------------------------------------------------
	log.Infof("Phase A: vlan100 DHCP -> static")
	devConfig.UpdateNetwork(vlan100Net, evetest.StaticNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
		Subnet:      vlanSubnet,
		Gateway:     evetest.IPAddress(vlanGwIP),
		DNSServers:  []net.IP{dnsServerIP},
	})
	devConfig.UpdateVLANSubinterface(evetest.VLANSubinterfaceConfig{
		LogicalLabel:       "vlan100",
		InterfaceName:      "vlan100",
		ParentLogicalLabel: "ethernet3",
		VlanID:             100,
		NetworkUUID:        vlan100Net,
		Usage:              evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		StaticIP:           evetest.IPAddress("10.53.100.5"),
	})
	device.ApplyConfig(devConfig, true, true)
	pingGateways("vlan100 switched to static IP")
	evetest.Checkpoint("vlan100-static")

	// -----------------------------------------------------------------------
	// Phase B: vlan100, static IP -> DHCP client (Phase A, reversed).
	// -----------------------------------------------------------------------
	log.Infof("Phase B: vlan100 static -> DHCP")
	devConfig.UpdateNetwork(vlan100Net, evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.UpdateVLANSubinterface(evetest.VLANSubinterfaceConfig{
		LogicalLabel:       "vlan100",
		InterfaceName:      "vlan100",
		ParentLogicalLabel: "ethernet3",
		VlanID:             100,
		NetworkUUID:        vlan100Net,
		Usage:              evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})
	device.ApplyConfig(devConfig, true, true)
	pingGateways("vlan100 switched back to DHCP")
	evetest.Checkpoint("vlan100-dhcp-restored")

	// -----------------------------------------------------------------------
	// Phase C: vlan100, DHCP client -> no IP. Flips vlan100 from bridged by
	// NIM to not bridged at all: NIM releases it and zedrouter's own
	// switch-NI bridging takes over the same interface directly.
	// -----------------------------------------------------------------------
	log.Infof("Phase C: vlan100 DHCP -> no IP (un-bridging)")
	devConfig.UpdateNetwork(vlan100Net, evetest.NoIPNetworkConfig{})
	devConfig.UpdateVLANSubinterface(evetest.VLANSubinterfaceConfig{
		LogicalLabel:       "vlan100",
		InterfaceName:      "vlan100",
		ParentLogicalLabel: "ethernet3",
		VlanID:             100,
		NetworkUUID:        vlan100Net,
		Usage:              evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})
	device.ApplyConfig(devConfig, true, true)
	pingGateways("vlan100 un-bridged (no IP)")
	evetest.Checkpoint("vlan100-unbridged")

	// -----------------------------------------------------------------------
	// Phase D: vlan100, no IP -> DHCP client (Phase C, reversed: bridged by
	// NIM again).
	// -----------------------------------------------------------------------
	log.Infof("Phase D: vlan100 no IP -> DHCP (re-bridging)")
	devConfig.UpdateNetwork(vlan100Net, evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.UpdateVLANSubinterface(evetest.VLANSubinterfaceConfig{
		LogicalLabel:       "vlan100",
		InterfaceName:      "vlan100",
		ParentLogicalLabel: "ethernet3",
		VlanID:             100,
		NetworkUUID:        vlan100Net,
		Usage:              evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})
	device.ApplyConfig(devConfig, true, true)
	pingGateways("vlan100 re-bridged (DHCP)")
	evetest.Checkpoint("vlan100-rebridged")

	// waitForMultiNIAdapterCount waits for multiswitch-ni to report the given
	// number of AssignedAdapters, used by Phase E below to confirm ethernet2
	// actually left/rejoined the NI (not just that traffic still flows).
	waitForMultiNIAdapterCount := func(count int, reason string) {
		t.Eventually(multiNIUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
			fmt.Sprintf("multiswitch-ni has %d assigned adapter(s) (%s)", count, reason),
			func(info *eveinfo.ZInfoNetworkInstance) bool {
				return info.State == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE &&
					len(info.AssignedAdapters) == count
			}).StopIf(niHasError)))
	}

	// -----------------------------------------------------------------------
	// Phase E: ethernet2 leaves multiswitch-ports (becoming an individually
	// NIM-bridged DHCP client) and rejoins. Exercises a port transitioning
	// out of a zedrouter-owned multi-port bridge and into a NIM-owned one
	// (and back), rather than a NIM-owned bridge's own DHCP/static config
	// changing as in Phases A-D.
	// -----------------------------------------------------------------------
	log.Infof("Phase E: ethernet2 leaves multiswitch-ports, becomes a DHCP client")
	devConfig.UpdateNetwork(eth2Net, evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.UpdateNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet2",
		PhysicalLabel: "eth2",
		InterfaceName: "eth2",
		NetworkUUID:   eth2Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})
	device.ApplyConfig(devConfig, true, true)
	waitForMultiNIAdapterCount(1, "ethernet2 left")
	pingGateways("ethernet2 left multiswitch-ni and became an independent DHCP client")
	evetest.Checkpoint("ethernet2-left")

	log.Infof("Phase E: ethernet2 rejoins multiswitch-ports as a no-IP member")
	devConfig.UpdateNetwork(eth2Net, evetest.NoIPNetworkConfig{})
	devConfig.UpdateNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet2",
		PhysicalLabel: "eth2",
		InterfaceName: "eth2",
		NetworkUUID:   eth2Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		SharedLabels:  []string{"multiswitch-ports"},
	})
	device.ApplyConfig(devConfig, true, true)
	waitForMultiNIAdapterCount(2, "ethernet2 rejoined")
	pingGateways("ethernet2 rejoined multiswitch-ni")

	// Ping alone would not catch a lost BPDU guard -- it doesn't gate
	// ordinary traffic. This is the actual regression check for the
	// BPDUGuard fix: ethernet2's BridgePort (and BPDUGuard along with it)
	// was deleted when it left the NI and must be correctly recreated now
	// that it rejoined, not silently left off.
	t.Eventually(func(g Gomega) {
		bpduGuardFlag := readBpduGuard(device, multiBridgeName, "eth2", sshTimeout)
		g.Expect(bpduGuardFlag).To(Equal("1"))
	}, timeout, polling).Should(
		Succeed(), "BPDU guard must be back on for ethernet2 after rejoining")
	evetest.Checkpoint("ethernet2-rejoined")

	// -----------------------------------------------------------------------
	// Phase F: vlan-switch-ni's port switches from vlan100 (deleted) to its
	// former VLAN parent ethernet3, with VLAN filtering enabled -- the
	// first scenario to exercise VLANPort. ethernet3's link genuinely
	// carries 802.1Q-tagged traffic, so it stays a trunk port; vif1 is made
	// the VID 100 access port instead, which is what actually turns VLAN
	// filtering on for the NI. Changing vif1 restarts the app.
	// -----------------------------------------------------------------------
	log.Infof("Phase F: vlan-switch-ni switches from vlan100 to ethernet3 (VLAN filtering)")
	devConfig.DeleteVLANSubinterface("vlan100")
	devConfig.DeleteNetwork(vlan100Net)
	// ethernet3 shared noIPNet with ethernet1 as a passive VLAN parent; give
	// it its own network now that Phase G below churns it independently.
	eth3Net := devConfig.AddNetwork(evetest.NoIPNetworkConfig{})
	devConfig.UpdateNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet3",
		PhysicalLabel: "eth3",
		InterfaceName: "eth3",
		NetworkUUID:   eth3Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})
	devConfig.UpdateNetworkInstance(vlanNIUUID, evetest.SwitchNetworkInstanceConfig{
		DisplayName: "vlan-switch-ni",
		Port:        "ethernet3",
	})
	devConfig.UpdateApplication(appUUID, evetest.ApplicationInstanceConfig{
		DisplayName: "container-app",
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
				NetworkInstanceUUID: multiNIUUID,
				MAC:                 evetest.MACAddress(appMultiMAC),
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif1",
				NetworkInstanceUUID: vlanNIUUID,
				MAC:                 evetest.MACAddress(appVlanMAC),
				AccessVLAN:          100,
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	})
	device.ApplyConfig(devConfig, true, true)
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	pingGateways("vlan-switch-ni switched to ethernet3 with VLAN filtering")
	evetest.Checkpoint("vlan-switch-ni-on-ethernet3")

	// -----------------------------------------------------------------------
	// Phase G: with VLAN filtering active, churn ethernet3 between no IP
	// (bridged by zedrouter) and static IP (bridged by NIM) and back --
	// the same race as Phases C/D, now with a VLANPort in play. The static
	// subnet is deliberately unreachable (TEST-NET-1); it only needs to
	// make NIM bridge the port.
	// -----------------------------------------------------------------------
	log.Infof("Phase G: ethernet3 no IP -> static IP (re-bridging under VLAN filtering)")
	devConfig.UpdateNetwork(eth3Net, evetest.StaticNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
		Subnet:      evetest.IPSubnet("192.0.2.0/24"),
		Gateway:     evetest.IPAddress("192.0.2.1"),
	})
	devConfig.UpdateNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet3",
		PhysicalLabel: "eth3",
		InterfaceName: "eth3",
		NetworkUUID:   eth3Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		StaticIP:      evetest.IPAddress("192.0.2.5"),
	})
	device.ApplyConfig(devConfig, true, true)
	pingGateways("ethernet3 bridged by NIM under VLAN filtering (static IP)")
	evetest.Checkpoint("ethernet3-vlan-static")

	log.Infof("Phase G: ethernet3 static IP -> no IP (un-bridging under VLAN filtering)")
	devConfig.UpdateNetwork(eth3Net, evetest.NoIPNetworkConfig{})
	devConfig.UpdateNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet3",
		PhysicalLabel: "eth3",
		InterfaceName: "eth3",
		NetworkUUID:   eth3Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
	})
	device.ApplyConfig(devConfig, true, true)
	pingGateways("ethernet3 un-bridged by NIM under VLAN filtering (no IP)")
	evetest.Checkpoint("ethernet3-vlan-noip")
}
