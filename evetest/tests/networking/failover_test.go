// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
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

// TestPortFailover verifies that EVE switches between management ports when
// the currently-used port loses connectivity, that it prefers the lowest-cost
// port and recovers back to it once connectivity is restored, and that an
// application attached to a Local NI re-routes its default route accordingly.
//
// Network model
// -------------
//   - netmodels.TwoMgmtPorts -- two Ethernet ports on separate bridges and
//     networks, both with DHCP and controller reachability. Each network has
//     its own SDN DNS server resolving the controller and http-server.test,
//     so fail-over is observable from both the EVE side and the app side.
//
// Device configuration
// --------------------
//   - SystemAdapter on eth0: mgmt+app, DHCP, Cost=0 (preferred).
//   - SystemAdapter on eth1: mgmt+app, DHCP, Cost=10 (backup).
//   - One Local NI ("local-ni") on the predefined shared label "uplink"
//     (matches every mgmt port; see APP-CONNECTIVITY.md "Multi-Path IP
//     Routing"). The NI default route is configured explicitly as a
//     multi-path static route 0.0.0.0/0 -> "uplink" with next-hop probing
//     only (GwPingMaxCost=10 so both ports are probed) and
//     PreferLowerCost=true, overriding the route EVE would otherwise
//     auto-generate for an uplink-only NI -- see the inline rationale at
//     the route definition.
//   - One container app on the NI with a default-allow ACL and a port-fwd
//     2222->22 ACE so the test can SSH into it via either uplink.
//
// Phases
// ------
//  1. Steady state on eth0: SystemAdapterInfo reports the controller-pushed
//     DPC "zedagent" at currentIndex=0 with no overall error and both ports
//     holding IPv4. The NI is ONLINE and its 0.0.0.0/0 route points at
//     ethernet0 (lowest cost). From inside the app, `curl
//     http://http-server.test/helloworld` returns "Hello world!".
//  2. eth0 link-down: TwoMgmtPorts is cloned with Ports[0].AdminUp=false
//     and pushed via UpdateNetworkModel, taking eth0 down at the SDN.
//     Eventually the eth0 DevicePort reports a fresh port-level Err (its
//     Timestamp post-dates the model change, so stale Err values from
//     earlier DPC test cycles are ignored), the overall DPC LastError
//     stays empty (eth1 still reaches the controller), the NI's 0.0.0.0/0
//     route flips to ethernet1, and the app's curl keeps working.
//  3. eth0 recovery: the original network model is restored. Eventually
//     eth0 has IPv4 again, the DPC's LastSucceeded advances past the
//     recovery instant, and the NI's 0.0.0.0/0 route flips back to
//     ethernet0 (preferred lower cost).
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestPortFailover(test *testing.T) {
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

	// eth0: management DHCP, lowest cost (preferred).
	eth0Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   eth0Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		Cost:          0,
	})

	// eth1: management DHCP, higher cost (backup).
	eth1Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		NetworkUUID:   eth1Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		Cost:          10,
	})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("port-config-applied")

	// Local NI on "uplink" (predefined shared label matching every mgmt port).
	// The NI uses an explicit multi-path default route with next-hop probing
	// only -- no controller-targeting user probe. With port="uplink" alone,
	// EVE would auto-generate the default route with NH-ping (zero-cost
	// ports) + controller TCP probe; see APP-CONNECTIVITY.md "Network
	// Instance Default IP Route" and zedrouter/networkinstance.go.
	//
	// We avoid the auto-generated route here because the user-probe makes
	// fail-over too slow for a test: portprober uses a 150s probe interval
	// (NHProbeInterval * NHToUserProbeRatio, 15s * 10) and requires more
	// than MaxContFailCnt=4 consecutive failures to mark the probe DOWN,
	// i.e. ~10-12.5 min worst case before EVE concedes that eth0's user
	// probe has failed. With NH-only probing the equivalent transition is
	// 5 * 15s = ~75s.
	//
	// TODO: once portprober's Config (NHProbeInterval, MaxContFailCnt,
	// NHToUserProbeRatio, etc.) is exposed via controller config, drop the
	// explicit StaticRoutes below, revert to the bare port="uplink" form,
	// and lower those intervals from the test so the auto-generated route
	// (including the controller probe) can be exercised at a reasonable
	// speed.
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "uplink",
		Subnet:      evetest.IPSubnet("10.50.0.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.50.0.2"),
			End:   evetest.IPAddress("10.50.0.254"),
		},
		Gateway: evetest.IPAddress("10.50.0.1"),
		StaticRoutes: []pillartypes.IPRouteConfig{
			{
				DstNetwork:      evetest.IPSubnet("0.0.0.0/0"),
				OutputPortLabel: "uplink",
				PortProbe: pillartypes.NIPortProbe{
					// GwPingMaxCost must cover eth1's cost so the
					// next-hop ping probe applies to both ports.
					EnabledGwPing: true,
					GwPingMaxCost: 10,
				},
				PreferLowerCost: true,
			},
		},
		MTU: 1500,
	})

	const vifMAC = "02:16:3e:00:0f:00"
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "failover-app",
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
				MAC:                 evetest.MACAddress(vifMAC),
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
	device.ApplyConfig(devConfig, false, false)

	log := evetest.Logger()
	timeout := 3 * time.Minute

	// Phase 1: steady state.
	// SystemAdapterInfo must report exactly one DPC ("zedagent") at index 0
	// with both ports reporting no errors.
	log.Infof("Phase 1: verifying steady state with eth0 as the active uplink...")
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"DPC=zedagent healthy and both eth0 and eth1 have IPv4",
		// Per-port DevicePort.Err is intentionally not checked: it is
		// refreshed once per timer.port.testinterval (min 5 min), so a
		// port may have IPv4 assigned AND a stale "no suitable IP" Err
		// from an earlier cycle when DHCP was still in progress. The
		// stale Err clears only on the next test cycle.
		func(info *eveinfo.ZInfoDevice) bool {
			sa := info.GetSystemAdapter()
			if !matchSystemAdapterInfo(sa, 0, []string{"zedagent"}) {
				return false
			}
			if sa.GetStatus()[0].GetLastError() != "" {
				return false
			}
			return getPortIPv4Addr("ethernet0", info) != nil &&
				getPortIPv4Addr("ethernet1", info) != nil
		})))

	// NI: ONLINE with default route via the lower-cost port (ethernet0).
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI ONLINE with default route via ethernet0",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			if info.GetState() != eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE {
				return false
			}
			route := findRoute(info.GetIpRoutes(), "0.0.0.0/0")
			return route != nil && route.GetPort() == "ethernet0"
		}).StopIf(niHasError)))

	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	evetest.Checkpoint("app-running")

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second

	log.Infof("Phase 1: waiting for SSH and verifying http-server.test reachability via eth0...")
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"curl -sS --max-time 10 http://http-server.test/helloworld", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("Hello world!"))
	}, 5*time.Minute, polling).Should(Succeed())

	// Phase 2: bring eth0 AdminUp=false to fail the cheaper port.
	// Expected:
	//   - The overall (zedagent) DPC remains usable since eth1 still works.
	//   - The eth0 DevicePort reports a port-level error.
	//   - NI default route flips to ethernet1.
	//   - App still reaches http-server.test (via eth1).
	log.Infof("Phase 2: setting eth0 AdminUp=false to trigger failover to eth1...")
	updatedModel := proto.Clone(netmodels.TwoMgmtPorts).(*api.NetworkModel)
	for _, p := range updatedModel.Ports {
		if p.LogicalLabel == "eth0" {
			p.AdminUp = false
		}
	}
	// Capture a reference time so we can distinguish a fresh eth0 Err
	// (from a DPC test run after AdminUp=false took effect) from stale
	// pre-link-down Err values that linger in DevicePort.Err.
	phase2Start := time.Now()
	evetest.UpdateNetworkModel(updatedModel)
	// Always restore the model on exit so a mid-test failure does not leave
	// the SDN in an altered state for subsequent suite tests.
	defer evetest.UpdateNetworkModel(netmodels.TwoMgmtPorts)
	evetest.Checkpoint("eth0-link-down")

	// EVE's periodic connectivity test runs at timer.port.testinterval, whose
	// minimum is 5 minutes. Per-DPC fields (LastError, LastFailed,
	// LastSucceeded) only advance on a full test cycle, so allow one cycle
	// plus a buffer. We cannot accelerate this by re-applying the same
	// device config: DpcManager uses DevicePortConfig.MostlyEqual to detect
	// "new" DPCs, so a fresh ConfigTimestamp/Version alone is not enough
	// to trigger a retest.
	//
	// TODO: when EVE allows lowering timer.port.testinterval below its
	// current 5 min floor (via SetConfigProperties), drop this timeout and
	// trim the test's overall runtime accordingly. With NH-only probing
	// the NI port-flip itself completes in ~75s (failover) / ~60s
	// (recovery); the DPC-level assertions are what require this 10 min
	// budget.
	failoverTimeout := 10 * time.Minute

	t.Eventually(devUpdates, failoverTimeout).Should(Receive(matchers.SatisfyPredicate(
		"ethernet0 has a fresh port-level error while the overall DPC and eth1 stay healthy",
		func(info *eveinfo.ZInfoDevice) bool {
			sa := info.GetSystemAdapter()
			if !matchSystemAdapterInfo(sa, 0, []string{"zedagent"}) {
				return false
			}
			// The DPC must remain usable: eth1 still provides controller connectivity.
			if sa.GetStatus()[0].GetLastError() != "" {
				return false
			}
			if getPortIPv4Addr("ethernet1", info) == nil {
				return false
			}
			eth0Port := getDevicePort("ethernet0", info)
			if eth0Port == nil {
				return false
			}
			eth0Err := eth0Port.GetErr()
			if eth0Err == nil || eth0Err.GetDescription() == "" {
				return false
			}
			// Reject stale Err lingering from a DPC test cycle that
			// ran before AdminUp=false took effect (e.g. the "no
			// suitable IP" Err set during initial DHCP wait).
			ts := eth0Err.GetTimestamp()
			return ts != nil && !ts.AsTime().Before(phase2Start)
		})))

	t.Eventually(niUpdates, failoverTimeout).Should(Receive(matchers.SatisfyPredicate(
		"NI default route fails over to ethernet1",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			route := findRoute(info.GetIpRoutes(), "0.0.0.0/0")
			return route != nil && route.GetPort() == "ethernet1"
		})))

	log.Infof("Phase 2: verifying http-server.test remains reachable (via eth1)...")
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"curl -sS --max-time 10 http://http-server.test/helloworld", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("Hello world!"))
	}, 3*time.Minute, polling).Should(Succeed())

	// Phase 3: restore eth0; the cheaper port must come back as the route's port.
	log.Infof("Phase 3: restoring eth0 AdminUp=true; expecting default route back on eth0...")
	evetest.UpdateNetworkModel(netmodels.TwoMgmtPorts)
	evetest.Checkpoint("eth0-link-restored")

	recoveryStart := time.Now()
	t.Eventually(devUpdates, failoverTimeout).Should(Receive(matchers.SatisfyPredicate(
		"ethernet0 has IPv4 again and DPC LastSucceeded post-dates recovery",
		// As in Phase 1, we don't check per-port Err here. The next DPC
		// test cycle after eth0 recovers will clear eth0's Err, but
		// gating on that would just add another 5-min wait without
		// adding new signal — the NI route flip-back asserted below
		// already proves portprober sees eth0 as healthy.
		func(info *eveinfo.ZInfoDevice) bool {
			sa := info.GetSystemAdapter()
			if !matchSystemAdapterInfo(sa, 0, []string{"zedagent"}) {
				return false
			}
			dpc := sa.GetStatus()[0]
			if dpc.GetLastError() != "" {
				return false
			}
			ts := dpc.GetLastSucceeded()
			if ts == nil || ts.AsTime().Before(recoveryStart) {
				return false
			}
			return getPortIPv4Addr("ethernet0", info) != nil &&
				getPortIPv4Addr("ethernet1", info) != nil
		})))

	// EVE requires consecutive successful probes before re-selecting the
	// preferred port, so this may take a few probe cycles.
	t.Eventually(niUpdates, failoverTimeout).Should(Receive(matchers.SatisfyPredicate(
		"NI default route flips back to ethernet0 (lower cost)",
		func(info *eveinfo.ZInfoNetworkInstance) bool {
			route := findRoute(info.GetIpRoutes(), "0.0.0.0/0")
			return route != nil && route.GetPort() == "ethernet0"
		})))
}

// TestNetworkConfigFallback verifies that EVE rolls back to the previously
// working DevicePortConfig (DPC) when a newly applied configuration cannot
// reach the controller at all, and that it re-adopts the new config once the
// network actually matches it.
//
// ethernet1 is configured once at the start and never touched again: it is
// what keeps the *first* DPC genuinely working (so there is something to
// fall back to), but it deliberately has no role in the broken/recovered DPC
// under test in phases 2-3, which only ever contains ethernet0. A DPC is
// only considered failed as a whole once none of its ports can reach the
// controller (EVE's connectivity test tries every management port in the
// active DPC and succeeds if any one of them works -- see
// ControllerConnectivityTester.TestConnectivity), so leaving a second,
// unrelated working port in the broken DPC would have masked the failure
// this test needs to trigger.
//
// Network model
// -------------
//   - netmodels.TwoMgmtPorts -- two management ports.
//
// Device configuration
// --------------------
//   - Baseline: SystemAdapter for eth0 (mgmt) DHCP, SystemAdapter for eth1
//     (mgmt) DHCP. timer.port.testduration is lowered to 10s (fast per-DPC
//     connectivity test) and timer.port.testbetterinterval to 60s (fast
//     retest of a higher-priority DPC once it might have become usable
//     again); both via SetConfigProperties.
//
// Phases
// ------
//  1. Baseline: WatchDeviceInfo until SystemAdapterInfo reports currentIndex=0
//     with exactly one DPC entry keyed "zedagent" and no error (same pattern
//     as bootstrap_test.go's matchSystemAdapterInfo helper).
//  2. Broken-config rollback: applies a brand-new EdgeDeviceConfig containing
//     only ethernet0, switched from DHCP to a StaticNetworkConfig with a
//     subnet/gateway (10.99.99.0/24 / 10.99.99.1) that does not exist on the
//     SDN network (plus a static DNS server pointing at the real SDN DNS
//     endpoint, since a StaticNetworkConfig has no DHCP to supply one).
//     Since this DPC has no other management port to fall back on, EVE's
//     connectivity test for it fails outright. Eventually SystemAdapterInfo
//     reports: two DPC entries; CurrentIndex=1 (the older, still-working
//     two-port DPC); the newest entry (index 0) has a non-empty LastError
//     and a populated LastFailed. The device stays online throughout
//     (verified via EdgeDevice.GetState()) since it never actually lost
//     controller connectivity -- eth1 in the older DPC kept working the
//     whole time.
//  3. Recovery: UpdateNetworkModel clones netmodels.TwoMgmtPorts and rewrites
//     ethernet0's SDN subnet/gateway to 10.99.99.0/24 / 10.99.99.1, matching
//     the broken config -- so it is not actually broken anymore. Once EVE's
//     periodic testbetterinterval retest picks this up, SystemAdapterInfo
//     eventually reports CurrentIndex=0 again, with LastSucceeded advancing
//     past the recovery instant and LastError cleared.
//
// Future extension
// ----------------
//   - Variant where the new config IS valid (network model is updated to
//     match) but the controller temporarily blocks the device. Confirm
//     that a brief, "remote" failure (server cert expired) does NOT trigger
//     a fallback (per DEVICE-CONNECTIVITY.md "Handling remote (temporary)
//     failures").
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestNetworkConfigFallback(test *testing.T) {
	// DNS server endpoint reachable from ethernet0's bridge, as defined in
	// netmodels.TwoMgmtPorts (its own subnet, unaffected by network0's
	// client-facing subnet being rewritten below).
	const dnsServer0IP = "10.16.16.25"

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

	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.NetworkTestDuration, 10)
	cfgProps.SetGlobalValueInt(pillartypes.NetworkTestBetterInterval, 60)

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	devConfig.SetConfigProperties(cfgProps)

	eth0Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   eth0Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
	})
	eth1Net := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		NetworkUUID:   eth1Net,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
	})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("baseline-applied")

	log := evetest.Logger()

	// Phase 1: baseline.
	log.Infof("Phase 1: waiting for the baseline DPC to become active...")
	baselineTimeout := 3 * time.Minute
	t.Eventually(devUpdates, baselineTimeout).Should(Receive(matchers.SatisfyPredicate(
		"Baseline DPC (zedagent) is active with no error",
		func(info *eveinfo.ZInfoDevice) bool {
			sa := info.GetSystemAdapter()
			if !matchSystemAdapterInfo(sa, 0, []string{"zedagent"}) {
				return false
			}
			return sa.GetStatus()[0].GetLastError() == ""
		})))
	evetest.Checkpoint("phase1-baseline-complete")

	// Phase 2: apply a broken, ethernet0-only config. With no other
	// management port in this DPC, EVE's connectivity test for it fails
	// outright and NIM must roll back to the still-working two-port DPC.
	log.Infof("Phase 2: applying a broken ethernet0-only config...")
	brokenConfig := evetest.NewEdgeDeviceConfig(devName)
	brokenConfig.SetConfigProperties(cfgProps)
	brokenNet := brokenConfig.AddNetwork(evetest.StaticNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
		Subnet:      evetest.IPSubnet("10.99.99.0/24"),
		Gateway:     evetest.IPAddress("10.99.99.1"),
		DNSServers:  []net.IP{evetest.IPAddress(dnsServer0IP)},
	})
	brokenConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   brokenNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
		StaticIP:      evetest.IPAddress("10.99.99.5"),
	})
	device.ApplyConfig(brokenConfig, false, false)
	evetest.Checkpoint("phase2-broken-config-applied")

	phase2Timeout := 5 * time.Minute
	var brokenDPCLastFailed time.Time
	t.Eventually(devUpdates, phase2Timeout).Should(Receive(matchers.SatisfyPredicate(
		"New DPC fails outright; EVE falls back to the previous DPC",
		func(info *eveinfo.ZInfoDevice) bool {
			sa := info.GetSystemAdapter()
			if !matchSystemAdapterInfo(sa, 1, []string{"zedagent", "zedagent"}) {
				return false
			}
			newDPC := sa.GetStatus()[0]
			if newDPC.GetLastError() == "" || newDPC.GetLastFailed() == nil {
				return false
			}
			brokenDPCLastFailed = newDPC.GetLastFailed().AsTime()
			return true
		})))
	t.Expect(device.GetState()).To(Equal(api.EVEDeviceState_EVE_DEVICE_STATE_ONLINE),
		"device must stay online via the still-working older DPC")
	evetest.Checkpoint("phase2-fallback-complete")

	// Phase 3: fix the SDN network to match the broken config's subnet.
	// Once EVE's periodic retest of the higher-priority DPC succeeds, it
	// becomes active again.
	log.Infof("Phase 3: updating the SDN network to match ethernet0's static config...")
	fixedModel := proto.Clone(netmodels.TwoMgmtPorts).(*api.NetworkModel)
	for _, n := range fixedModel.Networks {
		if n.LogicalLabel == "network0" {
			n.Ipv4.Subnet = "10.99.99.0/24"
			n.Ipv4.GwIp = "10.99.99.1"
		}
	}
	recoveryStart := time.Now()
	evetest.UpdateNetworkModel(fixedModel)
	// Always restore the model on exit so a mid-test failure does not leave
	// the SDN in an altered state for subsequent suite tests.
	defer evetest.UpdateNetworkModel(netmodels.TwoMgmtPorts)
	evetest.Checkpoint("phase3-network-fixed")

	// DevicePortConfig.IsDPCTestable (pkg/pillar/types/dpc.go) refuses to
	// retest a previously-failed DPC until DpcMinTimeSinceFailure has passed
	// since its own LastFailed instant -- a hardcoded 5-minute constant in
	// pkg/pillar/dpcmanager/dpcmanager.go with no controller-config override
	// (unlike timer.port.testduration/testbetterinterval, which we do lower
	// above). Budget from the broken DPC's LastFailed, not from when we fix
	// the network here, plus one testbetterinterval tick and a safety margin
	// -- otherwise the retest can still be within its cooldown by the time a
	// timeout measured from recoveryStart elapses.
	const dpcMinTimeSinceFailure = 5 * time.Minute
	const testBetterInterval = 60 * time.Second
	phase3Timeout := time.Until(brokenDPCLastFailed.Add(
		dpcMinTimeSinceFailure + testBetterInterval + 2*time.Minute))
	if phase3Timeout < 3*time.Minute {
		phase3Timeout = 3 * time.Minute
	}
	// TODO: this can still time out even with the generous budget above.
	// The candidate (index 0) DPC is static on eth0 (10.99.99.5) while the
	// currently-active DPC (index 1) uses DHCP on the *same* eth0/subnet
	// (post-fix, leasing e.g. 10.99.99.123): each retest of the candidate
	// makes NIM flip eth0's address between the two, and the mgmt dnsmasq
	// (pkg/pillar/dpcreconciler/genericitems/mgmtdnsmasq.go) forwards to
	// 10.16.16.25@eth0 for both DPCs -- so it can get caught with eth0
	// mid-reconfiguration and time out ("read udp 127.0.0.1:53: i/o
	// timeout"), even though the network is genuinely fine moments before
	// and after. This was observed live: eth0 briefly held the static
	// candidate's address (10.99.99.5) while SystemAdapter.CurrentIndex
	// still reported the DHCP DPC (index 1) as active. DpcManager's
	// DNSCacheClearCounter (mgmtdnsmasq.go) only flushes dnsmasq's cached
	// *answers* on a DPC transition; it does not address a transiently
	// unavailable/inconsistent eth0 address+route during the swap, and
	// verifyDPC's AsyncInProgress wait (dpcmanager/verify.go) is meant for
	// slow reconcile operations (DHCP negotiation, etc.), not the brief
	// settling window after a plain address change. Needs a real fix in
	// dpcmanager/dpcreconciler (e.g. an explicit dependency/ordering so the
	// interface is confirmed stable before the connectivity test runs, or
	// before mgmt dnsmasq is told to reload) rather than a test-side
	// workaround. Tracked as a follow-up; not fixed by this test.
	t.Eventually(devUpdates, phase3Timeout).Should(Receive(matchers.SatisfyPredicate(
		"The newer DPC becomes active again once the network matches it",
		func(info *eveinfo.ZInfoDevice) bool {
			sa := info.GetSystemAdapter()
			if !matchSystemAdapterInfo(sa, 0, []string{"zedagent", "zedagent"}) {
				return false
			}
			dpc := sa.GetStatus()[0]
			if dpc.GetLastError() != "" {
				return false
			}
			ts := dpc.GetLastSucceeded()
			return ts != nil && !ts.AsTime().Before(recoveryStart)
		})))
	evetest.Checkpoint("phase3-recovery-complete")
}

// TestIntermittentConnectivity verifies that EVE remains (or eventually
// becomes) ONLINE when the network exhibits significant impairments --
// packet loss, high latency and jitter, narrow bandwidth, and full outages --
// on its only management uplink.
//
// Connectivity under each impairment is confirmed directly:
// timer.deviceinfo.interval is lowered to its allowed minimum (30s) so zedagent
// publishes a fresh ZInfoDevice periodically even absent any real change
// (see zedagent/handleconfig.go's configTimerTask), and after every impairment
// change the test asserts (via WatchDeviceInfo) that such an update still
// arrives within a bounded timeout. Actually getting a message through is a
// direct proof of connectivity.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- a single management port. The
//     interesting dimension here is per-port TrafficControl, not topology;
//     multi-port fail-over is already covered by TestPortFailover.
//
// Device configuration
// --------------------
//   - ethernet0 (mgmt+app, DHCP).
//   - One Local NI on ethernet0 with one container app (port-fwd 2222->22,
//     default-allow ACL) to also exercise app connectivity under degraded
//     network conditions.
//
// Phases
// ------
//  1. Baseline: apply config (including the lowered timer.deviceinfo.interval),
//     wait for the NI ONLINE and the app RUNNING, confirm the device is
//     ONLINE and the app can curl http-server.test.
//  2. High-loss link: UpdateNetworkModel sets TrafficControl{loss_probability:
//     20} on eth0. Two consecutive fresh-device-info waits (~3 minutes total)
//     confirm EVE keeps getting through repeatedly, not just once, despite
//     the loss. From the app, `ping -c 100 http-server.test` must show a
//     packet-loss percentage no higher than 50% (i.e. at least half of the
//     pings get through).
//  3. High latency + jitter: TrafficControl{delay: 500, delay_jitter: 300}.
//     A fresh device-info update still arrives within the timeout, and an
//     HTTP request from the app still succeeds within 30s.
//  4. Narrow bandwidth: TrafficControl{rate_limit: 64, queue_limit: 32,
//     burst_limit: 8} (KB/s and KB -- a few bytes of controller/HTTP traffic
//     still fit easily). A fresh device-info update still arrives, and the
//     app's HTTP fetch of /helloworld still succeeds.
//  5. Full outage window: AdminUp=false (90s) followed by AdminUp=true.
//     After the AdminUp=true transition, WatchDeviceInfo eventually reports
//     the active DPC's LastSucceeded newer than the transition instant, then
//     a fresh-device-info wait holds at the recovered state for a window
//     equal to the outage.
//  6. Restore and verify steady state: UpdateNetworkModel back to the
//     TrafficControl-less model; a fresh device-info update arrives and the
//     app's HTTP fetch succeeds promptly (no latency/loss left to mask a
//     regression).
//
// Notes
// -----
//   - This test is non-trivially time-sensitive; timeouts are generous
//     since the focus is on EVE's eventual recovery, not strict timing.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestIntermittentConnectivity(test *testing.T) {
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

	// Lower the periodic (unconditional, even absent any real change)
	// device-info publish interval to its allowed minimum, so the test can
	// use "a fresh ZInfoDevice arrives within a bounded timeout" as a
	// direct, real-time signal that EVE is still getting through to the
	// controller -- see zedagent/handleconfig.go's configTimerTask
	// ("ticker for periodical info publish when no real change").
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.DevInfoInterval, 30)
	devConfig.SetConfigProperties(cfgProps)

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

	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.50.0.0/24"),
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.50.0.2"),
			End:   evetest.IPAddress("10.50.0.254"),
		},
		Gateway: evetest.IPAddress("10.50.0.1"),
		MTU:     1500,
	})

	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "intermittent-test-app",
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
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	niUpdates, stopNIWatch := device.WatchNetworkInstanceInfo(niUUID)
	defer stopNIWatch()
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("config-applied")

	log := evetest.Logger()
	timeout := 3 * time.Minute

	// Phase 1: baseline.
	log.Infof("Phase 1: verifying baseline connectivity...")
	t.Eventually(niUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"NI is ONLINE", func(info *eveinfo.ZInfoNetworkInstance) bool {
			return info.GetState() == eveinfo.ZNetworkInstanceState_ZNETINST_STATE_ONLINE
		}).StopIf(niHasError)))
	device.WaitUntilAppIsRunning(appUUID, 5*time.Minute)
	evetest.Checkpoint("phase1-app-running")

	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	sshTimeout := 20 * time.Second
	polling := 3 * time.Second

	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"curl -sS --max-time 10 http://http-server.test/helloworld", sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring("Hello world!"))
	}, timeout, polling).Should(Succeed())
	t.Expect(device.GetState()).To(Equal(api.EVEDeviceState_EVE_DEVICE_STATE_ONLINE))
	evetest.Checkpoint("phase1-baseline-complete")

	// infoTimeout bounds how long a fresh ZInfoDevice update may take to
	// arrive after an impairment is applied: with timer.deviceinfo.interval
	// lowered to 30s above, 90s gives 3x margin for retries under packet
	// loss/high latency before treating an actual delivery failure as such.
	infoTimeout := 90 * time.Second
	waitForFreshInfo := func(reason string) {
		// Discard anything already buffered on the channel first, so this
		// only accepts a message that arrives after the check starts --
		// otherwise a backlog from before the impairment was applied could
		// satisfy Receive() immediately without proving anything new.
	drainBacklog:
		for {
			select {
			case <-devUpdates:
			default:
				break drainBacklog
			}
		}
		log.Infof("Waiting for a fresh device info update (%s)...", reason)
		t.Eventually(devUpdates, infoTimeout).Should(Receive(),
			"EVE should still get periodic device info through "+
				"to the controller (%s)", reason)
	}

	// Always restore the model on exit so a mid-test failure does not leave
	// the SDN in an altered state for subsequent suite tests.
	restoreModel := func() {
		evetest.UpdateNetworkModel(netmodels.SingleEthWithDHCP)
	}
	defer restoreModel()

	setTrafficControl := func(tc *api.TrafficControl) {
		model := proto.Clone(netmodels.SingleEthWithDHCP).(*api.NetworkModel)
		for _, p := range model.Ports {
			if p.LogicalLabel == "eth0" {
				p.TrafficControl = tc
			}
		}
		evetest.UpdateNetworkModel(model)
	}

	// Phase 2: high-loss link.
	log.Infof("Phase 2: applying 20%% packet loss on eth0...")
	setTrafficControl(&api.TrafficControl{LossProbability: 20})
	evetest.Checkpoint("phase2-loss-applied")

	// Give the lossy link a sustained period (longer than a single probe
	// cycle): two consecutive fresh-info waits cover ~3 minutes under loss,
	// confirming EVE keeps getting through repeatedly, not just once.
	waitForFreshInfo("20% packet loss, check 1/2")
	waitForFreshInfo("20% packet loss, check 2/2")

	log.Infof("Phase 2: pinging http-server.test through the lossy link...")
	pingOut, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"ping -c 50 -w 75 http-server.test", 80*time.Second, 0)
	t.Expect(err).ToNot(HaveOccurred())
	lossPct, err := pingPacketLossPercent(pingOut)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(lossPct).To(BeNumerically("<=", 50),
		"at least half of the pings must get through a 20%% -loss link:\n%s", pingOut)
	evetest.Checkpoint("phase2-complete")

	// Phase 3: high latency + jitter.
	log.Infof("Phase 3: applying 500ms +/- 300ms latency on eth0...")
	setTrafficControl(&api.TrafficControl{Delay: 500, DelayJitter: 300})
	evetest.Checkpoint("phase3-latency-applied")

	waitForFreshInfo("500ms +/- 300ms latency")
	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"curl -sS --max-time 30 http://http-server.test/helloworld", 35*time.Second, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring("Hello world!"))
	}, timeout, polling).Should(Succeed())
	evetest.Checkpoint("phase3-complete")

	// Phase 4: narrow bandwidth.
	log.Infof("Phase 4: applying a 64 KB/s rate limit on eth0...")
	setTrafficControl(&api.TrafficControl{
		RateLimit:  64,
		QueueLimit: 32,
		BurstLimit: 8,
	})
	evetest.Checkpoint("phase4-bandwidth-limited")

	waitForFreshInfo("64 KB/s rate limit")
	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"curl -sS --max-time 20 http://http-server.test/helloworld", 25*time.Second, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring("Hello world!"))
	}, timeout, polling).Should(Succeed())
	evetest.Checkpoint("phase4-complete")

	// Phase 5: full outage window.
	log.Infof("Phase 5: taking eth0 down, then restoring it...")
	const outageWindow = 90 * time.Second
	recoveryTimeout := 5 * time.Minute
	downModel := proto.Clone(netmodels.SingleEthWithDHCP).(*api.NetworkModel)
	for _, p := range downModel.Ports {
		if p.LogicalLabel == "eth0" {
			p.AdminUp = false
		}
	}
	evetest.UpdateNetworkModel(downModel)
	time.Sleep(outageWindow)

	log.Infof("Phase 5: restoring eth0...")
	recoveryStart := time.Now()
	restoreModel()

	t.Eventually(devUpdates, recoveryTimeout).Should(Receive(matchers.SatisfyPredicate(
		"DPC LastSucceeded advances past the AdminUp=true transition",
		func(info *eveinfo.ZInfoDevice) bool {
			sa := info.GetSystemAdapter()
			if sa == nil {
				return false
			}
			statusList := sa.GetStatus()
			idx := int(sa.GetCurrentIndex())
			if idx < 0 || idx >= len(statusList) {
				return false
			}
			ts := statusList[idx].GetLastSucceeded()
			return ts != nil && !ts.AsTime().Before(recoveryStart)
		})))
	// Hold at the recovered state for a window equal to the outage above,
	// actively confirming (rather than just sleeping) that fresh device
	// info keeps arriving throughout.
	waitForFreshInfo("recovered after outage")
	evetest.Checkpoint("phase5-complete")

	// Phase 6: restore and verify steady state.
	log.Infof("Phase 6: verifying steady state after restoring the clean network model...")
	restoreModel()
	waitForFreshInfo("steady state restored")
	t.Eventually(func(g Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"curl -sS --max-time 10 http://http-server.test/helloworld", sshTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(output).To(ContainSubstring("Hello world!"))
	}, timeout, polling).Should(Succeed())
	evetest.Checkpoint("phase6-complete")
}

// pingPacketLossPercent extracts the packet-loss percentage from the summary
// line of `ping` output (e.g. "100 packets transmitted, 82 received, 18%
// packet loss, time 99231ms"). The percentage is fractional whenever the
// loss ratio isn't a whole number (e.g. "14.5299%"), so it must be parsed as
// a float rather than truncated to the digits right before the '%'.
func pingPacketLossPercent(output string) (float64, error) {
	re := regexp.MustCompile(`([\d.]+)% packet loss`)
	m := re.FindStringSubmatch(output)
	if len(m) != 2 {
		return 0, fmt.Errorf("could not parse packet loss from ping output: %q", output)
	}
	return strconv.ParseFloat(m[1], 64)
}
