// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
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
//   - None. WithHypervisor=HypervisorKVM is hardcoded in RequireEdgeDevice
//     because this test lives in TestDeviceConnectivitySuite and
//     Device-suite tests do not parameterize the hypervisor.
func TestPortFailover(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    evetest.HypervisorKVM,
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
// reach the controller, and that it re-applies the new config once the
// network actually matches it.
//
// Network model
//   - Start with netmodels.TwoMgmtPorts. The "second" port (eth1) is initially
//     used as a backup with cost=10.
//
// Device configuration
//   - Initial config: SystemAdapter for eth0 (mgmt) DHCP, SystemAdapter for
//     eth1 (mgmt) DHCP. Apply, wait until SystemAdapterInfo (in published
//     device info) reports currentIndex=0 and exactly one DevicePortStatus
//     entry with key="zedagent" -- same pattern as bootstrap_test.go uses
//     via its matchSystemAdapterInfo helper. No raw pubsub readback is
//     needed; the SystemAdapterInfo embedded in ZInfoDevice carries the
//     full DPC list, the currentIndex pointer, and per-DPC lastError /
//     lastFailed / lastSucceeded timestamps.
//
// Phase 1 — induce a broken-config rollback
//   - Apply a NEW device config that intentionally does NOT match the SDN
//     network (so it cannot reach the controller):
//     -> Switch eth0 to StaticNetworkConfig with a wrong subnet/gateway
//     (e.g., 10.99.99.0/24 / 10.99.99.1).
//   - Wait for EVE to test the new config and fall back. All assertions
//     read SystemAdapterInfo from WatchDeviceInfo:
//   - SystemAdapterInfo.Status grows by one entry (the just-submitted DPC).
//     The new DPC -- the one at index 0 by priority -- must have
//     LastError set to a description mentioning the connectivity test
//     failure, and LastFailed timestamp populated.
//   - SystemAdapterInfo.CurrentIndex points at the OLDER (working) DPC,
//     not the one we just submitted (i.e. CurrentIndex > 0).
//   - The older DPC referenced by CurrentIndex must have LastSucceeded
//     advancing (it is still working).
//   - The device must REMAIN online — controller still receives info
//     messages, RunShellScript still works.
//
// Phase 2 — recovery
//   - UpdateNetworkModel (or update SDN router config) to make the network
//     actually match the broken config. For variant (a), change the SDN
//     network's subnet/gateway from 172.20.20.0/24 to 10.99.99.0/24
//     (clone netmodels.TwoMgmtPorts and rewrite Networks[0].Ipv4 — note
//     evetest.UpdateNetworkModel allows changing subnets but not the set
//     of ports).
//   - EVE periodically retests higher-priority DPCs (timer.port.testbetterinterval,
//     default 10 min — set it lower via SetConfigProperties for the test,
//     e.g. 60 s). Watching SystemAdapterInfo, eventually:
//   - CurrentIndex returns to 0 (the latest DPC works again).
//   - DevicePortStatus[0].LastSucceeded advances to a timestamp newer than
//     the recovery moment, and LastError is cleared.
//
// Future extension
// ----------------
//   - Variant where the new config IS valid (network model is updated to
//     match) but the controller temporarily blocks the device. Confirm
//     that a brief, "remote" failure (server cert expired) does NOT trigger
//     a fallback (per DEVICE-CONNECTIVITY.md "Handling remote (temporary)
//     failures").
func TestNetworkConfigFallback(test *testing.T) {
	test.Skip("not yet implemented")
}

// TestIntermittentConnectivity verifies that EVE remains (or eventually
// becomes) ONLINE when the network exhibits significant impairments such as
// high latency, packet loss, low bandwidth and intermittent outages.
//
// Network model
//   - Single management port (netmodels.SingleEthWithDHCP). The interesting
//     dimension is the per-port TrafficControl, not topology. We don't need
//     multi-port to exercise resilience to a flaky single uplink.
//
// Device configuration
//   - Plain DHCP-on-eth0 mgmt config.
//   - Add a Local NI + a small ICMP-only test app to also exercise app
//     connectivity under degraded network conditions.
//
// Phase 1 — baseline
//   - Apply config and confirm device is ONLINE, app is RUNNING, app can curl
//     http-server.test.
//
// Phase 2 — high-loss link
//   - UpdateNetworkModel: set TrafficControl on eth0 with loss_probability=20.
//   - Consistently for, say, 3 minutes (longer than EVE's default test
//     interval), poll device.GetState() / DeviceInfo: device must stay
//     ONLINE. SystemAdapterInfo.currentIndex must remain 0 (no fallback —
//     EVE retries succeed often enough).
//   - The app's `ping http-server.test` should mostly succeed (>50%
//     success rate) — assert >= 50% success over 100 pings.
//
// Phase 3 — high latency + jitter
//   - UpdateNetworkModel: TrafficControl{delay=500, delay_jitter=300, loss=0}.
//   - Device must stay ONLINE; HTTP request from app must still succeed
//     within a reasonable timeout (e.g. 30s).
//
// Phase 4 — narrow bandwidth
//   - UpdateNetworkModel: TrafficControl{rate_limit=64 KB/s, queue_limit=32 KB,
//     burst_limit=8 KB}.
//   - Device must stay ONLINE (controller traffic is small).
//   - The app's HTTP fetch of "/helloworld" must still succeed (it's a few
//     bytes of payload).
//
// Phase 5 — full outage windows
//   - For three iterations, alternate:
//     a) UpdateNetworkModel: AdminUp=false on eth0 -> hold for 90s.
//     b) UpdateNetworkModel: AdminUp=true -> hold for 90s.
//   - During AdminUp=false windows, device may transiently report an error
//     for the port; this is acceptable. The hard requirement is that the
//     device returns to ONLINE within X seconds (e.g. 60s) of every
//     AdminUp=true transition.
//   - lastSucceeded timestamp on the active DPC must keep advancing across
//     the test duration.
//
// Phase 6 — restore and verify steady state
//   - UpdateNetworkModel back to TrafficControl-less; verify ONLINE,
//     latency-free behavior.
//
// Notes
// -----
//   - This test is non-trivially time-sensitive. Generous timeouts are
//     necessary; the focus is on EVE's eventual recovery, not strict timing.
//   - If a CI run becomes too long, individual phases can be split into
//     separate test functions (each phase already maps cleanly to a sub-test).
func TestIntermittentConnectivity(test *testing.T) {
	test.Skip("not yet implemented")
}
