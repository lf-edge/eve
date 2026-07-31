// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"strings"
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
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

// TestDeviceNTPConfig verifies how EVE assembles per-port NTP server lists
// from DHCP and statically-configured sources, that a per-port exclusive
// override correctly discards the DHCP-provided entry, and that chronyd
// actually synchronizes against the resulting device-wide server set.
//
// Scope: device side only. Propagation of NTP servers to applications via
// DHCP option 42 is covered separately by TestApplicationNTPConfig.
//
// NTP servers used
// -----------------
// Real, long-stable, single-IP public NTP servers rather than an SDN-hosted
// fake one, so the test needs no SDN-side NTP daemon and can still assert on
// exact addresses (unlike pool.ntp.org-style rotating addresses):
//   - 162.159.200.1 (Cloudflare's primary anycast NTP address) -- advertised
//     via DHCP option 42 on eth0 (see netmodels.TwoMgmtPortsWithPublicNTP).
//   - 216.239.35.0 (Google's time1.google.com address) -- advertised via
//     DHCP option 42 on eth1; must be excluded (see below).
//   - 162.159.200.123 (Cloudflare's secondary anycast NTP address) --
//     statically configured on both ports (device side).
//
// Network model
// -------------
//   - netmodels.TwoMgmtPortsWithPublicNTP -- two management ports, each
//     advertising a different public NTP server via DHCP option 42.
//
// Device configuration
// --------------------
//   - ethernet0 (eth0, mgmt, cost=0): DHCP with the static server appended
//     (IgnoreNTPFromDHCP=false). Effective set: {DHCP-provided Cloudflare
//     primary, static Cloudflare secondary}.
//   - ethernet1 (eth1, mgmt, cost=1): DHCP with IgnoreNTPFromDHCP=true and
//     the same static server. The DHCP-provided Google address must be
//     discarded. Effective set: {static Cloudflare secondary} only.
//
// Phases
// ------
//  1. Per-port NTP state: waits (WatchDeviceInfo) until both ports have
//     acquired DHCP addresses and DevicePort.ntpServer + more_ntp_servers
//     match the expected sets exactly (set equality, catching both missing
//     entries and the exclusive-override leaking the DHCP entry through).
//  2. Device-wide chrony synchronization: chronyd has a single global source
//     list built from the deduplicated union of every port's NTP servers
//     (see pkg/pillar/scripts/device-steps.sh, get_ntp_servers_from_nim), so
//     the Google address excluded on eth1 must never reach chronyd either.
//     WatchNTPSources (ZInfoNTPSources) eventually reports at least one
//     source in SYNC state and a source-address set equal to exactly the two
//     Cloudflare addresses.
//  3. SSH cross-check: `eve exec pillar chronyc sources` (chronyd runs inside
//     the pillar service container) shows at least one of the two Cloudflare
//     addresses marked as the current sync source ('*').
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestDeviceNTPConfig(test *testing.T) {
	const (
		ntpCloudflarePrimary   = "162.159.200.1"   // DHCP-advertised on eth0
		ntpCloudflareSecondary = "162.159.200.123" // statically configured on both ports
	)

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
			NetworkModel: netmodels.TwoMgmtPortsWithPublicNTP,
		},
		evetest.RequireInternetConnectivity{},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	net0 := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
		NTPServers:  []string{ntpCloudflareSecondary},
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   net0,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
		Cost:          0,
	})

	net1 := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType:       evecommon.NetworkType_V4Only,
		NTPServers:        []string{ntpCloudflareSecondary},
		IgnoreNTPFromDHCP: true,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		NetworkUUID:   net1,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
		Cost:          1,
	})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("config-applied")

	log := evetest.Logger()

	// Phase 1: per-port NTP state.
	log.Infof("Phase 1: waiting for per-port NTP state to settle...")
	phase1Timeout := 3 * time.Minute
	t.Eventually(devUpdates, phase1Timeout).Should(Receive(matchers.SatisfyPredicate(
		"Both ports have expected NTP servers",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			eth0 := getDevicePort("ethernet0", dinfo)
			eth1 := getDevicePort("ethernet1", dinfo)
			if eth0 == nil || eth1 == nil {
				return false
			}
			if len(eth0.GetIPAddrs()) == 0 || len(eth1.GetIPAddrs()) == 0 {
				return false
			}
			// eth1's expected set has only the static entry, so this already
			// requires the DHCP-provided Google address to be absent (a set
			// containing it, or an empty set, would both fail EqualSets here).
			return generics.EqualSets(portNtpServers(eth0),
				[]string{ntpCloudflarePrimary, ntpCloudflareSecondary}) &&
				generics.EqualSets(portNtpServers(eth1), []string{ntpCloudflareSecondary})
		})))
	evetest.Checkpoint("phase1-complete")

	// Phase 2: device-wide chrony synchronization.
	log.Infof("Phase 2: waiting for chronyd to synchronize with the expected NTP servers...")
	expectedSources := []string{ntpCloudflarePrimary, ntpCloudflareSecondary}
	ntpUpdates, stopNTPWatch := device.WatchNTPSources()
	defer stopNTPWatch()
	if ntpSourcesSynced(device.GetNTPSources(), expectedSources) {
		log.Infof("chronyd is already synchronized with the expected NTP servers")
	} else {
		phase2Timeout := 5 * time.Minute
		t.Eventually(ntpUpdates, phase2Timeout).Should(Receive(matchers.SatisfyPredicate(
			"chronyd synchronized with exactly the expected NTP servers",
			func(sources *eveinfo.ZInfoNTPSources) bool {
				return ntpSourcesSynced(sources, expectedSources)
			})))
	}
	evetest.Checkpoint("phase2-complete")

	// Phase 3: SSH cross-check via chronyc (chronyd runs inside the pillar
	// service container). "-n" disables reverse-DNS lookups so the address
	// column shows the numeric IP we configured, not a resolved hostname.
	log.Infof("Phase 3: cross-checking via chronyc sources over SSH...")
	output, _, err := device.RunShellScript(
		"eve exec pillar chronyc -n sources", 15*time.Second, 0)
	t.Expect(err).ToNot(HaveOccurred())
	foundSyncedLine := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "^*") &&
			(strings.Contains(line, ntpCloudflarePrimary) ||
				strings.Contains(line, ntpCloudflareSecondary)) {
			foundSyncedLine = true
			break
		}
	}
	t.Expect(foundSyncedLine).To(BeTrue(),
		"chronyc sources must show one of the expected Cloudflare addresses "+
			"as the current sync source ('^*'):\n%s", output)
	evetest.Checkpoint("phase3-complete")
}

// portNtpServers combines DevicePort.ntpServer and more_ntp_servers into a
// single slice (or nil if the port has no NTP servers configured).
func portNtpServers(port *eveinfo.DevicePort) []string {
	if port.GetNtpServer() == "" {
		return nil
	}
	return append([]string{port.GetNtpServer()}, port.GetMoreNtpServers()...)
}

// ntpSourcesSynced reports whether sources contains at least one source in
// SYNC state and its set of source addresses equals exactly expectedAddrs.
func ntpSourcesSynced(sources *eveinfo.ZInfoNTPSources, expectedAddrs []string) bool {
	if sources == nil {
		return false
	}
	var addrs []string
	synced := false
	for _, src := range sources.GetSources() {
		addrs = append(addrs, src.GetDstAddr())
		if src.GetState() == eveinfo.NTPSourceState_NTP_SOURCE_STATE_SYNC {
			synced = true
		}
	}
	return synced && generics.EqualSets(addrs, expectedAddrs)
}

// TestApplicationNTPConfig verifies that the per-NI DHCP server propagates
// the correct NTP server list (port-NTP union NI-NTP) to an application, and
// that the application's NI VIF status reflects this in published EVE state.
//
// Scope: application side only. Device-side NTP plumbing is covered by
// TestDeviceNTPConfig.
//
// Known limitation: EVE's per-NI dnsmasq does advertise the NTP list via
// DHCP option 42 (the same mechanism that carries DNS servers), but the
// shim-VM's DHCP client script (pkg/xen-tools/initrd/udhcpc_script.sh) only
// acts on the DNS/IP/route options it receives -- it never writes the NTP
// option (udhcpc's "$ntpsrv") anywhere inside the guest. So unlike DNS
// servers (verifiable via nslookup from inside the app), there is currently
// no guest-visible effect of the DHCP-advertised NTP list to check over SSH;
// this test can only verify what EVE itself reports it configured
// (ZInfoNetwork.ntp_servers), which is exactly the per-NI DHCP server's
// computed advertisement.
//
// NTP servers used
// -----------------
// Reuses the same real public NTP servers as TestDeviceNTPConfig, plus one
// more for the NI-level override:
//   - 162.159.200.1 (Cloudflare primary) -- DHCP-advertised on eth0.
//   - 162.159.200.123 (Cloudflare secondary) -- statically configured on
//     eth0.
//   - 216.239.35.0 (Google time1) -- DHCP-advertised on eth1 (unrelated port;
//     must not leak into the app).
//   - 216.239.35.4 (Google time2) -- configured on the Local NI itself.
//
// Network model
// -------------
//   - netmodels.TwoMgmtPortsWithPublicNTP (same model as TestDeviceNTPConfig).
//
// Device configuration
// --------------------
//   - ethernet0 (eth0, mgmt+app, cost=0): DHCP with the Cloudflare secondary
//     server appended. Effective port set: {Cloudflare primary (DHCP),
//     Cloudflare secondary (static)}.
//   - ethernet1 (eth1, mgmt only): plain DHCP, left unexcluded (Google time1
//     stays active on this port), but not part of any NI -- present purely
//     to prove a port's NTP servers don't leak into an app bound to a
//     different port.
//   - One Local NI ("local-ni") on eth0 with its own NTPServers entry
//     pointing at the Google time2 address.
//   - One container app on the NI (default-allow ACL + port-fwd 2222->22),
//     using the lfedge/evetest-ubuntu-ctr image.
//
// Phases
// ------
//  1. WaitUntilAppIsRunning, then wait (WatchAppInfo) until the app's VIF
//     receives an IP from the NI subnet and ZInfoNetwork.ntp_servers equals
//     exactly the port union NI set: {Cloudflare primary, Cloudflare
//     secondary, Google time2}. Set equality (not subset) also catches
//     eth1's Google time1 address leaking through, which must not happen
//     since the NI doesn't use eth1.
//  2. Runtime update: removes the NI's NTPServers entry (UpdateNetworkInstance)
//     and deactivates/reactivates the app to force a fresh DHCP cycle.
//     Eventually ZInfoNetwork.ntp_servers drops the Google time2 address,
//     leaving only the two eth0 port-level servers.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestApplicationConnectivitySuite.
func TestApplicationNTPConfig(test *testing.T) {
	const (
		ntpCloudflarePrimary   = "162.159.200.1"   // DHCP-advertised on eth0
		ntpCloudflareSecondary = "162.159.200.123" // statically configured on eth0
		ntpGoogleTime2         = "216.239.35.4"    // configured on the NI itself
	)

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
			NetworkModel: netmodels.TwoMgmtPortsWithPublicNTP,
		},
		evetest.RequireInternetConnectivity{},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	net0 := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
		NTPServers:  []string{ntpCloudflareSecondary},
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   net0,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})

	// ethernet1 is not used by the NI below; it is configured (with its own
	// DHCP-advertised NTP server left active, unexcluded) purely to prove
	// that a port's NTP servers do not leak into an app whose NI is bound to
	// a different port.
	net1 := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet1",
		PhysicalLabel: "eth1",
		InterfaceName: "eth1",
		NetworkUUID:   net1,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtOnly,
	})

	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	niSubnet := evetest.IPSubnet("10.11.12.0/24")
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      niSubnet,
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:    evetest.IPAddress("10.11.12.1"),
		NTPServers: []string{ntpGoogleTime2},
		MTU:        1500,
	})

	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "ntp-test-app",
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

	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("config-applied")

	log := evetest.Logger()
	timeout := 5 * time.Minute

	log.Infof("Waiting for the app to become running...")
	device.WaitUntilAppIsRunning(appUUID, timeout)
	evetest.Checkpoint("app-running")

	// Phase 1: app VIF NTP server set.
	log.Infof("Phase 1: waiting for the app VIF to report the expected NTP servers...")
	expectedNTPServers := []string{ntpCloudflarePrimary, ntpCloudflareSecondary, ntpGoogleTime2}
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App VIF has an IP from the NI subnet and the expected NTP server set",
		func(info *eveinfo.ZInfoApp) bool {
			if len(info.Network) != 1 || len(info.Network[0].IPAddrs) == 0 {
				return false
			}
			return generics.EqualSets(info.Network[0].GetNtpServers(), expectedNTPServers)
		}).StopIf(appHasError)))
	evetest.Checkpoint("phase1-complete")

	// Phase 2: runtime update -- remove the NI-level NTP server and force a
	// fresh DHCP cycle by deactivating and reactivating the app.
	log.Infof("Phase 2: removing the NI's NTP server and forcing a fresh DHCP cycle...")
	devConfig.UpdateNetworkInstance(niUUID, evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      niSubnet,
		DHCPRange: pillartypes.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway: evetest.IPAddress("10.11.12.1"),
		MTU:     1500,
	})
	device.ApplyConfig(devConfig, false, false)
	device.DeactivateApplication(appUUID, true, timeout)
	device.ActivateApplication(appUUID, true, timeout)

	expectedNTPServersAfterUpdate := []string{ntpCloudflarePrimary, ntpCloudflareSecondary}
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"App VIF NTP servers no longer include the removed NI-level server",
		func(info *eveinfo.ZInfoApp) bool {
			if len(info.Network) != 1 || len(info.Network[0].IPAddrs) == 0 {
				return false
			}
			return generics.EqualSets(info.Network[0].GetNtpServers(), expectedNTPServersAfterUpdate)
		}).StopIf(appHasError)))
	evetest.Checkpoint("phase2-complete")
}
