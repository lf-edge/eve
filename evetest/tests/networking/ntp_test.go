// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import "testing"

// TestDeviceNTPConfig verifies how EVE assembles per-port NTP server lists
// from DHCP and statically-configured sources, that chronyd actually
// synchronizes against the configured peers, and that the configuration
// surfaces correctly in published EVE state.
//
// Scope: device side only. Propagation of NTP servers to applications via
// DHCP option 42 is covered separately by TestApplicationNTPConfig (which
// lives in TestApplicationConnectivitySuite and parameterizes the hypervisor).
//
// SDN framework prerequisite (NOT yet implemented)
// ------------------------------------------------
// SDN exposes the api.NTPServer endpoint type in grpcapi/proto/sdn.proto
// and the sdnagent parses/validates it (parse.go around the GetNtpServers
// loop), but it does NOT actually deploy an NTP daemon: there is no
// `ntpSrv.go` config item under evetest/sdn/vm/pkg/configitems (compare
// with the existing dnsSrv.go / httpSrv.go / scepSrv.go). The DHCP server
// (dhcpSrv.go) is wired to ADVERTISE an NTP server IP via DHCP option 42
// / 56, but nothing actually listens on that IP. Before this test can be
// implemented, the SDN side needs an "NTP server endpoint" config item
// that runs a real NTP daemon (chronyd, ntpd, or a small in-process
// stratum-1-like responder) bound to the endpoint's IP. The scenario
// below assumes that work is complete.
//
// Network model
// -------------
// Add netmodel `MultiPortWithNTPServers` (proposed: evetest/netmodels/multi-eth.go)
// extending TwoMgmtPorts with three SDN NTPServer endpoints:
//
//	eth0 -- DHCP, DHCP advertises NTP server "ntp0" (private endpoint inside SDN)
//	eth1 -- DHCP, DHCP advertises NTP server "ntp1" (different SDN endpoint)
//	   + "ntp-static" reachable via SDN routing for the static-override case.
//
// All NTP endpoints (api.NTPServer in evetest/grpcapi/proto/sdn.proto) run
// inside SDN and answer NTP queries with a stable clock. They have distinct
// IPs so the test can tell which sources EVE actually uses.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt) and eth1 (DHCP, mgmt).
//   - On eth0, also add a STATIC NTP server in NetworkConfig.NTPServers, e.g.
//     "static-ntp.test" (resolved via SDN DNS to the SDN NTPServer endpoint
//     "ntp-static"). Leave IgnoreNTPFromDHCP=false so it is appended to
//     DHCP-provided servers.
//   - On eth1, set IgnoreNTPFromDHCP=true and add a different static entry
//     ("static-ntp-2.test" -> NTPServer "ntp-static-2"). This exercises the
//     DhcpOptionsIgnore.ntp_server_exclusively code path: only ntp-static-2
//     should appear for eth1, NOT ntp1.
//   - Hypervisor: hardcode WithHypervisor=HypervisorKVM in RequireEdgeDevice.
//     Device-suite tests do not parameterize the hypervisor (the device-level
//     plumbing under test does not depend on app virtualization).
//
// Assertions
// ----------
//   - WatchDeviceInfo / DevicePortStatus.ntpServer + more_ntp_servers:
//   - eth0 reports BOTH ntp0 (DHCP) and ntp-static (static append).
//   - eth1 reports ONLY ntp-static-2 (the DHCP-supplied ntp1 must be
//     filtered out by the exclusive flag).
//   - WatchNTPSources (uses the ZInfoNTPSources publication; see
//     edgedevice.go GetNTPSources / WatchNTPSources and
//     proto/info/ntpsources.proto):
//   - Eventually at least one source reaches state SYNC ('*').
//   - The set of source addresses contains every configured NTP IP EVE
//     should be using (ntp0, ntp-static, ntp-static-2). ntp1 must NOT
//     appear (it was excluded by the exclusive flag).
//   - Each tracked source has mode=CLIENT and reachability ramps up
//     (consistently within a few minutes).
//   - SSH check (acceptable -- chronyd is the canonical timekeeping
//     daemon on EVE per CLOCK-SYNCHRONIZATION.md): `chronyc tracking`
//     reports a non-zero Reference ID matching one of the configured SDN
//     NTPServer IPs.
//
// Runtime update
// --------------
//   - UpdateNetworkAdapter to remove ntp-static from eth0; re-apply.
//   - Eventually:
//   - DevicePort NTP list shrinks accordingly.
//   - WatchNTPSources stops including ntp-static (state may transition
//     to UNREACH first; the eventual condition is "source disappears
//     or stops being used").
//
// Notes
// -----
//   - The test does not depend on real-world Internet NTP (pool.ntp.org).
//     All NTP traffic stays inside SDN.
//   - DHCPNetworkConfig already exposes NTPServers + IgnoreNTPFromDHCP and
//     the evecommon.DhcpOptionsIgnore plumbing -- no framework additions
//     are needed.
func TestDeviceNTPConfig(test *testing.T) {
	test.Skip("not yet implemented")
}

// TestApplicationNTPConfig verifies that the per-NI DHCP server propagates
// the correct NTP server list (port-NTP ∪ NI-NTP) to applications via DHCP
// option 42 / 56, and that the application's NI VIF status reflects this in
// published EVE state.
//
// Scope: application side only. Device-side NTP plumbing is covered by
// TestDeviceNTPConfig.
//
// SDN framework prerequisite (NOT yet implemented)
// ------------------------------------------------
// Same prerequisite as TestDeviceNTPConfig: SDN must actually run an NTP
// daemon bound to each `api.NTPServer` endpoint's IP. The proto/API exists
// and the sdnagent validates the config, but there is no NTP server config
// item that actually listens on the wire (no `ntpSrv.go` under
// evetest/sdn/vm/pkg/configitems). The DHCP server can only advertise an
// NTP server IP via DHCP option 42; nothing answers on that IP today.
// In-app chronyc would therefore never see a SYNC source. This test cannot
// be implemented until that gap is filled.
//
// Network model
// -------------
// Reuse the same `MultiPortWithNTPServers` netmodel proposed for
// TestDeviceNTPConfig. Add one more SDN NTPServer endpoint "ntp-local-ni"
// that the NI itself will advertise to apps in addition to the port-level
// NTP servers.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+app, with static NTP "ntp-static"
//     appended) and eth1 (DHCP, mgmt, with exclusive override -- only
//     ntp-static-2 used). Same plumbing as TestDeviceNTPConfig.
//   - One Local NI ("local-ni") on eth0 with its own NIConfig.NTPServers
//     entry pointing to "ntp-local-ni". The NI's dnsmasq must merge port
//     NTP servers and the NI NTP server and advertise the union to apps.
//   - One container app on the NI (default-allow + port-fwd 2222->22).
//     Use the existing milan4zededa/evetest-ubuntu-ctr image; it ships
//     with chronyd which will sync against whatever DHCP delivers.
//
// Assertions
// ----------
//   - WaitUntilAppIsRunning(appUUID).
//   - WatchAppInfo: the app VIF's ZInfoNetwork.ntp_servers reports the
//     EXPECTED set: ntp0, ntp-static (from the port), plus ntp-local-ni
//     (from the NI itself). ntp1 / ntp-static-2 must NOT appear (they
//     belong to eth1, which is not used by this NI). Use set equality so
//     accidental over-reporting is caught.
//   - SSH inside the app: `chronyc sources` reports the same set of
//     servers. Optionally `cat /etc/chrony.conf` to confirm the DHCP-driven
//     configuration was applied. (chronyd-in-container is supported on the
//     evetest-ubuntu-ctr image; see CLOCK-SYNCHRONIZATION.md
//     "Recommendations when NTP is not available on the Guests".)
//
// Runtime update
// --------------
//   - UpdateNetworkInstance to remove ntp-local-ni from the NI's NTP list.
//     To force the app to pick up the new DHCP option without redeploying,
//     either DeactivateApplication + ActivateApplication to trigger a fresh
//     DHCP cycle, or wait for the DHCP lease renewal. The first approach
//     is faster and is what the eden tests effectively do.
//   - After re-acquire: ZInfoNetwork.ntp_servers no longer includes
//     ntp-local-ni; the in-app chronyc sources reflects the same change.
//
// Test params
// -----------
//   - HYPERVISOR. The test must call evetest.SkipIfHypervisorKubevirt()
//     after reading the parameter -- Kubevirt is reserved for cluster tests.
//
// Notes
// -----
//   - All NTP traffic stays inside SDN; no public pool.ntp.org dependency.
//   - LocalNetworkInstanceConfig already exposes NTPServers in the framework,
//     so no devconfig changes are required.
func TestApplicationNTPConfig(test *testing.T) {
	test.Skip("not yet implemented")
}
