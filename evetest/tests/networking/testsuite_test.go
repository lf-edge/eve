// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestBootstrapSuite drives every network-bootstrapping scenario in this
// package. Each subtest exercises the controller-onboarding path of a
// fresh EVE device whose initial network config has to be supplied
// out-of-band (bootstrap config or override.json). The suite registers two
// variants per scenario where applicable, so we run the same scenario
// once with bootstrap config and once with override.json.
//
// Subtests
// --------
//   - TestBootstrapWithLastResort (variants: LAST_RESORT_ENABLED=false
//     and =true) -- fresh install with neither bootstrap nor override.json;
//     EVE must fall back to last-resort to reach the controller, and the
//     retention behavior of last-resort in the DPCL depends on
//     network.fallback.any.eth.
//   - TestBootstrapWithStaticIP (variants: bootstrap config /
//     override.json) -- static IPv4 on a DHCP-less SDN network.
//   - TestBootstrapWithProxy (variants: manual / transparent /
//     auto-discovery proxy, each in both injection paths) -- SDN drops
//     direct controller traffic; EVE must onboard via the proxy.
//   - TestBootstrapWithMgmtVLAN (variants: bootstrap / override.json) --
//     management VLAN sub-interface required at first boot.
//   - TestBootstrapWithLACPBond (variants: bootstrap / override.json) --
//     SDN-side LACP peer requires the bond to be configured before EVE
//     ever transmits, hence bootstrap-only path.
//
// All bootstrap tests hardcode WithHypervisor=HypervisorKVM and do not
// parameterize the hypervisor.
func TestBootstrapSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	// This below will be implemented using t.Run()
	// Note that evetest.Close needs to behave differently when test is part of
	// a test suite and there are more tests to execute.
	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestBootstrapWithLastResort,
			Variants: []evetest.TestVariant{
				{
					Name: "TestBootstrapWithLastResortDisabled",
					Parameters: []evetest.TestParameterValue{
						{Key: lastResortParamKey, Value: false},
					},
				},
				{
					Name: "TestBootstrapWithLastResortEnabled",
					Parameters: []evetest.TestParameterValue{
						{Key: lastResortParamKey, Value: true},
					},
				},
				// Add at least one bootstrap test exercising EVE installation.
				{
					Name: "TestBootstrapWithInstaller",
					Parameters: []evetest.TestParameterValue{
						{Key: lastResortParamKey, Value: false},
						{Key: useInstallerParamKey, Value: true},
					},
				},
			},
		},
		evetest.TestCase{
			Test: TestBootstrapWithStaticIP,
			Variants: []evetest.TestVariant{
				{
					Name: "TestBootstrapWithStaticIP",
					Parameters: []evetest.TestParameterValue{
						{Key: useOverrideJSONParamKey, Value: false},
					},
				},
				{
					Name: "TestBootstrapWithStaticIPUsingOverrideJSON",
					Parameters: []evetest.TestParameterValue{
						{Key: useOverrideJSONParamKey, Value: true},
					},
				},
			},
		},
		evetest.TestCase{
			Test: TestBootstrapWithProxy,
			Variants: []evetest.TestVariant{
				{
					Name: "TestBootstrapWithManualProxyConfig",
					Parameters: []evetest.TestParameterValue{
						{Key: useOverrideJSONParamKey, Value: false},
						{Key: proxyConfigTypeParamKey, Value: ProxyConfigManual},
					},
				},
				{
					Name: "TestBootstrapWithManualProxyConfigUsingOverrideJSON",
					Parameters: []evetest.TestParameterValue{
						{Key: useOverrideJSONParamKey, Value: true},
						{Key: proxyConfigTypeParamKey, Value: ProxyConfigManual},
					},
				},
				{
					Name: "TestBootstrapWithTransparentProxy",
					Parameters: []evetest.TestParameterValue{
						{Key: useOverrideJSONParamKey, Value: false},
						{Key: proxyConfigTypeParamKey, Value: ProxyConfigTransparent},
					},
				},
				{
					Name: "TestBootstrapWithTransparentProxyUsingOverrideJSON",
					Parameters: []evetest.TestParameterValue{
						{Key: useOverrideJSONParamKey, Value: true},
						{Key: proxyConfigTypeParamKey, Value: ProxyConfigTransparent},
					},
				},
				{
					Name: "TestBootstrapWithAutoDiscoveredProxy",
					Parameters: []evetest.TestParameterValue{
						{Key: useOverrideJSONParamKey, Value: false},
						{Key: proxyConfigTypeParamKey, Value: ProxyConfigAutoDiscovery},
					},
				},
				{
					Name: "TestBootstrapWithAutoDiscoveredProxyUsingOverrideJSON",
					Parameters: []evetest.TestParameterValue{
						{Key: useOverrideJSONParamKey, Value: true},
						{Key: proxyConfigTypeParamKey, Value: ProxyConfigAutoDiscovery},
					},
				},
			},
		},
		evetest.TestCase{
			Test: TestBootstrapWithMgmtVLAN,
			Variants: []evetest.TestVariant{
				{
					Name: "TestBootstrapWithMgmtVLAN",
					Parameters: []evetest.TestParameterValue{
						{Key: useOverrideJSONParamKey, Value: false},
					},
				},
				{
					Name: "TestBootstrapWithMgmtVLANUsingOverrideJSON",
					Parameters: []evetest.TestParameterValue{
						{Key: useOverrideJSONParamKey, Value: true},
					},
				},
			},
		},
		evetest.TestCase{
			Test: TestBootstrapWithLACPBond,
			Variants: []evetest.TestVariant{
				{
					Name: "TestBootstrapWithLACPBond",
					Parameters: []evetest.TestParameterValue{
						{Key: useOverrideJSONParamKey, Value: false},
					},
				},
				{
					Name: "TestBootstrapWithLACPBondUsingOverrideJSON",
					Parameters: []evetest.TestParameterValue{
						{Key: useOverrideJSONParamKey, Value: true},
					},
				},
			},
		},
	)
}

// TestDeviceConnectivitySuite drives every device-side networking
// scenario: how EVE itself manages its physical / L2 / IP adapters and
// keeps controller connectivity alive. None of the subtests deploy an
// application -- they focus on the EVE control plane only -- and therefore
// none parameterize the hypervisor (all hardcode HypervisorKVM via the
// shared deviceRequirementsForNetAdapterTests / deviceRequirementsForBootstrap
// helpers or directly).
//
// Subtests
// --------
//   - TestPNAC (variants: REQUIRE_SCEP_PROXY=false / =true) -- 802.1X +
//     SCEP enrollment.
//   - TestDHCPIPv4Only / TestStaticIPv4Only -- IPv4-only port config on a
//     dual-stack SDN network.
//   - TestDNSFunctionality -- per-port DNS aggregation, resolv.conf
//     completeness, DHCP-override exclusivity (currently a stub
//     scenario).
//   - TestPortFailover / TestNetworkConfigFallback /
//     TestIntermittentConnectivity -- fail-over / fallback resilience
//     (currently stub scenarios).
//   - TestDeviceIPv6Connectivity -- IPv6-only device side (stub scenario).
//   - TestDeviceNTPConfig -- per-port NTP server propagation to EVE's
//     chrony (stub scenario; needs SDN-side NTP daemon).
//   - TestActiveBackupBond / TestLACPBond -- bond status, failover,
//     LACP negotiation.
//   - TestVLANSubinterfaces / TestVLANSubinterfacesOnTopOfLAGs -- VLAN
//     sub-interfaces (stub scenarios).
//   - TestCellularConnectivity / TestWifiConnectivity -- wireless;
//     intentionally unimplemented (require PCI/USB passthrough).
func TestDeviceConnectivitySuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestPNAC,
			Variants: []evetest.TestVariant{
				{
					Name: "TestPNACWithoutProxy",
					Parameters: []evetest.TestParameterValue{
						{Key: requireSCEPProxyParamKey, Value: false},
					},
				},
				{
					Name: "TestPNACWithProxy",
					Parameters: []evetest.TestParameterValue{
						{Key: requireSCEPProxyParamKey, Value: true},
					},
				},
			},
		},
		evetest.TestCase{
			Test: TestDHCPIPv4Only,
		},
		evetest.TestCase{
			Test: TestStaticIPv4Only,
		},
		evetest.TestCase{
			Test: TestDNSFunctionality,
		},
		evetest.TestCase{
			Test: TestPortFailover,
		},
		evetest.TestCase{
			Test: TestNetworkConfigFallback,
		},
		evetest.TestCase{
			Test: TestIntermittentConnectivity,
		},
		evetest.TestCase{
			Test: TestDeviceIPv6Connectivity,
		},
		evetest.TestCase{
			Test: TestDeviceNTPConfig,
		},
		evetest.TestCase{
			Test: TestActiveBackupBond,
		},
		evetest.TestCase{
			Test: TestLACPBond,
		},
		evetest.TestCase{
			Test: TestVLANSubinterfaces,
		},
		evetest.TestCase{
			Test: TestVLANSubinterfacesOnTopOfLAGs,
		},
		evetest.TestCase{
			Test: TestCellularConnectivity,
		},
		evetest.TestCase{
			Test: TestWifiConnectivity,
		},
	)
}

// TestApplicationConnectivitySuite drives every application-side
// networking scenario. All subtests deploy at least one application and
// therefore share the HYPERVISOR parameter -- the suite declares
// evetest.HypervisorParameter() once and every subtest reads it via
// evetest.GetHypervisorParameterValue(). Each subtest also calls
// evetest.SkipIfHypervisorKubevirt() right after reading the value:
// Kubevirt is reserved for cluster tests under evetest/tests/cluster.
//
// Subtests
// --------
//   - TestLocalNI / TestSwitchNI -- canonical Local-NI / Switch-NI
//     life-cycles plus connected-app smoke tests.
//   - TestFlowLog -- per-app flow log + DNS log assertions
//     (skipped; depends on GetAppFlowLogs / GetAppDNSLogs which are not
//     yet wired up in evetest).
//   - TestLocalNetInstanceACLs / TestSwitchNetInstanceACLs -- ACL
//     filtering on Local / Switch NIs (variants: ENABLE_FLOWLOG=false / =true).
//   - TestApplicationIPv6Connectivity -- app on a Switch NI in an
//     IPv6-only segment (stub scenario).
//   - TestApplicationNTPConfig -- DHCP-propagated NTP server set
//     reaching the application (stub scenario; needs SDN NTP daemon).
//   - TestPropagatedRoutes / TestLocalNIWithMultiplePorts /
//     TestApplicationGateway -- IP-routing-related scenarios mirroring
//     the eden app-routing examples (stub scenarios).
//   - TestSwitchNIWithMultiplePorts -- STP / BPDU-guard on a Switch NI
//     with redundant L2 links (stub scenario).
//   - TestAccessVLANs -- VLAN-aware Switch NI (stub scenario).
//   - TestNetworkAdapterPassthrough -- direct adapter assignment to an
//     app (stub scenario; needs broker QEMU flag tweak).
func TestApplicationConnectivitySuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	// Define parameters for the entire test suite.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestLocalNI,
		},
		evetest.TestCase{
			Test: TestSwitchNI,
		},
		evetest.TestCase{
			Test: TestFlowLog,
		},
		evetest.TestCase{
			Test: TestLocalNetInstanceACLs,
			Variants: []evetest.TestVariant{
				{
					Name: "TestLocalNetInstanceACLs",
					Parameters: []evetest.TestParameterValue{
						{Key: enableFlowlogParamKey, Value: false},
					},
				},
				{
					Name: "TestLocalNetInstanceACLsWithFlowLog",
					Parameters: []evetest.TestParameterValue{
						{Key: enableFlowlogParamKey, Value: true},
					},
				},
			},
		},
		evetest.TestCase{
			Test: TestSwitchNetInstanceACLs,
			Variants: []evetest.TestVariant{
				{
					Name: "TestSwitchNetInstanceACLs",
					Parameters: []evetest.TestParameterValue{
						{Key: enableFlowlogParamKey, Value: false},
					},
				},
				{
					Name: "TestSwitchNetInstanceACLsWithFlowLog",
					Parameters: []evetest.TestParameterValue{
						{Key: enableFlowlogParamKey, Value: true},
					},
				},
			},
		},
		evetest.TestCase{
			Test: TestApplicationIPv6Connectivity,
		},
		evetest.TestCase{
			Test: TestApplicationNTPConfig,
		},
		evetest.TestCase{
			Test: TestPropagatedRoutes,
		},
		evetest.TestCase{
			Test: TestLocalNIWithMultiplePorts,
		},
		evetest.TestCase{
			Test: TestApplicationGateway,
		},
		evetest.TestCase{
			Test: TestSwitchNIWithMultiplePorts,
		},
		evetest.TestCase{
			Test: TestAccessVLANs,
		},
		evetest.TestCase{
			Test: TestNetworkAdapterPassthrough,
		},
	)
}

// TestDatastoreSuite drives every datastore-pull scenario: EVE downloads
// an application content tree from a backend (HTTP, HTTPS, S3, SFTP,
// Azure, container registry), verifies the SHA, and brings the resulting
// app up. The suite does not parameterize the hypervisor -- datastore
// tests deploy a tiny "consumer" app but the test value is in the
// download/verification plumbing, not in the app runtime, so the
// hypervisor is hardcoded to KVM per the same rule applied to Device-suite
// tests.
//
// Subtests
// --------
//   - TestHTTPDatastore / TestHTTPSDatastore / TestSFTPDatastore --
//     can be self-contained inside SDN once SDN exposes a binary-content
//     file-server endpoint type (stub scenarios pending that framework
//     enhancement).
//   - TestAWSDatastore / TestAzureDatastore -- opt-in via parameters
//     (real cloud datastores).
//   - TestContainerRegistry -- pulls from Docker Hub (or the configured
//     pull-through mirror).
func TestDatastoreSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestHTTPDatastore,
		},
		evetest.TestCase{
			Test: TestHTTPSDatastore,
		},
		evetest.TestCase{
			Test: TestAWSDatastore,
		},
		evetest.TestCase{
			Test: TestSFTPDatastore,
		},
		evetest.TestCase{
			Test: TestAzureDatastore,
		},
		evetest.TestCase{
			Test: TestContainerRegistry,
		},
	)
}

// TestPcibackErrorSuite drives every assignable-adapter / PhysicalIO
// error-reporting scenario: EVE detects an inconsistency in the model
// (phantom PCI address, self-parent assign-group, USB address collision,
// interface-name mismatch, cross-group PCI conflict, warning+error bundle)
// and reports it to the controller with the correct severity, then clears
// it once the model is fixed. The suite does not parameterize the
// hypervisor -- no application is deployed, so the hypervisor is hardcoded
// to KVM like the other Device-suite tests.
//
// Every scenario but the last runs on the TwoMgmtPorts model and reuses
// the same device via ResetDeviceConfig. TestReportWarningsOnly needs the
// four-port ManyDNSServers model; a differing network model forces the
// framework to recreate and reonboard the device, so it runs last to incur
// that cost once rather than twice (switching away and back mid-suite).
//
// Subtests
// --------
//   - TestReportMissingDevice -- phantom device with a non-existent PCI
//     address (error).
//   - TestReportParentAssigngrp -- self-parent assignment group (error).
//   - TestReportCycleDetected -- parentassigngrp cycle (error).
//   - TestReportCollision -- USB address collision within a group
//     (single group-level error).
//   - TestReportIfnameMismatch -- model interface name disagrees with the
//     kernel (warning; kept in host and matched by PCI).
//   - TestReportAssignmentGroupConflict -- device shares an in-use port's
//     PCI in another group (error).
//   - TestReportWarningPlusError -- bundle carrying both a warning and a
//     hard error (reported as error).
//   - TestReportClearsOnFix -- inconsistency is reported and then clears
//     once the model is corrected.
//   - TestReportWarningsOnly -- warnings-only across multiple ports
//     (four-port model; runs last).
func TestPcibackErrorSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.RunTestSuite(
		evetest.TestCase{Test: TestReportMissingDevice},
		evetest.TestCase{Test: TestReportParentAssigngrp},
		evetest.TestCase{Test: TestReportCycleDetected},
		evetest.TestCase{Test: TestReportCollision},
		evetest.TestCase{Test: TestReportIfnameMismatch},
		evetest.TestCase{Test: TestReportAssignmentGroupConflict},
		evetest.TestCase{Test: TestReportWarningPlusError},
		evetest.TestCase{Test: TestReportClearsOnFix},
		evetest.TestCase{Test: TestReportWarningsOnly},
	)
}
