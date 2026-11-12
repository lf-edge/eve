// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package networking_test holds the EVE networking tests.
//
// helpers_test.go holds helpers shared across multiple tests in this
// package. New shared helpers belong there too, not alongside the test
// that first needed them.
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
//   - TestBootstrapWithNetworkBoot: install EVE over the network via iPXE.
//
// All bootstrap tests share the HYPERVISOR parameter (defaults to KVM).
func TestBootstrapSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

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
			Test: TestBootstrapWithNetworkBoot,
		},
	)
}

// TestDeviceConnectivitySuite drives every device-side networking
// scenario: how EVE itself manages its physical / L2 / IP adapters and
// keeps controller connectivity alive.
// All subtests share the HYPERVISOR parameter (defaults to KVM).
//
// Subtests
// --------
//   - TestDHCPIPv4Only / TestStaticIPv4Only -- IPv4-only port config on a
//     dual-stack SDN network.
//   - TestDNSFunctionality -- per-port DNS aggregation, resolv.conf
//     completeness, DHCP-override exclusivity (currently a stub
//     scenario).
//   - TestPortFailover / TestNetworkConfigFallback /
//     TestIntermittentConnectivity -- fail-over / fallback resilience
//     (currently stub scenarios).
//   - TestMgmtTrafficRoutedViaApp -- EVE's own device-management traffic
//     routed through an app-based NAT gateway, surviving a full reboot.
//   - TestVLANSubinterfaces -- VLAN sub-interfaces (stub scenarios).
//   - TestCellularConnectivity / TestWifiConnectivity -- wireless;
//     intentionally unimplemented (require PCI/USB passthrough).
func TestDeviceConnectivitySuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
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
			Test: TestMgmtTrafficRoutedViaApp,
		},
		evetest.TestCase{
			Test: TestVLANSubinterfaces,
		},
		evetest.TestCase{
			Test: TestCellularConnectivity,
		},
		evetest.TestCase{
			Test: TestWifiConnectivity,
		},
	)
}

// TestLocalNetworkInstanceSuite drives the application-side behavior of
// Local (L3/NAT) Network Instances: the NI life-cycle, DHCP/DNS
// service to apps, IP allocation limits, rapid NI replacement, moving an app
// between NIs, per-VIF ACLs, port-forwarding (D-NAT), flow logging and the
// NI's resilience to uplink flaps. All subtests deploy at least one application and
// therefore share the HYPERVISOR parameter -- the suite declares
// evetest.HypervisorParameter() once and every subtest reads it via
// evetest.GetHypervisorParameterValue() (defaults to KVM).
//
// Part of the application-side networking scenarios, together with
// TestSwitchNetworkInstanceSuite, TestAppRoutingSuite and TestAppNICsSuite,
// which were split from one suite to keep each job short.
func TestLocalNetworkInstanceSuite(test *testing.T) {
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
			Test: TestNIReplace,
		},
		evetest.TestCase{
			Test: TestMoveAppBetweenNIs,
		},
		evetest.TestCase{
			Test: TestLimitedIPSpace,
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
			Test: TestPortForwarding,
		},
		evetest.TestCase{
			Test: TestLocalNIUplinkFlap,
		},
	)
}

// TestSwitchNetworkInstanceSuite drives the application-side behavior of
// Switch (L2-only) Network Instances: the NI life-cycle, IP learning by packet
// snooping (including air-gapped NIs), per-VIF ACLs,
// STP/BPDU guard on redundant links, and VLAN isolation. All subtests deploy at least one application and
// therefore share the HYPERVISOR parameter -- the suite declares
// evetest.HypervisorParameter() once and every subtest reads it via
// evetest.GetHypervisorParameterValue() (defaults to KVM).
func TestSwitchNetworkInstanceSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	// Define parameters for the entire test suite.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestSwitchNI,
		},
		evetest.TestCase{
			Test: TestAirGapSwitchNI,
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
			Test: TestSwitchNIWithMultiplePorts,
		},
		evetest.TestCase{
			Test: TestAccessVLANs,
		},
	)
}

// TestAppRoutingSuite drives application IP routing: connected and static
// routes delivered to apps over DHCP, multi-path routes across several uplink
// ports of one Local NI, and the "application gateway" topology in which one
// app routes, NATs and filters traffic for others. All subtests deploy at least one application and
// therefore share the HYPERVISOR parameter -- the suite declares
// evetest.HypervisorParameter() once and every subtest reads it via
// evetest.GetHypervisorParameterValue() (defaults to KVM).
func TestAppRoutingSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	// Define parameters for the entire test suite.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestPropagatedRoutes,
		},
		evetest.TestCase{
			Test: TestLocalNIWithMultiplePorts,
		},
		evetest.TestCase{
			Test: TestApplicationGateway,
		},
	)
}

// TestAppNICsSuite drives the network adapters (VIFs and directly assigned
// physical NICs) of an application: PCI passthrough of a physical NIC.
// All subtests deploy at least one application and
// therefore share the HYPERVISOR parameter -- the suite declares
// evetest.HypervisorParameter() once and every subtest reads it via
// evetest.GetHypervisorParameterValue() (defaults to KVM).
func TestAppNICsSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	// Define parameters for the entire test suite.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestNetworkAdapterPassthrough,
		},
	)
}

// TestDatastoreSuite drives every datastore-pull scenario: EVE downloads
// an application content tree from a backend (HTTP, HTTPS, S3, SFTP,
// Azure, container registry), verifies the SHA, and brings the resulting
// app up. Datastore tests deploy a tiny "consumer" app but the test value
// is in the download/verification plumbing, not in the app runtime; the
// suite still shares the HYPERVISOR parameter (defaults to KVM).
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
//   - TestNoRedownloadOnURLTokenChange -- a content tree whose URL carries
//     an access token as a GET parameter must not be downloaded again when
//     only that token is replaced and the SHA256 stays the same; the
//     datastore is evetest's image server, which records every request it
//     receives.
//   - TestLocalDatastore -- a datastore found through mDNS on the bridge of
//     a network instance (host name ending with ".local"), served by an
//     app running on the device itself.
func TestDatastoreSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

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
		evetest.TestCase{
			Test: TestNoRedownloadOnURLTokenChange,
		},
		evetest.TestCase{
			Test: TestLocalDatastore,
		},
	)
}

// TestPcibackErrorSuite drives every assignable-adapter / PhysicalIO
// error-reporting scenario: EVE detects an inconsistency in the model
// (phantom PCI address, self-parent assign-group, USB address collision,
// interface-name mismatch, cross-group PCI conflict, warning+error bundle)
// and reports it to the controller with the correct severity, then clears
// it once the model is fixed. No application is deployed, but the suite
// still shares the HYPERVISOR parameter (defaults to KVM).
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

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

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
