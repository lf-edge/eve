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
	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
)

func deviceRequirementsForNetAdapterTests(
	devName string, hypervisor evetest.Hypervisor) evetest.RequireEdgeDevice {
	return evetest.RequireEdgeDevice{
		Name:           devName,
		WithHypervisor: hypervisor,
		MinCPUs:        4,
		WithGrubOptions: []string{
			// No applications are deployed in these network adapter tests.
			// Prioritize maximizing EVE performance and reducing device onboarding time.
			"set_global hv_dom0_cpu_settings \"dom0_max_vcpus=4\"",
			"set_global hv_eve_cpu_settings \"eve_max_vcpus=3\"",
			"set_global hv_ctrd_cpu_settings \"ctrd_max_vcpus=3\""},
		DeviceReusePolicy: evetest.ResetDeviceConfig,
	}
}

// TestDHCPIPv4Only verifies that when a port is configured with DHCP-enabled
// and IPv4-only, EVE acquires an IPv4 address via DHCP and explicitly
// does NOT pick up an IPv6 address, even though the SDN network advertises
// IPv6 (DHCPv6 + SLAAC) alongside IPv4.
//
// Network model
// -------------
//   - Dual-stack network that would happily hand out both v4 and v6 if EVE
//     asked for both.
//
// Device configuration
// --------------------
//   - network with DHCP-enabled and NetworkType=V4Only, applied on eth0
//     (mgmt+app usage).
//
// Phases
// ------
//   - Eventually: eth0 acquires IPv4 address AND no IPv6 address.
//   - Consistently for one minute: no IPv6 ever appears on the port.
func TestDHCPIPv4Only(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	// Set up the test harness and specify the test prerequisites.
	devName := "edge-dev"
	requiredDevice := deviceRequirementsForNetAdapterTests(devName, hypervisor)
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCPAndIPv6,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build and apply the initial device configuration.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("config-applied")

	log := evetest.Logger()

	log.Infof("Waiting for device to report IPv4 (only) address...")
	t.Eventually(func() bool {
		ips := device.GetDeviceIPAddress("ethernet0")
		return containsIPv4(ips) && !containsIPv6(ips)
	}, 3*time.Minute, 10*time.Second).Should(BeTrue())

	t.Consistently(func() bool {
		log.Infof("Checking that eth0 remains without any IPv6 address assigned...")
		ips := device.GetDeviceIPAddress("ethernet0")
		return containsIPv6(ips)
	}, time.Minute, 10*time.Second).Should(BeFalse())
}

// TestStaticIPv4Only verifies that when a port is configured with a
// static network config for IPv4-only, EVE applies the exact static IPv4
// address and does NOT pick up an IPv6 address from a v6-capable SDN
// network.
//
// Network model
// -------------
//   - Dual-stack network without DHCP; the v4 subnet matches the static IP
//     we will assign so the link works, while v6 stays available for the negative
//     assertion.
//
// Device configuration
// --------------------
//   - network with static IPv4 configuration matching the network model
//   - SystemAdapter on eth0 (mgmt+app) with the static IP 172.20.20.100.
//
// Phases
// ------
//   - Eventually: eth0 is configured with 172.20.20.100 AND no IPv6 address.
//   - Consistently for one minute: no IPv6 ever appears on the port.
func TestStaticIPv4Only(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	// Set up the test harness and specify the test prerequisites.
	devName := "edge-dev"
	requiredDevice := deviceRequirementsForNetAdapterTests(devName, hypervisor)
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCPAndIPv6,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build and apply the initial device configuration.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	staticNet := devConfig.AddNetwork(
		evetest.StaticNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
			Subnet:      evetest.IPSubnet("172.20.20.0/24"),
			Gateway:     evetest.IPAddress("172.20.20.1"),
			DNSServers:  []net.IP{evetest.IPAddress("10.16.16.25")},
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   staticNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			StaticIP:      evetest.IPAddress("172.20.20.100"),
		})
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("config-applied")

	log := evetest.Logger()

	log.Infof("Waiting for device to report the static IPv4 (only) address...")
	t.Eventually(func() bool {
		ips := device.GetDeviceIPAddress("ethernet0")
		containsStaticIP := generics.ContainsItemFn(
			ips, evetest.IPAddress("172.20.20.100"), netutils.EqualIPs)
		return containsStaticIP && !containsIPv6(ips)
	}, 3*time.Minute, 10*time.Second).Should(BeTrue())

	t.Consistently(func() bool {
		log.Infof("Checking that eth0 remains without any IPv6 address assigned...")
		ips := device.GetDeviceIPAddress("ethernet0")
		return containsIPv6(ips)
	}, time.Minute, 10*time.Second).Should(BeFalse())
}

const requireSCEPProxyParamKey = "REQUIRE_SCEP_PROXY"
const pnacReauthCycleCountParamKey = "PNAC_REAUTH_CYCLE_COUNT"

var (
	pnacReauthCycleCountParam = evetest.TestParameterDefinition{
		Key:          pnacReauthCycleCountParamKey,
		DefaultValue: 3,
		Description: evetest.TestParameterDescription{
			Summary: "Number of re-authentication cycles (trusted CA changes) " +
				"to exercise; increase to look for resource growth",
			Default: "3",
		},
	}
	requireSCEPProxyParam = evetest.TestParameterDefinition{
		Key:          requireSCEPProxyParamKey,
		DefaultValue: false,
		Description: evetest.TestParameterDescription{
			Summary: "Require controller-provided SCEP proxy " +
				"(unauthenticated ports are not granted direct access to the SCEP server)",
			Default: "false",
		},
	}
)

// TestPNAC verifies the IEEE 802.1X Port-Based Network Access Control flow:
// EVE enrolls an X.509 certificate via SCEP, authenticates with the
// upstream switch using EAP-TLS, transitions from the bootstrap VLAN to
// the authenticated VLAN, reacquires DHCP on the new VLAN, and reports
// PNAC status + metrics. See DEVICE-CONNECTIVITY.md
// "Port-Based Network Access Control (802.1X) and SCEP Certificate
// Enrollment" for the workflow.
//
// Two variants are exercised via the REQUIRE_SCEP_PROXY parameter:
//   - false: the device contacts the SCEP server directly from the
//     bootstrap VLAN (the SDN firewall is permissive enough to allow it).
//   - true:  the bootstrap-VLAN firewall blocks direct access to the SCEP
//     server, so EVE must route SCEP requests through the controller-
//     provided SCEP proxy. The device config sets
//     SCEPProfile.UseControllerProxy=true accordingly.
//
// Network model
// -------------
//   - netmodels.SingleEthWithPNAC(requireSCEPProxy) -- builds an
//     SDN topology with a single Ethernet port on a PNAC-enabled bridge:
//   - Pre-auth VLAN 10 (172.20.10.0/24): only the controller, the SDN DNS
//     server, EVE-test SSH access, and (when REQUIRE_SCEP_PROXY=false)
//     the SCEP server are reachable. Default-deny otherwise.
//   - Post-auth VLAN 20 (172.20.20.0/24): full reachability (incl.
//     http-server.test for the post-auth smoke probe).
//   - The bridge runs hostapd with a CA cert + EAP user "evetest" using
//     EAP-TLS, and a separate SCEP CA issues client certs.
//
// Device configuration
// --------------------
//   - SystemAdapter on eth0 (DHCP, mgmt+app) with PNAC enabled, using EAP-TLS
//   - SCEP profile with server URL = http://<server>:8080/scep (server hostname resolved
//     via SDN DNS in the non-proxy variant; in the proxy variant the URL
//     uses the SCEP server's raw IP because Adam does not consult SDN's
//     DNS).
//
// Phases
// ------
//  1. Certificate enrolled: watch device info until ZInfoDevice.EnrolledCerts has
//     exactly one CertInfo entry with Status=AVAILABLE.
//  2. Port authenticated: DevicePort.PnacStatus on eth0 reaches
//     SUPPLICANT_STATE_AUTHENTICATED with non-empty LastAuthTimestamp
//     (strictly after the config-apply time) and Enabled=true, Err=nil.
//  3. IP updated: DevicePort gets an IPv4 address from the post-auth
//     VLAN (172.20.20.0/24), confirming EVE reacquired DHCP after the
//     supplicant moved to the authenticated VLAN.
//  4. PNAC metrics (DeviceMetric.PnacMetrics) report non-zero EAPOL
//     frame counters and zero error counters.
//  5. Smoke test: curl http://http-server.test/helloworld from EVE over
//     SSH succeeds -- the authenticated VLAN allows it.
//  6. SCEP profile swap while device is NOT ONLINE: create a new SCEP profile
//     while the device is rebooting. We previously had a bug where the device
//     failed to remove the old, now-obsolete profile in this scenario.
//  7. Stress cycles (PNAC_REAUTH_CYCLE_COUNT, 3 by default) that repeatedly
//     re-authenticate the port, make the authenticator reject the device and
//     re-enroll certificates. Every cycle:
//     a. Re-initializes the port on the authenticator twice (the switch-side
//     "initialize"): after each one the reported LastAuthTimestamp must
//     advance (a missed supplicant event leaves it stale) and the port must
//     keep an IP from the authenticated VLAN.
//     b. Makes the authenticator trust only an unrelated CA and re-initializes
//     the port: the reported state must become FAILED with an error (not
//     stay AUTHENTICATED) and the port must move to a pre-auth ("guest")
//     VLAN IP. Note that hostapd also signs its server certificate with the
//     CA, so here the supplicant rejects the server rather than the other
//     way round; the observable outcome is the same.
//     c. Restores the authenticator's CA and re-initializes: the port must
//     authenticate again without manual intervention and renew its IP in
//     the authenticated VLAN.
//     d. Disables PNAC and removes the SCEP profile (the certificate must be
//     removed and the port must fall back to a pre-auth VLAN IP), then
//     re-adds both with a different key type and checks enrollment,
//     authentication and the IP again.
//     After every cycle the EVE memory usage reported in device metrics is
//     logged. An unexpected reboot (e.g. after an agent was killed for running
//     out of memory) fails the test.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//   - REQUIRE_SCEP_PROXY (defaults to false).
//   - PNAC_REAUTH_CYCLE_COUNT (defaults to 3): number of cycles of phase 7,
//     set via EVETEST_PNAC_REAUTH_CYCLE_COUNT. Raise it (e.g. to 20) to look
//     for memory growth; 0 skips phase 7.
func TestPNAC(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		requireSCEPProxyParam,
		pnacReauthCycleCountParam,
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()
	requireSCEPProxy := evetest.GetTestParameter[bool](requireSCEPProxyParamKey)
	reauthCycles := evetest.GetTestParameter[int](pnacReauthCycleCountParamKey)
	t.Expect(reauthCycles).To(BeNumerically(">=", 0),
		"EVETEST_PNAC_REAUTH_CYCLE_COUNT must not be negative")

	// Set up the test harness and specify the test prerequisites.
	devName := "edge-dev"
	requiredDevice := deviceRequirementsForNetAdapterTests(devName, hypervisor)
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithPNAC(requireSCEPProxy),
	}
	// 802.1X port authentication exchanges EAPOL frames across the simulated
	// link between EVE and the SDN; skip on providers that cannot forward them.
	requiredCaps := evetest.RequireCapabilities{
		Capabilities: []api.Capability{api.Capability_CAPABILITY_FORWARD_EAPOL},
	}
	evetest.Setup(requiredDevice, requiredNetModel, requiredCaps)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build and apply the initial device configuration.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.SCEPRetryInterval, 10)
	devConfig.SetConfigProperties(cfgProps)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	adapterConfig := evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		PNAC: evetest.PNAC{
			Enable:                    true,
			EAPIdentity:               "evetest",
			EAPMethod:                 eveconfig.EAPMethod_EAP_METHOD_TLS,
			CertEnrollmentProfileName: "scep-test",
		},
	}
	devConfig.AddNetworkAdapter(adapterConfig)
	scepServerHostname := "scep-server.test"
	if requireSCEPProxy {
		// Adam does not use DNS servers running inside SDN and therefore
		// cannot resolve hostnames defined only within the network model.
		// When the controller proxy is required, reference the SCEP server
		// directly by its IP address.
		scepServerHostname = "10.17.17.25"
	}
	devConfig.AddSCEPProfile(
		evetest.SCEPProfile{
			Name:               "scep-test",
			SCEPServerURL:      fmt.Sprintf("http://%s:8080/scep", scepServerHostname),
			UseControllerProxy: requireSCEPProxy,
			ChallengePassword:  "123456789",
			CACertsPEM:         []string{netmodels.PnacRootCACertPEM},
			CSR: evetest.CSRProfile{
				CommonName:         devName,
				Organization:       "lf-edge",
				Country:            "US",
				SanURIs:            []string{fmt.Sprintf("URN:Name:%s", devName)},
				RenewPeriodPercent: 50,
				KeyType:            eveconfig.KeyType_KEY_TYPE_RSA_2048,
				HashAlgorithm:      eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA256,
			},
		})

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	devMetrics, stopDevMetricsWatch := device.WatchDeviceMetrics()
	defer stopDevMetricsWatch()
	configAppliedAt := time.Now()
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("config-applied")

	timeout := 3 * time.Minute
	var cert *eveinfo.CertInfo
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Device has enrolled certificate for 802.1x",
		func(info *eveinfo.ZInfoDevice) bool {
			if len(info.GetEnrolledCerts()) != 1 {
				return false
			}
			cert = info.GetEnrolledCerts()[0]
			return cert.GetStatus() == eveinfo.CertStatus_CERT_STATUS_AVAILABLE
		})))

	evetest.Checkpoint("cert-enrolled")

	// Verify certificate content.
	t.Expect(cert.GetCertEnrollmentProfileName()).To(Equal("scep-test"))
	t.Expect(cert.GetStatus()).To(Equal(eveinfo.CertStatus_CERT_STATUS_AVAILABLE))
	t.Expect(cert.GetErr()).To(BeNil())
	t.Expect(cert.GetRenewPeriodPercent()).To(Equal(uint32(50)))
	t.Expect(cert.GetSha256Fingerprint()).ToNot(BeEmpty())
	// Subject: CN=edge-dev, O=lf-edge, C=US
	subject := cert.GetSubject()
	t.Expect(subject.GetCommonName()).To(Equal(devName))
	t.Expect(subject.GetOrganization()).To(Equal([]string{"lf-edge"}))
	t.Expect(subject.GetCountry()).To(Equal([]string{"US"}))
	// Issuer: CN=SCEP CA, O=Example, OU=Lab, C=US
	issuer := cert.GetIssuer()
	t.Expect(issuer.GetCommonName()).To(Equal("SCEP CA"))
	t.Expect(issuer.GetOrganization()).To(Equal([]string{"Example"}))
	t.Expect(issuer.GetOrganizationalUnit()).To(Equal([]string{"Lab"}))
	t.Expect(issuer.GetCountry()).To(Equal([]string{"US"}))
	// SAN URI
	t.Expect(cert.GetSanUri()).To(Equal([]string{fmt.Sprintf("urn:Name:%s", devName)}))
	// Note: SCEP server issues certificate valid from 10 minutes ago.
	issueTime := cert.GetIssueTimestamp().AsTime()
	expirationTime := cert.GetExpirationTimestamp().AsTime()
	t.Expect(issueTime.After(configAppliedAt.Add(-11 * time.Minute))).To(BeTrue())
	t.Expect(issueTime.Before(time.Now())).To(BeTrue())
	t.Expect(expirationTime.After(time.Now())).To(BeTrue())

	dinfo := device.GetDeviceInfo()
	pnacStatus := getPNACStatus("ethernet0", dinfo)
	if pnacStatus.GetState() != eveinfo.SupplicantState_SUPPLICANT_STATE_AUTHENTICATED {
		t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
			"Device has authenticated port ethernet0",
			func(info *eveinfo.ZInfoDevice) bool {
				dinfo = info
				pnacStatus = getPNACStatus("ethernet0", dinfo)
				pnacState := pnacStatus.GetState()
				return pnacState == eveinfo.SupplicantState_SUPPLICANT_STATE_AUTHENTICATED
			})))
	}

	evetest.Checkpoint("port-authenticated")

	t.Expect(pnacStatus.Enabled).To(BeTrue())
	t.Expect(pnacStatus.Err).To(BeNil())
	lastAuthAt := pnacStatus.LastAuthTimestamp.AsTime()
	t.Expect(lastAuthAt.After(configAppliedAt)).To(BeTrue())
	t.Expect(lastAuthAt.Before(time.Now())).To(BeTrue())

	authVLANSubnet := evetest.IPSubnet("172.20.20.0/24")
	portIP := getPortIPv4Addr("ethernet0", dinfo)
	if portIP == nil || !authVLANSubnet.Contains(portIP) {
		t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
			"Device has acquired IP for ethernet0 from the authenticated VLAN",
			func(info *eveinfo.ZInfoDevice) bool {
				dinfo = info
				portIP := getPortIPv4Addr("ethernet0", dinfo)
				return portIP != nil && authVLANSubnet.Contains(portIP)
			})))
	}

	evetest.Checkpoint("ip-updated")

	var eth0PNACMetrics *evemetrics.PNACMetrics
	t.Eventually(devMetrics, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Device has reported non-zero PNAC metrics",
		func(metrics *evemetrics.DeviceMetric) bool {
			pnacMetrics := metrics.GetPnacMetrics()
			if len(pnacMetrics) != 1 || pnacMetrics[0].Logicallabel != "ethernet0" {
				return false
			}
			eth0PNACMetrics = pnacMetrics[0]
			return eth0PNACMetrics.EapolFramesRx > 0 &&
				eth0PNACMetrics.EapolFramesTx > 0 &&
				eth0PNACMetrics.EapolReqFramesRx > 0 &&
				eth0PNACMetrics.EapolRespFramesTx > 0
		})))
	t.Expect(eth0PNACMetrics.EapLengthErrorFramesRx).To(BeZero())
	t.Expect(eth0PNACMetrics.InvalidEapolFramesRx).To(BeZero())

	httpServerURL := "http://http-server.test/helloworld"
	command := fmt.Sprintf("curl -sS %s", httpServerURL)
	_, stderr, err := device.RunShellScript(command, 0, 5*time.Second)
	if err != nil {
		err = fmt.Errorf("curl %s failed: %s", httpServerURL, stderr)
	}
	t.Expect(err).ToNot(HaveOccurred())

	// Swap SCEP profile while device is not online.
	// The goal is to check that EVE will (eventually) properly resync persisted config
	// against the received config after boot.
	device.RequestReboot(false, false)
	devConfig.DeleteSCEPProfile("scep-test")
	newSCEPProfile := func(caCertsPEM ...string) evetest.SCEPProfile {
		return evetest.SCEPProfile{
			Name:               "new-scep-profile",
			SCEPServerURL:      fmt.Sprintf("http://%s:8080/scep", scepServerHostname),
			UseControllerProxy: requireSCEPProxy,
			ChallengePassword:  "123456789",
			CACertsPEM:         caCertsPEM,
			CSR: evetest.CSRProfile{
				CommonName:         devName,
				Organization:       "different-org",
				Country:            "SK",
				SanURIs:            []string{fmt.Sprintf("URN:Name:%s", devName)},
				RenewPeriodPercent: 30,
				KeyType:            eveconfig.KeyType_KEY_TYPE_RSA_2048,
				HashAlgorithm:      eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA256,
			},
		}
	}
	devConfig.AddSCEPProfile(newSCEPProfile(netmodels.PnacRootCACertPEM))
	devConfig.Pnacs[0].CertEnrollmentProfileName = "new-scep-profile"
	adapterConfig.PNAC.CertEnrollmentProfileName = "new-scep-profile"
	configAppliedAt = time.Now()
	device.ApplyConfig(devConfig, false, false)

	evetest.Checkpoint("scep-profile-replaced")

	timeout = 10 * time.Minute // give device some extra time to reboot and resync
	t.Eventually(devUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Device has enrolled NEW certificate for 802.1x "+
			"AND deleted the obsolete certificate",
		func(info *eveinfo.ZInfoDevice) bool {
			if len(info.GetEnrolledCerts()) != 1 {
				return false
			}
			cert = info.GetEnrolledCerts()[0]
			return cert.CertEnrollmentProfileName == "new-scep-profile" &&
				cert.GetStatus() == eveinfo.CertStatus_CERT_STATUS_AVAILABLE
		})))

	evetest.Checkpoint("new-cert-enrolled")

	// Verify certificate content.
	t.Expect(cert.GetCertEnrollmentProfileName()).To(Equal("new-scep-profile"))
	t.Expect(cert.GetStatus()).To(Equal(eveinfo.CertStatus_CERT_STATUS_AVAILABLE))
	t.Expect(cert.GetErr()).To(BeNil())
	t.Expect(cert.GetRenewPeriodPercent()).To(Equal(uint32(30)))
	t.Expect(cert.GetSha256Fingerprint()).ToNot(BeEmpty())
	// Subject: CN=edge-dev, O=different-org, C=SK
	subject = cert.GetSubject()
	t.Expect(subject.GetCommonName()).To(Equal(devName))
	t.Expect(subject.GetOrganization()).To(Equal([]string{"different-org"}))
	t.Expect(subject.GetCountry()).To(Equal([]string{"SK"}))
	// Issuer: CN=SCEP CA, O=Example, OU=Lab, C=US
	issuer = cert.GetIssuer()
	t.Expect(issuer.GetCommonName()).To(Equal("SCEP CA"))
	t.Expect(issuer.GetOrganization()).To(Equal([]string{"Example"}))
	t.Expect(issuer.GetOrganizationalUnit()).To(Equal([]string{"Lab"}))
	t.Expect(issuer.GetCountry()).To(Equal([]string{"US"}))
	// SAN URI
	t.Expect(cert.GetSanUri()).To(Equal([]string{fmt.Sprintf("urn:Name:%s", devName)}))
	// Note: SCEP server issues certificate valid from 10 minutes ago.
	issueTime = cert.GetIssueTimestamp().AsTime()
	expirationTime = cert.GetExpirationTimestamp().AsTime()
	t.Expect(issueTime.After(configAppliedAt.Add(-11 * time.Minute))).To(BeTrue())
	t.Expect(issueTime.Before(time.Now())).To(BeTrue())
	t.Expect(expirationTime.After(time.Now())).To(BeTrue())

	// dinfo predates the reboot: authenticate against the latest info and only
	// accept an authentication performed after the new config was applied.
	dinfo = device.GetDeviceInfo()
	pnacStatus = getPNACStatus("ethernet0", dinfo)
	authVLANSubnet = evetest.IPSubnet("172.20.20.0/24")
	portIP = getPortIPv4Addr("ethernet0", dinfo)
	if pnacStatus.GetState() != eveinfo.SupplicantState_SUPPLICANT_STATE_AUTHENTICATED ||
		!pnacStatus.GetLastAuthTimestamp().AsTime().After(configAppliedAt) ||
		portIP == nil || !authVLANSubnet.Contains(portIP) {
		pnacStatus = waitForPNACAuthenticated(t, devUpdates, "ethernet0",
			configAppliedAt, authVLANSubnet, timeout,
			"Device has authenticated port ethernet0 with new cert")
	}

	evetest.Checkpoint("port-authenticated-with-new-cert")

	// Stress cycles: switch-port re-initialization, RADIUS rejection and
	// recovery, PNAC disable + re-enrollment.
	preAuthVLANSubnet := evetest.IPSubnet("172.20.10.0/24")
	reauthTimeout := 5 * time.Minute
	var reauthGeneration uint32
	// authenticatorModel returns the network model with the authenticator
	// trusting the given CA; every call also re-initializes the port.
	authenticatorModel := func(caCertPEM, caKeyPEM string) *api.NetworkModel {
		reauthGeneration++
		model := netmodels.SingleEthWithPNAC(requireSCEPProxy)
		pnac := model.Bridges[0].Pnac
		pnac.CaCertPem = caCertPEM
		pnac.CaKeyPem = caKeyPEM
		pnac.ReauthGeneration = reauthGeneration
		return model
	}
	defer func() {
		if reauthCycles > 0 {
			evetest.UpdateNetworkModel(netmodels.SingleEthWithPNAC(requireSCEPProxy))
		}
	}()
	keyTypes := []eveconfig.KeyType{
		eveconfig.KeyType_KEY_TYPE_RSA_2048,
		eveconfig.KeyType_KEY_TYPE_RSA_3072,
		eveconfig.KeyType_KEY_TYPE_RSA_4096,
	}
	scepProfileName := "new-scep-profile"
	for i := 1; i <= reauthCycles; i++ {
		evetest.Logger().Infof("PNAC stress cycle %d/%d", i, reauthCycles)
		lastAuth := pnacStatus.GetLastAuthTimestamp().AsTime()

		// a. Authenticator re-initializes the port; EVE must notice every
		// successful re-authentication.
		for j := 1; j <= 2; j++ {
			evetest.UpdateNetworkModel(authenticatorModel(
				netmodels.PnacRootCACertPEM, netmodels.PnacRootCAKeyPEM))
			pnacStatus = waitForPNACAuthenticated(t, devUpdates, "ethernet0",
				lastAuth, authVLANSubnet, reauthTimeout,
				fmt.Sprintf("cycle %d: LastAuthTimestamp advanced after port re-init #%d",
					i, j))
			lastAuth = pnacStatus.GetLastAuthTimestamp().AsTime()
		}
		evetest.Checkpoint(fmt.Sprintf("cycle-%d-reinit", i))

		// b. Authenticator rejects the device.
		otherCACert, otherCAKey, err := generateUnrelatedCA(
			fmt.Sprintf("unrelated-ca-%d", i))
		t.Expect(err).ToNot(HaveOccurred())
		evetest.UpdateNetworkModel(authenticatorModel(otherCACert, otherCAKey))
		t.Eventually(devUpdates, reauthTimeout).Should(Receive(matchers.SatisfyPredicate(
			fmt.Sprintf("cycle %d: authentication failure is reported and "+
				"the port moved to the pre-auth VLAN", i),
			func(info *eveinfo.ZInfoDevice) bool {
				status := getPNACStatus("ethernet0", info)
				ip := getPortIPv4Addr("ethernet0", info)
				return status.GetState() == eveinfo.SupplicantState_SUPPLICANT_STATE_FAILED &&
					status.GetErr() != nil &&
					ip != nil && preAuthVLANSubnet.Contains(ip)
			})))
		evetest.Checkpoint(fmt.Sprintf("cycle-%d-rejected", i))

		// c. Authenticator trusts the device again; no manual action.
		evetest.UpdateNetworkModel(authenticatorModel(
			netmodels.PnacRootCACertPEM, netmodels.PnacRootCAKeyPEM))
		pnacStatus = waitForPNACAuthenticated(t, devUpdates, "ethernet0",
			lastAuth, authVLANSubnet, reauthTimeout,
			fmt.Sprintf("cycle %d: port recovered after the authenticator "+
				"trusts the device again", i))
		_, stderr, err = device.RunShellScript(command, 0, 30*time.Second)
		t.Expect(err).ToNot(HaveOccurred(), "curl failed: %s", stderr)
		evetest.Checkpoint(fmt.Sprintf("cycle-%d-recovered", i))

		// d. Disable PNAC, drop the profile, enroll a different certificate.
		adapterConfig.PNAC.Enable = false
		devConfig.UpdateNetworkAdapter(adapterConfig)
		devConfig.DeleteSCEPProfile(scepProfileName)
		device.ApplyConfig(devConfig, false, false)
		t.Eventually(devUpdates, reauthTimeout).Should(Receive(matchers.SatisfyPredicate(
			fmt.Sprintf("cycle %d: enrolled certificate removed, PNAC disabled "+
				"and the port moved to the pre-auth VLAN", i),
			func(info *eveinfo.ZInfoDevice) bool {
				ip := getPortIPv4Addr("ethernet0", info)
				return len(info.GetEnrolledCerts()) == 0 &&
					!getPNACStatus("ethernet0", info).GetEnabled() &&
					ip != nil && preAuthVLANSubnet.Contains(ip)
			})))
		evetest.Checkpoint(fmt.Sprintf("cycle-%d-pnac-disabled", i))

		profile := newSCEPProfile(netmodels.PnacRootCACertPEM)
		profile.Name = fmt.Sprintf("scep-cycle-%d", i)
		scepProfileName = profile.Name
		profile.CSR.KeyType = keyTypes[i%len(keyTypes)]
		devConfig.AddSCEPProfile(profile)
		adapterConfig.PNAC.Enable = true
		adapterConfig.PNAC.CertEnrollmentProfileName = profile.Name
		devConfig.UpdateNetworkAdapter(adapterConfig)
		enrollAfter := time.Now()
		device.ApplyConfig(devConfig, false, false)
		t.Eventually(devUpdates, reauthTimeout).Should(Receive(matchers.SatisfyPredicate(
			fmt.Sprintf("cycle %d: certificate enrolled with profile %s", i, profile.Name),
			func(info *eveinfo.ZInfoDevice) bool {
				certs := info.GetEnrolledCerts()
				return len(certs) == 1 &&
					certs[0].GetCertEnrollmentProfileName() == profile.Name &&
					certs[0].GetStatus() == eveinfo.CertStatus_CERT_STATUS_AVAILABLE
			})))
		pnacStatus = waitForPNACAuthenticated(t, devUpdates, "ethernet0",
			enrollAfter, authVLANSubnet, reauthTimeout,
			fmt.Sprintf("cycle %d: port authenticated with the new certificate", i))
		evetest.Checkpoint(fmt.Sprintf("cycle-%d-reenrolled", i))

		// Memory usage is only logged: it includes reclaimable page cache. If
		// repeated cycles exhausted EVE memory, the device would reboot, which
		// evetest reports as an unexpected reboot.
		if memory := device.GetDeviceMetrics().GetDeviceMemory(); memory != nil {
			evetest.Logger().Infof("PNAC stress cycle %d/%d done: EVE memory "+
				"used %d MB of %d MB", i, reauthCycles,
				memory.GetUsedEveMB(), memory.GetAllocatedEveMB())
		}
	}
}

// waitForPNACAuthenticated waits until the port with the given logical label
// reports an authentication performed strictly after notBefore, in the
// AUTHENTICATED state without an error, and holds an IPv4 address from the given
// subnet. It returns the status that satisfied the conditions.
func waitForPNACAuthenticated(t Gomega, updates <-chan *eveinfo.ZInfoDevice,
	portLL string, notBefore time.Time, subnet *net.IPNet,
	timeout time.Duration, description string) *eveinfo.PNACStatus {
	var result *eveinfo.PNACStatus
	t.Eventually(updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		description,
		func(info *eveinfo.ZInfoDevice) bool {
			status := getPNACStatus(portLL, info)
			if status == nil || !status.GetEnabled() || status.GetErr() != nil ||
				status.GetState() != eveinfo.SupplicantState_SUPPLICANT_STATE_AUTHENTICATED ||
				!status.GetLastAuthTimestamp().AsTime().After(notBefore) {
				return false
			}
			ip := getPortIPv4Addr(portLL, info)
			if ip == nil || !subnet.Contains(ip) {
				return false
			}
			result = status
			return true
		})))
	return result
}

// getPNACStatus returns the PNAC (802.1X) status for the port with the given
// logical label from the currently active DevicePortStatus entry, or nil if
// the port is not found.
func getPNACStatus(portLL string, dinfo *eveinfo.ZInfoDevice) *eveinfo.PNACStatus {
	port := getDevicePort(portLL, dinfo)
	if port == nil {
		return nil
	}
	return port.GetPnacStatus()
}

// getPortIPv4Addr returns the first IPv4 address assigned to the port with
// the given logical label from the currently active DevicePortStatus entry,
// or nil if the port is not found or has no IPv4 address.
func getPortIPv4Addr(portLL string, dinfo *eveinfo.ZInfoDevice) net.IP {
	port := getDevicePort(portLL, dinfo)
	if port == nil {
		return nil
	}
	for _, ipStr := range port.GetIPAddrs() {
		ip := net.ParseIP(ipStr)
		if ip != nil && ip.To4() != nil {
			return ip
		}
	}
	return nil
}

// getPortIPv6GlobalAddr returns the first global-unicast IPv6 address assigned
// to the port with the given logical label from the currently active
// DevicePortStatus entry, or nil if the port is not found or has no such address.
func getPortIPv6GlobalAddr(portLL string, dinfo *eveinfo.ZInfoDevice) net.IP {
	port := getDevicePort(portLL, dinfo)
	if port == nil {
		return nil
	}
	for _, ipStr := range port.GetIPAddrs() {
		ip := net.ParseIP(ipStr)
		if ip != nil && ip.To4() == nil && ip.IsGlobalUnicast() {
			return ip
		}
	}
	return nil
}

// getCurrentDPC returns the active DevicePortStatus from dinfo, or nil if the
// system adapter info is absent or the current index is out of range.
func getCurrentDPC(dinfo *eveinfo.ZInfoDevice) *eveinfo.DevicePortStatus {
	sa := dinfo.GetSystemAdapter()
	if sa == nil {
		return nil
	}
	statusList := sa.GetStatus()
	idx := int(sa.GetCurrentIndex())
	if idx >= len(statusList) {
		return nil
	}
	return statusList[idx]
}

// getDevicePort finds and returns the DevicePort with the given logical label
// from the currently active DevicePortStatus entry in the device info.
func getDevicePort(portLL string, dinfo *eveinfo.ZInfoDevice) *eveinfo.DevicePort {
	dpc := getCurrentDPC(dinfo)
	if dpc == nil {
		return nil
	}
	for _, port := range dpc.GetPorts() {
		if port.GetName() == portLL {
			return port
		}
	}
	return nil
}

func containsIPv4(ips []net.IP) bool {
	for _, ip := range ips {
		if ip.To4() != nil {
			return true
		}
	}
	return false
}

func containsIPv6(ips []net.IP) bool {
	for _, ip := range ips {
		if ip.To4() == nil {
			return true
		}
	}
	return false
}
