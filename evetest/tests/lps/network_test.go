// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package lps_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestNetworkLocalChanges verifies that EVE's Local Profile Server (LPS)
// integration honors the per-port AllowLocalModifications flag when an
// app deployed on the device submits network-config overrides via the
// LPS management API. EVE must:
//   - publish its current NetworkInfo to the LPS,
//   - reject local overrides for ports that do not have
//     AllowLocalModifications set in the controller config,
//   - apply overrides for ports that do, and reflect the result in both
//     the data plane (resolv.conf / sys/class/net/<if>/mtu) and the
//     NetworkInfo / LocalConfig payload posted back to the LPS,
//   - revert applied overrides when the LPS reports an empty config.
//
// Network model
// -------------
//   - netmodels.TwoMgmtPorts -- two mgmt+app ports (eth0, eth1) each on
//     its own SDN bridge with DHCP and controller reachability. eth0 is
//     also the port for the local NI that hosts the LPS application.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+app). Initially
//     AllowLocalModifications=false on eth0 -- LPS overrides for it must
//     be rejected.
//   - SystemAdapter for eth1 (DHCP, mgmt+app) with
//     AllowLocalModifications=true.
//   - Local NI "local-ni" (10.11.12.0/24, MTU=1500) on eth0.
//   - LPS application "lps-app" (lfedge/evetest-lps:1.0, see
//     newLPSAppConfig in helpers_test.go) on the NI, with SSH port-fwd
//     2222->22 for the test framework to drive curl-against-LPS commands,
//     and 8888->8888 to let a developer expose the LPS UI through
//     `evetest eve portfwd 8888:8888` while a checkpoint is paused.
//   - waitLPSAppReady (helpers_test.go) waits for the LPS app to become
//     reachable over SSH, configures the LPS server token via the LPS
//     management API, and returns the app's IP; the test then pushes
//     evetest.LPSConfig{Address: <appIP>:8888, AuthToken: token} into the
//     device config so EVE actually talks to the LPS.
//
// Phases / assertions
// -------------------
//  1. setup-done -> initial-config-applied -> lps-app-is-running:
//     the LPS container is up.
//  2. lps-configured -> lps-receiving-network-info: EVE picks up the LPS
//     config and starts posting NetworkInfo (HTTP 200 on
//     /manage/v1/network).
//  3. Submit a localNetworkConfig via the LPS management API that
//     overrides DNS for eth0 (dns-server0-alt, 10.16.18.25) and MTU for
//     eth1 (9000). Assert via `Eventually` (configChangeTimeout):
//     - NetworkInfo.LocalConfig.Ports has entries for both adapters.
//     - eth0 entry: ErrorMessage contains "not permitted",
//     ConfigApplied=false.
//     - eth1 entry: no "not permitted" error, ConfigApplied=true, Mtu
//     in the LocalConfig reflects 9000.
//     - Runtime PortStatus for eth0: LinkUp, IPs assigned, DNS does NOT
//     include the rejected 10.16.18.25.
//     - Runtime PortStatus for eth1: Mtu=9000.
//     - On EVE itself: /run/nim/dnsmasq.mgmt.servers does NOT contain
//     10.16.18.25, /sys/class/net/eth1/mtu == "9000".
//  4. Enable AllowLocalModifications=true on eth0 via UpdateNetworkAdapter
//     and re-ApplyConfig. Assert:
//     - LocalConfig.Ports[eth0]: no "not permitted" error,
//     ConfigApplied=true.
//     - PortStatus for eth0: DNS now includes 10.16.18.25.
//     - On EVE: /run/nim/dnsmasq.mgmt.servers now contains 10.16.18.25.
//  5. Push an empty config via the LPS management API
//     ({"serverToken":..., "ports":[]}). Assert that both ports revert
//     to the controller-supplied config:
//     - LatestConfig.ConfigApplied=true for both ports; eth1.Mtu is
//     no longer 9000.
//     - PortStatus for eth0: DNS no longer contains the LPS-supplied
//     entries; PortStatus for eth1: Mtu back to 1500.
//     - On EVE: dnsmasq.mgmt.servers no longer contains 10.16.18.25;
//     /sys/class/net/eth1/mtu == "1500".
//
// Hypervisor / suite placement
// ----------------------------
//   - HYPERVISOR (defaults to KVM).
func TestNetworkLocalChanges(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	// Set up the test harness and specify the test prerequisites.
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
	evetest.Checkpoint("setup-done")

	// Build initial device configuration with two management ports.
	// Only eth1 has AllowLocalModifications enabled at first.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet0 := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	dhcpNet1 := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet0,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:            "ethernet1",
			PhysicalLabel:           "eth1",
			InterfaceName:           "eth1",
			NetworkUUID:             dhcpNet1,
			Usage:                   evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			AllowLocalModifications: true,
		})

	// Deploy the LPS application, connected to a local NI with port forwarding.
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		Gateway:     evetest.IPAddress("10.11.12.1"),
		MTU:         1500,
	})
	appUUID := devConfig.AddApplication(newLPSAppConfig("lps-app", niUUID, 2222))

	device := evetest.GetEdgeDevice(devName)
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("initial-config-applied")

	device.WaitUntilAppIsRunning(appUUID, 10*time.Minute)
	evetest.Checkpoint("lps-app-is-running")

	log := evetest.Logger()
	sshTimeout := 20 * time.Second
	polling := 5 * time.Second
	var output string
	var err error

	lpsIP := waitLPSAppReady(t, device, appUUID, lpsServerToken)

	// Configure EVE to use the LPS.
	devConfig.SetLPS(evetest.LPSConfig{
		Address:   fmt.Sprintf("%s:8888", lpsIP),
		AuthToken: lpsServerToken,
	})
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("lps-configured")

	// Wait for EVE to start posting network info to the LPS.
	configChangeTimeout := 2 * time.Minute
	log.Infof("Waiting for LPS to receive network info from EVE...")
	t.Eventually(func(t Gomega) {
		output := runInLPSApp(t, device, appUUID,
			"curl -sS -o /dev/null -w '%{http_code}' "+lpsManageURL+"/network")
		t.Expect(output).To(Equal("200"))
	}, configChangeTimeout, polling).Should(Succeed())
	evetest.Checkpoint("lps-receiving-network-info")

	// Apply local config: DNS override for eth0, MTU override for eth1.
	log.Infof("Submitting local network config via LPS management API")
	putLPSNetworkConfig(t, device, appUUID, `[
		{
			"logicalLabel": "ethernet0",
			"useDhcp": true,
			"dnsServers": ["10.16.18.25"]
		},
		{
			"logicalLabel": "ethernet1",
			"useDhcp": true,
			"mtu": 9000
		}
	]`)
	evetest.Checkpoint("local-config-submitted")

	// Verify eth0 changes are rejected, eth1 changes are applied.
	// Wait until the NetworkInfo posted by EVE to LPS shows that the local config
	// for eth1 was applied (MTU=9000) and eth0 was rejected (not permitted).
	log.Infof("Verifying eth1 local changes are applied and eth0 is rejected...")
	t.Eventually(func(t Gomega) {
		netInfo := getLPSNetworkInfo(t, device, appUUID)
		t.Expect(netInfo.LocalConfig).ToNot(BeNil())
		for _, port := range netInfo.LocalConfig.Ports {
			switch port.LogicalLabel {
			case "ethernet0":
				t.Expect(port.ErrorMessage).To(
					ContainSubstring("not permitted"),
					"eth0 local config should be rejected")
				t.Expect(port.ConfigApplied).To(BeFalse(),
					"eth0 local config should not be applied")
			case "ethernet1":
				t.Expect(port.ErrorMessage).ToNot(
					ContainSubstring("not permitted"),
					"eth1 local config should be permitted")
				t.Expect(port.ConfigApplied).To(BeTrue(),
					"eth1 local config should be applied")
				t.Expect(port.Mtu).To(Equal(uint32(9000)))
			}
		}

		// Runtime port status that EVE publishes to LPS should reflect
		// the same outcome: eth1's MTU is 9000, eth0 did not pick up
		// the rejected DNS override. Both ports must be up and have
		// at least one IP address assigned.
		eth0Status := portStatusByLabel(t, netInfo, "ethernet0")
		eth1Status := portStatusByLabel(t, netInfo, "ethernet1")
		t.Expect(eth0Status.LinkUp).To(BeTrue())
		t.Expect(eth1Status.LinkUp).To(BeTrue())
		t.Expect(eth0Status.IpAddresses).ToNot(BeEmpty())
		t.Expect(eth1Status.IpAddresses).ToNot(BeEmpty())
		t.Expect(eth1Status.Mtu).To(Equal(uint32(9000)),
			"eth1 MTU in PortStatus should be 9000")
		t.Expect(eth0Status.DnsServers).ToNot(ContainElement("10.16.18.25"),
			"eth0 DNS servers should not include the rejected override")

		// Verify on the EVE device itself: eth0 should NOT have custom DNS,
		// eth1 should have MTU 9000.
		output, _, err = device.RunShellScript(
			"cat /run/nim/dnsmasq.mgmt.servers", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).ToNot(ContainSubstring("10.16.18.25"),
			"eth0 DNS should not be applied")

		output, _, err = device.RunShellScript(
			"cat /sys/class/net/eth1/mtu", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(strings.TrimSpace(output)).To(Equal("9000"),
			"eth1 MTU should be 9000")
	}, configChangeTimeout, polling).Should(Succeed())

	// Enable AllowLocalModifications for eth0
	log.Infof("Enabling AllowLocalModifications for eth0...")
	devConfig.UpdateNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:            "ethernet0",
			PhysicalLabel:           "eth0",
			InterfaceName:           "eth0",
			NetworkUUID:             dhcpNet0,
			Usage:                   evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			AllowLocalModifications: true,
		})
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("eth0-allow-local-mods-enabled")

	// Verify eth0 changes are now applied
	log.Infof("Verifying eth0 local changes are now applied...")
	t.Eventually(func(t Gomega) {
		netInfo := getLPSNetworkInfo(t, device, appUUID)
		t.Expect(netInfo.LocalConfig).ToNot(BeNil())
		for _, port := range netInfo.LocalConfig.Ports {
			if port.LogicalLabel == "ethernet0" {
				t.Expect(port.ErrorMessage).ToNot(
					ContainSubstring("not permitted"),
					"eth0 local config should now be permitted")
				t.Expect(port.ConfigApplied).To(BeTrue(),
					"eth0 local config should now be applied")
			}
		}

		// Runtime port status must reflect the newly-accepted override:
		// eth0's resolver now includes the DNS servers we submitted.
		eth0Status := portStatusByLabel(t, netInfo, "ethernet0")
		t.Expect(eth0Status.DnsServers).To(ContainElement("10.16.18.25"),
			"eth0 PortStatus should include the applied DNS override")

		// Verify on the EVE device: eth0 should now have custom DNS.
		output, _, err = device.RunShellScript(
			"cat /run/nim/dnsmasq.mgmt.servers", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("10.16.18.25"),
			"eth0 DNS should now be applied")
	}, configChangeTimeout, polling).Should(Succeed())

	// Revert local changes by submitting empty config
	log.Infof("Reverting local network config by submitting empty config...")
	putLPSNetworkConfig(t, device, appUUID, "[]")
	evetest.Checkpoint("local-changes-reverted")

	// Verify both ports revert to controller config
	log.Infof("Verifying both ports reverted to controller config...")
	t.Eventually(func(t Gomega) {
		netInfo := getLPSNetworkInfo(t, device, appUUID)
		// After submitting empty config, LocalConfig should have no ports
		// or all ports should show controller config applied.
		for _, port := range netInfo.LatestConfig {
			switch port.LogicalLabel {
			case "ethernet0":
				t.Expect(port.ConfigApplied).To(BeTrue(),
					"eth0 should have controller config applied")
			case "ethernet1":
				t.Expect(port.ConfigApplied).To(BeTrue(),
					"eth1 should have controller config applied")
				t.Expect(port.Mtu).ToNot(Equal(uint32(9000)),
					"eth1 MTU should have reverted from 9000")
			}
		}

		// Runtime port status must reflect the revert: no more LPS DNS
		// override on eth0, MTU back to the default on eth1.
		eth0Status := portStatusByLabel(t, netInfo, "ethernet0")
		eth1Status := portStatusByLabel(t, netInfo, "ethernet1")
		t.Expect(eth0Status.DnsServers).ToNot(ContainElement("10.16.18.25"),
			"eth0 PortStatus DNS should have reverted")
		t.Expect(eth1Status.Mtu).To(Equal(uint32(1500)),
			"eth1 PortStatus MTU should be back to 1500")

		// Verify on the EVE device: DNS reverted, MTU back to 1500.
		output, _, err = device.RunShellScript(
			"cat /run/nim/dnsmasq.mgmt.servers", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).ToNot(ContainSubstring("10.16.18.25"),
			"eth0 DNS should have reverted")

		output, _, err = device.RunShellScript(
			"cat /sys/class/net/eth1/mtu", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(strings.TrimSpace(output)).To(Equal("1500"),
			"eth1 MTU should have reverted to 1500")
	}, configChangeTimeout, polling).Should(Succeed())
}
