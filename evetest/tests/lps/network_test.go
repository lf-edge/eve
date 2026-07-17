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

	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve-api/go/profile"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const (
	lpsServerToken        = "evetest-lps-token"
	lpsLocalBaseURL       = "http://localhost:8888"
	lpsManageURL          = lpsLocalBaseURL + "/manage/v1"
	lpsManageNetConfigURL = lpsManageURL + "/network-config"
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
//   - LPS application "lps-app" (lfedge/evetest-lps:1.0) on the NI
//     with two port-fwd rules:
//   - 2222->22 for the test framework to drive curl-against-LPS commands
//     via SSH inside the app,
//   - 8888->8888 to let a developer expose the LPS UI through
//     `evetest eve portfwd 8888:8888` while a checkpoint is paused.
//   - After the LPS app is reachable over SSH, the test configures the LPS
//     server token via the LPS management API, reads the app's IP, and
//     pushes evetest.LPSConfig{Address: <appIP>:8888, AuthToken: token}
//     into the device config so EVE actually talks to the LPS.
//
// Phases / assertions
// -------------------
//  1. setup-done -> initial-config-applied -> lps-app-is-running:
//     the LPS container is up.
//  2. lps-app-ssh-reachable: the framework can SSH into the app over the
//     port-fwd; a hello probe succeeds.
//  3. lps-configured -> lps-receiving-network-info: EVE picks up the LPS
//     config and starts posting NetworkInfo (HTTP 200 on
//     /manage/v1/network).
//  4. Submit a localNetworkConfig via the LPS management API that
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
//  5. Enable AllowLocalModifications=true on eth0 via UpdateNetworkAdapter
//     and re-ApplyConfig. Assert:
//     - LocalConfig.Ports[eth0]: no "not permitted" error,
//     ConfigApplied=true.
//     - PortStatus for eth0: DNS now includes 10.16.18.25.
//     - On EVE: /run/nim/dnsmasq.mgmt.servers now contains 10.16.18.25.
//  6. Push an empty config via the LPS management API
//     ({"serverToken":..., "ports":[]}). Assert that both ports revert
//     to the controller-supplied config:
//     - LatestConfig.ConfigApplied=true for both ports; eth1.Mtu is
//     no longer 9000.
//     - PortStatus for eth0: DNS no longer contains the LPS-supplied
//     entries; PortStatus for eth1: Mtu back to 1500.
//     - On EVE: dnsmasq.mgmt.servers no longer contains 10.16.18.25;
//     /sys/class/net/eth1/mtu == "1500".
//
// Helpers used
// ------------
//   - getLPSNetworkInfo (defined below): curls /manage/v1/network from
//     inside the LPS app and unmarshals the protobuf-json into a
//     profile.NetworkInfo.
//   - portStatusByLabel (defined below): walks NetworkInfo.PortStatus
//     looking up a port by its LogicalLabel, with a failing assertion
//     if not found.
//
// Hypervisor / suite placement
// ----------------------------
//   - Hardcoded HypervisorKVM. The TODO in TestLPSSuite notes that the
//     HypervisorParameter will be added once additional LPS tests exist
//     that depend on app virtualization.
func TestNetworkLocalChanges(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Set up the test harness and specify the test prerequisites.
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
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "lps-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-lps",
			Tag:       "1.0",
		},
		CPUs:        1,
		MemoryBytes: 512 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				PortFwdRules: []evetest.PortFwdRule{
					{
						// SSH access
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
						AppPort:      22,
					},
					{
						// For developers troubleshooting LPS who need access to the UI:
						// Pause test after LPS is deployed (at checkpoint
						// "lps-app-is-running" or later), then run:
						// $ evetest eve portfwd 8888:8888
						// And open http://localhost:8888 in your browser.
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 8888,
						AppPort:      8888,
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

	device := evetest.GetEdgeDevice(devName)
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	device.WaitUntilAppIsRunning(appUUID, 10*time.Minute)
	evetest.Checkpoint("lps-app-is-running")

	// Wait for the LPS app to become reachable via SSH.
	appAuth := evetest.UsernamePasswordAuth{
		Username: "root",
		Password: "testpassword",
	}
	log := evetest.Logger()
	sshTimeout := 20 * time.Second
	polling := 5 * time.Second
	timeout := 3 * time.Minute
	log.Infof("Waiting for LPS app SSH to become reachable...")
	t.Eventually(func(t Gomega) {
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"echo hello", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(ContainSubstring("hello"))
	}, timeout, polling).Should(Succeed())
	evetest.Checkpoint("lps-app-ssh-reachable")

	// Configure the server token via the LPS management API.
	_, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		fmt.Sprintf(`curl -sS -X PUT -d '{"token":"%s"}' `+lpsManageURL+`/token`,
			lpsServerToken), sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())

	// Get the application's IP (LPS is reachable at this IP from EVE).
	output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
		"hostname -I | awk '{print $1}'", sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	lpsIP := strings.TrimSpace(output)
	log.Infof("LPS app IP: %s", lpsIP)

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
		output, _, err := device.RunShellScriptInsideApp(appUUID, appAuth,
			"curl -sS -o /dev/null -w '%{http_code}' "+lpsManageURL+"/network",
			sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		t.Expect(output).To(Equal("200"))
	}, configChangeTimeout, polling).Should(Succeed())
	evetest.Checkpoint("lps-receiving-network-info")

	// Apply local config: DNS override for eth0, MTU override for eth1.
	localNetworkConfig := fmt.Sprintf(`{
		"serverToken": "%s",
		"ports": [
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
		]
	}`, lpsServerToken)
	log.Infof("Submitting local network config via LPS management API")
	_, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		fmt.Sprintf(`curl -sS -X PUT -H 'Content-Type: application/json' -d '%s' %s`,
			localNetworkConfig, lpsManageNetConfigURL), sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	evetest.Checkpoint("local-config-submitted")

	// Verify eth0 changes are rejected, eth1 changes are applied.
	// Wait until the NetworkInfo posted by EVE to LPS shows that the local config
	// for eth1 was applied (MTU=9000) and eth0 was rejected (not permitted).
	log.Infof("Verifying eth1 local changes are applied and eth0 is rejected...")
	t.Eventually(func(t Gomega) {
		netInfo := getLPSNetworkInfo(t, device, appUUID, appAuth, sshTimeout)
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
		netInfo := getLPSNetworkInfo(t, device, appUUID, appAuth, sshTimeout)
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
	emptyConfig := fmt.Sprintf(`{
		"serverToken": "%s",
		"ports": []
	}`, lpsServerToken)
	_, _, err = device.RunShellScriptInsideApp(appUUID, appAuth,
		fmt.Sprintf(`curl -sS -X PUT -H 'Content-Type: application/json' -d '%s' %s`,
			emptyConfig, lpsManageNetConfigURL), sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	evetest.Checkpoint("local-changes-reverted")

	// Verify both ports revert to controller config
	log.Infof("Verifying both ports reverted to controller config...")
	t.Eventually(func(t Gomega) {
		netInfo := getLPSNetworkInfo(t, device, appUUID, appAuth, sshTimeout)
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

// portStatusByLabel returns the NetworkPortStatus entry matching the given
// logical label. Fails the assertion if no such entry is present in the
// NetworkInfo published by EVE.
func portStatusByLabel(t Gomega, netInfo *profile.NetworkInfo,
	label string) *profile.NetworkPortStatus {
	for _, ps := range netInfo.PortStatus {
		if ps.LogicalLabel == label {
			return ps
		}
	}
	t.Expect(netInfo.PortStatus).To(ContainElement(
		HaveField("LogicalLabel", label)),
		"NetworkInfo.PortStatus should include "+label)
	return nil
}

// getLPSNetworkInfo retrieves and parses the network info that EVE posted to the LPS.
func getLPSNetworkInfo(t Gomega, device *evetest.EdgeDevice,
	appUUID uuid.UUID, auth evetest.AuthMethod,
	timeout time.Duration) *profile.NetworkInfo {
	output, _, err := device.RunShellScriptInsideApp(appUUID, auth,
		"curl -sS "+lpsManageURL+"/network", timeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	var netInfo profile.NetworkInfo
	err = protojson.Unmarshal([]byte(output), &netInfo)
	t.Expect(err).ToNot(HaveOccurred())
	return &netInfo
}
