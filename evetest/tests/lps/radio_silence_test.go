// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package lps_test

import (
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestRadioSilence verifies EVE's radio-silence message exchange with the
// Local Profile Server (LPS): the LPS can request radio silence be imposed
// or lifted, EVE reports the resulting state back to both the LPS and its
// own internal ZedAgentStatus, and the imposed state survives a device
// reboot.
//
// Note: none of evetest's device models currently define a wireless (cellular/WiFi)
// network adapter, so this only exercises the message-passing and persistence
// paths between the LPS, zedagent and nim -- not an actual radio transmitter being
// switched off.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port, used for controller
//     reachability and the LPS app's Local NI.
//
// Phases
// ------
//  1. Deploy the evetest-lps app on Local NI "local-ni". WaitUntilAppIsRunning,
//     then configure EVE to use it via SetLPS.
//  2. Confirm the initial radio status is unsilenced, per both the LPS
//     (GET /manage/v1/radio-status) and EVE's own ZedAgentStatus.
//  3. Toggle radio silence ON (PUT /manage/v1/radio-config
//     {"radioSilence":true}). Assert both:
//     - the LPS's radio-status eventually reports RadioSilence=true, and
//     - EVE's own /run/zedagent/ZedAgentStatus/zedagent.json (read via
//     `eve exec pillar jq ...` over SSH) reports RadioSilence.Imposed=true.
//  4. Toggle radio silence OFF and assert both views report false again.
//  5. Toggle radio silence back ON (assert both views report true again),
//     then reboot the device via RequestReboot and wait for it to come back online.
//  6. After the reboot, assert -- reading EVE's own ZedAgentStatus only,
//     deliberately without any further LPS interaction -- that
//     RadioSilence.Imposed is still true. zedagent persists the
//     last-applied radio-silence state across reboots and re-publishes it
//     on startup.
//  7. Cleanup: delete the app and the NI, waiting for each to be gone.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestLPSSuite.
func TestRadioSilence(test *testing.T) {
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
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4Only})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		Gateway:     evetest.IPAddress("10.11.12.1"),
		MTU:         1500,
	})
	lpsAppUUID := devConfig.AddApplication(newLPSAppConfig("lps-app", niUUID, 2222))
	lpsAppUpdates, stopLPSAppWatch := device.WatchAppInfo(lpsAppUUID)
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	device.WaitUntilAppIsRunning(lpsAppUUID, 5*time.Minute)
	evetest.Checkpoint("lps-app-running")

	lpsIP := waitLPSAppReady(t, device, lpsAppUUID, lpsServerToken)
	devConfig.SetLPS(evetest.LPSConfig{
		Address:   lpsIP + ":8888",
		AuthToken: lpsServerToken,
	})
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("lps-configured")

	log := evetest.Logger()
	timeout := 3 * time.Minute
	polling := 3 * time.Second

	// waitRadioSilence asserts that both the LPS-reported radio status and
	// EVE's own ZedAgentStatus agree on the given RadioSilence value.
	waitRadioSilence := func(want bool, desc string) {
		log.Infof("Waiting for radio-silence=%t (%s)", want, desc)
		t.Eventually(func(t Gomega) {
			status := getLPSRadioStatus(t, device, lpsAppUUID)
			t.Expect(status.RadioSilence).To(Equal(want), "LPS-reported radio status")
			t.Expect(getEVERadioSilenceImposed(t, device)).To(Equal(want),
				"EVE-side ZedAgentStatus.RadioSilence.Imposed")
		}, timeout, polling).Should(Succeed())
	}

	// Step 2: confirm the initial (unsilenced) radio status.
	waitRadioSilence(false, "initial state")
	evetest.Checkpoint("initial-radio-status-confirmed")

	// Step 3: toggle radio silence ON.
	putLPSRadioSilence(t, device, lpsAppUUID, true)
	waitRadioSilence(true, "toggled ON")
	evetest.Checkpoint("radio-silence-on")

	// Step 4: toggle radio silence OFF.
	putLPSRadioSilence(t, device, lpsAppUUID, false)
	waitRadioSilence(false, "toggled OFF")
	evetest.Checkpoint("radio-silence-off")

	// Step 5: toggle back ON, then reboot.
	putLPSRadioSilence(t, device, lpsAppUUID, true)
	waitRadioSilence(true, "toggled ON again, pre-reboot")
	evetest.Checkpoint("radio-silence-on-pre-reboot")

	log.Infof("Rebooting the device via the controller")
	device.RequestReboot(true)
	evetest.Checkpoint("device-rebooted")

	// Step 6: persistence -- EVE's own state only, no LPS interaction.
	log.Infof("Confirming radio-silence=true persisted across the reboot " +
		"(EVE-side check only)")
	t.Eventually(func(t Gomega) {
		t.Expect(getEVERadioSilenceImposed(t, device)).To(BeTrue(),
			"EVE should still report RadioSilence.Imposed=true after reboot")
	}, timeout, polling).Should(Succeed())
	evetest.Checkpoint("radio-silence-persisted")

	// Cleanup.
	devConfig.DeleteApplication(lpsAppUUID)
	devConfig.DeleteNetworkInstance(niUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(lpsAppUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"lps-app is gone", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
	stopLPSAppWatch()
}

// getEVERadioSilenceImposed reads RadioSilence.Imposed directly from EVE's
// own /run/zedagent/ZedAgentStatus/zedagent.json, bypassing the LPS
// entirely. Used to confirm EVE's internal state independent of whether the
// LPS app has (re)connected.
func getEVERadioSilenceImposed(t Gomega, device *evetest.EdgeDevice) bool {
	output, _, err := device.RunShellScript(
		`eve exec pillar jq -r '.RadioSilence.Imposed' /run/zedagent/ZedAgentStatus/zedagent.json`,
		20*time.Second, 0)
	t.Expect(err).ToNot(HaveOccurred())
	return strings.TrimSpace(output) == "true"
}
