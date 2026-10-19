// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package lps_test

import (
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
)

// TestDevLocalInfo verifies the Local Profile Server (LPS) device-info /
// device-command exchange: EVE reports its own device state to the LPS (GET
// /manage/v1/devinfo), and the LPS can request a graceful shutdown or a
// graceful shutdown-and-poweroff of the whole device (PUT
// /manage/v1/dev-command) independently of the controller.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port. Local NI "local-ni"
//     hosts both the LPS app and "app1" (port-fwd for direct SSH, used only
//     to confirm it is reachable/unreachable at the expected points).
//
// Phases
// ------
//  1. Deploy the LPS app. WaitUntilAppIsRunning, configure the LPS token,
//     and configure EVE to use it via SetLPS.
//  2. Deploy "app1" (plain container, no ProfileList). WaitUntilAppIsRunning,
//     wait for SSH, then confirm the LPS's devinfo reports device state
//     ONLINE.
//  3. LPS-driven graceful shutdown: PUT a dev-command {timestamp=100,
//     COMMAND_SHUTDOWN}. Confirm the LPS-reported devinfo reaches state
//     PREPARING_POWEROFF with LastCmdTimestamp=100 (checked while the LPS
//     app is still up), then wait for both app1 and lps-app to reach
//     HALTED (via their WatchAppInfo channels).
//  4. Recovery: reboot the device via RequestReboot (a controller-driven
//     reboot). Wait for both apps to reach RUNNING again, wait for app1's
//     SSH to become reachable again, then re-run waitLPSAppReady
//     (the LPS app's own in-memory token is wiped by its restart) and confirm
//     devinfo reports ONLINE again.
//  5. LPS-driven graceful shutdown-and-poweroff: PUT a dev-command
//     {timestamp=200, COMMAND_GRACEFUL_POWEROFF}. Confirm the LPS-reported
//     devinfo reaches state POWERING_OFF with LastCmdTimestamp=200 (again
//     checked while the LPS app is still up), then wait for both app1 and
//     lps-app to reach HALTED.
//  6. Call device.PowerOff() to force the VM fully off (this both confirms
//     and, if needed, completes the poweroff EVE initiated in step 5), then
//     device.PowerOn(false) to bring it back -- waitUntilOnline=false since
//     LastRebootTime isn't reliable after a true hard power-off (see
//     PowerOn's doc comment); recovery is confirmed via WaitUntilAppIsRunning
//     on both apps below instead. Wait for both apps to reach RUNNING again
//     and for app1's SSH to become reachable.
//  7. Cleanup: delete both apps and the NI, waiting for each to be gone.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestLPSSuite.
func TestDevLocalInfo(test *testing.T) {
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

	// Step 1: deploy the LPS app.
	lpsAppUUID := devConfig.AddApplication(newLPSAppConfig("lps-app", niUUID, 2222))
	lpsAppUpdates, stopLPSAppWatch := device.WatchAppInfo(lpsAppUUID)
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(lpsAppUUID, timeoutExcludingDownload)
	evetest.Checkpoint("lps-app-running")

	lpsIP := waitLPSAppReady(t, device, lpsAppUUID, lpsServerToken)
	devConfig.SetLPS(evetest.LPSConfig{
		Address:   lpsIP + ":8888",
		AuthToken: lpsServerToken,
	})
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("lps-configured")

	log := evetest.Logger()
	timeout := 5 * time.Minute
	polling := 3 * time.Second

	// Step 2: deploy app1.
	app1UUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "app1",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        256 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2224,
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
	app1Updates, stopApp1Watch := device.WatchAppInfo(app1UUID)
	device.ApplyConfig(devConfig, false, false)
	device.WaitUntilAppIsRunning(app1UUID, timeoutExcludingDownload)
	evetest.Checkpoint("app1-running")

	sshTimeout := 20 * time.Second
	log.Infof("Waiting for app1 SSH to become reachable...")
	waitApp1SSHReachable := func() {
		t.Eventually(func(t Gomega) {
			_, _, err := device.RunShellScriptInsideApp(
				app1UUID, lpsAppAuth, "echo hello", sshTimeout, 0)
			t.Expect(err).ToNot(HaveOccurred())
		}, timeout, polling).Should(Succeed())
	}
	waitApp1SSHReachable()

	// waitDevState polls the LPS-reported devinfo until it reaches the given
	// state, and confirms the LastCmdTimestamp last applied by a dev-command
	// (0 if none has been applied yet). Only valid while the LPS app itself
	// is still up and reachable.
	waitDevState := func(want eveinfo.ZDeviceState, wantLastCmdTimestamp uint64, desc string) {
		log.Infof("Waiting for device state %s (%s)", want, desc)
		t.Eventually(func(t Gomega) {
			info := getLPSDevInfo(t, device, lpsAppUUID)
			t.Expect(info.GetState()).To(Equal(want), desc)
			t.Expect(info.GetLastCmdTimestamp()).To(Equal(wantLastCmdTimestamp), desc)
		}, timeout, polling).Should(Succeed())
	}
	waitDevState(eveinfo.ZDeviceState_ZDEVICE_STATE_ONLINE, 0,
		"device online after app1 deployed")
	evetest.Checkpoint("device-online")

	// waitAppState waits for the given app's WatchAppInfo channel to report
	// the given state. Used for HALTED/INVALID waits below (RUNNING waits
	// use WaitUntilAppIsRunning directly instead).
	waitAppState := func(updates <-chan *eveinfo.ZInfoApp, appName string, want eveinfo.ZSwState) {
		t.Eventually(updates, timeout).Should(Receive(matchers.SatisfyPredicate(
			appName+" reaches "+want.String(),
			func(info *eveinfo.ZInfoApp) bool {
				return info.State == want
			})))
	}

	// Step 3: LPS-driven graceful shutdown.
	log.Infof("Testing LPS-driven COMMAND_SHUTDOWN")
	putLPSDevCommand(t, device, lpsAppUUID, 100, "COMMAND_SHUTDOWN")
	waitDevState(eveinfo.ZDeviceState_ZDEVICE_STATE_PREPARING_POWEROFF, 100,
		"device shutting down after COMMAND_SHUTDOWN")
	waitAppState(app1Updates, "app1", eveinfo.ZSwState_HALTED)
	waitAppState(lpsAppUpdates, "lps-app", eveinfo.ZSwState_HALTED)
	evetest.Checkpoint("shutdown-done")

	// Step 4: recovery via a controller-driven reboot.
	log.Infof("Rebooting the device via the controller to recover from the shutdown")
	device.RequestReboot(true)
	device.WaitUntilAppIsRunning(app1UUID, timeout)
	device.WaitUntilAppIsRunning(lpsAppUUID, timeout)
	waitApp1SSHReachable()

	// The LPS app's in-memory token was wiped by its own restart; re-set it
	// and re-confirm EVE has reconnected to it.
	lpsIP = waitLPSAppReady(t, device, lpsAppUUID, lpsServerToken)
	devConfig.SetLPS(evetest.LPSConfig{
		Address:   lpsIP + ":8888",
		AuthToken: lpsServerToken,
	})
	device.ApplyConfig(devConfig, false, false)
	waitDevState(eveinfo.ZDeviceState_ZDEVICE_STATE_ONLINE, 100,
		"device online again after reboot")
	evetest.Checkpoint("shutdown-recovered")

	// Step 5: LPS-driven graceful shutdown-and-poweroff.
	log.Infof("Testing LPS-driven COMMAND_GRACEFUL_POWEROFF")
	putLPSDevCommand(t, device, lpsAppUUID, 200, "COMMAND_GRACEFUL_POWEROFF")
	waitDevState(eveinfo.ZDeviceState_ZDEVICE_STATE_POWERING_OFF, 200,
		"device powering off after COMMAND_GRACEFUL_POWEROFF")
	waitAppState(app1Updates, "app1", eveinfo.ZSwState_HALTED)
	waitAppState(lpsAppUpdates, "lps-app", eveinfo.ZSwState_HALTED)
	evetest.Checkpoint("poweroff-done")

	// Step 6: force the VM off (confirming/completing the poweroff EVE
	// initiated above) and power it back on.
	log.Infof("Powering the device off (via the broker) and back on")
	device.PowerOff()
	// waitUntilOnline=false: see PowerOn's doc comment -- LastRebootTime
	// isn't reliable after a true hard power-off, so recovery is confirmed
	// below via WaitUntilAppIsRunning instead.
	device.PowerOn(false)
	device.WaitUntilAppIsRunning(app1UUID, timeout)
	device.WaitUntilAppIsRunning(lpsAppUUID, timeout)
	waitApp1SSHReachable()
	evetest.Checkpoint("poweroff-recovered")

	// Cleanup.
	devConfig.DeleteApplication(app1UUID)
	devConfig.DeleteApplication(lpsAppUUID)
	devConfig.DeleteNetworkInstance(niUUID)
	device.ApplyConfig(devConfig, false, false)

	waitAppState(app1Updates, "app1", eveinfo.ZSwState_INVALID)
	stopApp1Watch()
	waitAppState(lpsAppUpdates, "lps-app", eveinfo.ZSwState_INVALID)
	stopLPSAppWatch()
}
