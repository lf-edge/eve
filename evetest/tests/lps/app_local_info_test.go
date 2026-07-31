// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package lps_test

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
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
)

// TestAppLocalInfo verifies the Local Profile Server (LPS) app-info /
// app-command exchange: EVE reports every deployed app's state to the LPS
// (GET /manage/v1/appinfo), and the LPS can request a purge or restart of a
// specific app (PUT /manage/v1/app-command) independently of the
// controller. EVE sums LPS-driven and controller-driven purge/restart
// counters -- both paths must work, and only a purge (LPS-driven or
// controller-driven) recreates the app's volume; a restart does not.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port. Local NI "local-ni"
//     hosts both the LPS app (port-fwd for its management API + SSH) and
//     "app1" (port-fwd for direct SSH, used to create/check files that
//     prove whether a purge recreated the volume).
//
// Phases
// ------
//  1. Deploy the LPS app. WaitUntilAppIsRunning, configure the LPS token,
//     and configure EVE to use it via SetLPS.
//  2. Confirm the LPS's app-info list includes "lps-app" but not "app1"
//     (app1 does not exist yet).
//  3. Deploy "app1" (plain container, no ProfileList). WaitUntilAppIsRunning,
//     wait for SSH, then confirm the LPS's app-info list now includes both
//     apps.
//  4. LPS-driven purge: create /root/purge_test in app1, confirm app1's
//     LPS-reported LastCmdTimestamp is still 0, then PUT an app-command
//     {app1, timestamp=123, COMMAND_PURGE}. Wait for app1 to pass through
//     PURGING/HALTING and back to RUNNING, confirm the LPS now reports
//     LastCmdTimestamp=123, and confirm /root/purge_test is gone (purge
//     recreated the volume).
//  5. Controller-driven purge: create /root/purge_test again, call
//     PurgeApplication directly (bypassing the LPS). Wait for the same
//     PURGING/HALTING -> RUNNING cycle, confirm the LPS-reported
//     LastCmdTimestamp is *unchanged* at 123 (a controller-driven purge
//     does not touch the LPS-tracked command timestamp), and confirm
//     /root/purge_test is gone again.
//  6. LPS-driven restart: create both /tmp/restart_test (tmpfs -- wiped by
//     any VM reboot) and /root/purge_test (persistent -- survives a
//     restart, unlike a purge) in app1, then PUT an app-command {app1,
//     timestamp=456, COMMAND_RESTART}. Wait for app1 to pass through
//     RESTARTING/HALTING and back to RUNNING, confirm LastCmdTimestamp=456,
//     confirm /tmp/restart_test is gone but /root/purge_test still exists
//     (a restart does not recreate the volume).
//  7. Controller-driven restart: same file setup, call RebootApplication
//     directly. Confirm LastCmdTimestamp is *unchanged* at 456, and the
//     same file-survival pattern.
//  8. Delete app1, wait for it to be gone, then confirm the LPS's app-info
//     list no longer includes "app1" (but still includes "lps-app").
//  9. Cleanup: delete the LPS app and the NI, waiting for each to be gone.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestLPSSuite.
func TestAppLocalInfo(test *testing.T) {
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

	// Step 2: appinfo includes lps-app but not app1 yet.
	log.Infof("Waiting for the LPS to report appinfo for lps-app only")
	t.Eventually(func(t Gomega) {
		list := getLPSAppInfo(t, device, lpsAppUUID)
		t.Expect(appInfoByName(list, "lps-app")).ToNot(BeNil())
		t.Expect(appInfoByName(list, "app1")).To(BeNil())
	}, timeout, polling).Should(Succeed())
	evetest.Checkpoint("appinfo-before-app1")

	// Step 3: deploy app1.
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
	waitApp1SSHReachable := func() {
		log.Infof("Waiting for app1 SSH to become reachable...")
		t.Eventually(func(t Gomega) {
			_, _, err := device.RunShellScriptInsideApp(
				app1UUID, lpsAppAuth, "echo hello", sshTimeout, 0)
			t.Expect(err).ToNot(HaveOccurred())
		}, timeout, polling).Should(Succeed())
	}
	waitApp1SSHReachable()

	log.Infof("Waiting for the LPS to report appinfo for both apps")
	t.Eventually(func(t Gomega) {
		list := getLPSAppInfo(t, device, lpsAppUUID)
		t.Expect(appInfoByName(list, "lps-app")).ToNot(BeNil())
		t.Expect(appInfoByName(list, "app1")).ToNot(BeNil())
	}, timeout, polling).Should(Succeed())
	evetest.Checkpoint("appinfo-with-app1")

	// waitAppTransientThenRunning drains app1Updates until it reports one of
	// the given transient states (no exported helper targets these), then
	// waits for RUNNING again via WaitUntilAppIsRunning directly, then for
	// SSH to become reachable again.
	waitAppTransientThenRunning := func(transient ...eveinfo.ZSwState) {
		t.Eventually(app1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
			"app1 enters a transient state",
			func(info *eveinfo.ZInfoApp) bool {
				return generics.ContainsItem(transient, info.State)
			})))
		device.WaitUntilAppIsRunning(app1UUID, timeout)
		waitApp1SSHReachable()
	}
	touchApp1 := func(path string) {
		_, _, err := device.RunShellScriptInsideApp(app1UUID, lpsAppAuth,
			"touch "+path, sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
	}
	app1FileExists := func(path string) bool {
		output, _, err := device.RunShellScriptInsideApp(app1UUID, lpsAppAuth,
			"test -f "+path+" && echo EXISTS; true", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
		return strings.Contains(output, "EXISTS")
	}
	waitLastCmdTimestamp := func(want uint64, desc string) {
		t.Eventually(func(t Gomega) {
			list := getLPSAppInfo(t, device, lpsAppUUID)
			info := appInfoByName(list, "app1")
			t.Expect(info).ToNot(BeNil())
			t.Expect(info.GetLastCmdTimestamp()).To(Equal(want), desc)
		}, timeout, polling).Should(Succeed())
	}

	// Step 4: LPS-driven purge.
	log.Infof("Testing LPS-driven purge")
	touchApp1("/root/purge_test")
	waitLastCmdTimestamp(0, "app1 has no LPS command applied yet")
	putLPSAppCommand(t, device, lpsAppUUID, "app1", 123, "COMMAND_PURGE")
	waitAppTransientThenRunning(eveinfo.ZSwState_PURGING, eveinfo.ZSwState_HALTING)
	waitLastCmdTimestamp(123, "app1 should report the LPS purge command timestamp")
	t.Expect(app1FileExists("/root/purge_test")).To(BeFalse(),
		"purge should have recreated app1's volume")
	evetest.Checkpoint("lps-purge-done")

	// Step 5: controller-driven purge. EVE sums local and remote purge
	// counters, but the LPS-visible LastCmdTimestamp must not change.
	log.Infof("Testing controller-driven purge")
	touchApp1("/root/purge_test")
	device.PurgeApplication(app1UUID, true, timeout)
	waitApp1SSHReachable()
	waitLastCmdTimestamp(123, "controller-driven purge must not change the LPS timestamp")
	t.Expect(app1FileExists("/root/purge_test")).To(BeFalse(),
		"controller-driven purge should also recreate app1's volume")
	evetest.Checkpoint("controller-purge-done")

	// Step 6: LPS-driven restart. Unlike a purge, a restart does not
	// recreate the volume.
	log.Infof("Testing LPS-driven restart")
	touchApp1("/tmp/restart_test")
	touchApp1("/root/purge_test")
	putLPSAppCommand(t, device, lpsAppUUID, "app1", 456, "COMMAND_RESTART")
	waitAppTransientThenRunning(eveinfo.ZSwState_RESTARTING, eveinfo.ZSwState_HALTING)
	waitLastCmdTimestamp(456, "app1 should report the LPS restart command timestamp")
	t.Expect(app1FileExists("/tmp/restart_test")).To(BeFalse(),
		"restart should have wiped the tmpfs /tmp")
	t.Expect(app1FileExists("/root/purge_test")).To(BeTrue(),
		"restart should not have recreated app1's volume")
	evetest.Checkpoint("lps-restart-done")

	// Step 7: controller-driven restart.
	log.Infof("Testing controller-driven restart")
	touchApp1("/tmp/restart_test")
	touchApp1("/root/purge_test")
	device.RebootApplication(app1UUID, true, timeout)
	waitApp1SSHReachable()
	waitLastCmdTimestamp(456, "controller-driven restart must not change the LPS timestamp")
	t.Expect(app1FileExists("/tmp/restart_test")).To(BeFalse(),
		"controller-driven restart should have wiped the tmpfs /tmp")
	t.Expect(app1FileExists("/root/purge_test")).To(BeTrue(),
		"controller-driven restart should not have recreated app1's volume")
	evetest.Checkpoint("controller-restart-done")

	// Step 8: remove app1 and confirm the LPS stops seeing it.
	devConfig.DeleteApplication(app1UUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(app1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app1 is gone", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
	stopApp1Watch()

	log.Infof("Waiting for the LPS to stop reporting app1")
	t.Eventually(func(t Gomega) {
		list := getLPSAppInfo(t, device, lpsAppUUID)
		t.Expect(appInfoByName(list, "lps-app")).ToNot(BeNil())
		t.Expect(appInfoByName(list, "app1")).To(BeNil())
	}, timeout, polling).Should(Succeed())
	evetest.Checkpoint("appinfo-after-app1-removed")

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
