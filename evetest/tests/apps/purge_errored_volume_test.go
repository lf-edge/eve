// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"strings"
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// regenerationErrorText is the substring of the error volumemgr's
// handleVolumeModify sets when a volume's MaxVolSize, ReadOnly, ContentID or
// origin type changes without a new generation. The test checks for it so that
// an unrelated error cannot stand in for the trigger.
const regenerationErrorText = "generation counter not incremented"

// TestVMAppPurgeWithErroredVolume purges a running app whose volume is in
// error. The purge must complete: the old domain is torn down and the app runs
// again on a new volume generation.
//
// While purging, zedmanager keeps the old generation's VolumeRefStatus for as
// long as the running domain still uses it, so that the volume is released
// only after the domain is gone. If that volume is in error, its error must not
// block the purge. Otherwise doInstall never reports done, so the domain is
// never torn down, so the old volume is never released: the purge stays in
// DownloadAndVerify indefinitely. TestPurgeNeverActivatedApp covers the
// related case where the failed volume never got a domain.
//
// The error is induced through the controller: the app's volume is given a
// new size without a new generation, which volumemgr refuses with
// regenerationErrorText while the domain keeps running on it. zedmanager only
// picks up a volume's error while the app is installing or purging, and only
// for volumes still in the app's config, so a first purge that keeps the
// generation is what brings the error into the app. A second purge, with a new
// generation, then leaves that errored generation out of the config while the
// domain still uses it.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port, controller reachable.
//
// Device configuration
// --------------------
//   - purgeDeviceRequirements (purge_helpers_test.go): created from scratch,
//     default ext4 (configurable via FILESYSTEM).
//   - SystemAdapter on eth0 (DHCP, mgmt+app), one Local NI and one shim-VM
//     app (vmShimApplication) with an explicit 1 GiB volume size.
//
// Test parameters
// ---------------
//   - HYPERVISOR (kvm or kubevirt).
//   - TPM via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4).
//
// Phases
// ------
//  1. setup-done -> app-is-running: deploy the app and wait for RUNNING.
//  2. volume-in-error: change the volume's size to 2 GiB without a new
//     generation and wait for volumemgr's regenerationErrorText; then purge
//     without a new generation either and wait until the app reports it. That
//     purge cannot complete, and the domain keeps running.
//  3. purge-issued: purge again with a new volume generation at the new size.
//  4. purge-verified: purge counter at the second purge, purge phase NotInprogress, app
//     RUNNING with no error, a single volume at the new generation, and the
//     domain no longer on the old one.
//
// Suite placement
// ---------------
//   - TestAppsSuite, with the other purge tests that need a fresh device.
func TestVMAppPurgeWithErroredVolume(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	evetest.Setup(
		purgeDeviceRequirements(devName, withTPM, filesystem, hypervisor),
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
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
	niUUID := addLocalNI(devConfig)

	// An explicit size: with none, volumemgr fills MaxVolSize in from the
	// created volume, and the config's zero no longer matches it.
	const appDisplayName = "purge-errvol-app"
	app := vmShimApplication(appDisplayName, niUUID)
	app.DiskBytes = 1 * evetest.GiB
	appUUID := devConfig.AddApplication(app)

	device := evetest.GetEdgeDevice(devName)
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(clusterReadyTimeout)
	}
	device.WaitUntilAppIsRunning(appUUID, appReadyTimeout)
	evetest.Checkpoint("app-is-running")

	baselineVolGen := ""
	t.Eventually(func(g Gomega) {
		baselineVolGen = soleVolumeStatus(g, device).Key()
	}, baselineTimeout, assertPollInterval).Should(Succeed())
	baselineCounter, _ := purgeCounter(device, appUUID)

	log := evetest.Logger()
	log.Infof("Resizing volume of app %s without a new generation", appUUID)
	resized := false
	for _, a := range devConfig.Apps {
		if a.GetUuidandversion().GetUuid() != appUUID.String() {
			continue
		}
		t.Expect(a.VolumeRefList).To(HaveLen(1))
		for _, vol := range devConfig.Volumes {
			if vol.Uuid == a.VolumeRefList[0].Uuid {
				vol.Maxsizebytes = int64(2 * evetest.GiB)
				resized = true
			}
		}
	}
	t.Expect(resized).To(BeTrue(), "volume of app %s not found in config", appUUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(func(g Gomega) {
		g.Expect(soleVolumeStatus(g, device).Error).To(
			ContainSubstring(regenerationErrorText))
	}, baselineTimeout, assertPollInterval).Should(Succeed())

	purgeInConfig(t, devConfig, appUUID, false)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(appUpdates, baselineTimeout).Should(Receive(matchers.SatisfyPredicate(
		"app reports the volume regeneration error",
		func(info *eveinfo.ZInfoApp) bool {
			for _, e := range info.AppErr {
				if strings.Contains(e.Description, regenerationErrorText) {
					return true
				}
			}
			return false
		})))
	evetest.Checkpoint("volume-in-error")

	purgeInConfig(t, devConfig, appUUID, true)
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("purge-issued")

	// The purge has to tear the domain down and download nothing new (the
	// image is cached), so both budgets together are generous.
	wantCounter := baselineCounter + 2
	t.Eventually(func(g Gomega) {
		assertPurgeCompleted(g, device, appUUID, wantCounter, baselineVolGen)
		status, found := appPublication[types.AppInstanceStatus](
			device, "zedmanager", appUUID)
		g.Expect(found).To(BeTrue(), "expected a published AppInstanceStatus")
		g.Expect(status.Error).To(BeEmpty(),
			"the old volume's error must not outlive the purge")
		if hypervisor == evetest.HypervisorKubevirt {
			assertKubePurgeEndState(g, device, appUUID, appDisplayName, wantCounter)
		} else {
			assertLocalDomainPurgeEndState(g, device, appUUID, baselineVolGen,
				hypervisor)
		}
	}, purgeCompleteTimeout+purgeEndStateTimeout, assertPollInterval).Should(Succeed())
	evetest.Checkpoint("purge-verified")

	deleteAppAndWait(t, device, devConfig, appUUID)
}

// purgeInConfig increments appUUID's purge counter in
// devConfig and, if bumpVolumeGeneration, the generation of every volume it
// references. evetest.PurgeApplication always changes the volume's identity, so
// it cannot issue the first, generation-keeping purge; both purges go through
// here so that devConfig stays the config the device was given.
func purgeInConfig(t *WithT, devConfig *evetest.EdgeDeviceConfig,
	appUUID uuid.UUID, bumpVolumeGeneration bool) {
	for _, app := range devConfig.Apps {
		if app.GetUuidandversion().GetUuid() != appUUID.String() {
			continue
		}
		app.Purge = &eveconfig.InstanceOpsCmd{Counter: app.GetPurge().GetCounter() + 1}
		if !bumpVolumeGeneration {
			return
		}
		for _, volRef := range app.GetVolumeRefList() {
			volRef.GenerationCount++
			for _, vol := range devConfig.Volumes {
				if vol.GetUuid() == volRef.GetUuid() {
					vol.GenerationCount++
				}
			}
		}
		return
	}
	t.Expect(false).To(BeTrue(), "app %s not found in config", appUUID)
}
