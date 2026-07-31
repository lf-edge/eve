// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

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
	uuid "github.com/satori/go.uuid"
	"google.golang.org/protobuf/proto"
)

// TestPurgeNeverActivatedApp is a regression test for EVE commit a1582bb40
// ("zedmanager: fix purge stuck when app was never activated").
//
// The bug: when a purge was triggered for an app whose image had failed to
// download (so no domain was ever created for it), the old code left
// PurgeInprogress=BringDown without calling purgeCmdDone. This caused the
// app to get stuck indefinitely (at LOADED with VerifyOnly=true) because
// volumemgr was never told to create the volume.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- only needed for controller reachability
//     and to pull the container images; the app under test needs no network
//     adapter of its own for this test.
//
// Phases
// ------
//  1. Deploy "bad-image-app" referencing a nonexistent image tag
//     (docker://nginx:purge-test-nonexistent-99999). Tag resolution fails,
//     so the app never activates (no domain is ever created). Wait for the
//     app to report a non-empty AppErr while not RUNNING -- this confirms
//     the broken precondition without assuming any particular stuck
//     SwState (the exact state the app settles into isn't the point of this
//     test, and asserting on the wrong one would make the test as fragile
//     as the bug it's meant to catch).
//  2. fixImageAndPurge applies, in a single EdgeDevConfig mutation /
//     ApplyConfig call:
//     a. a fresh ContentTree (new UUID, same datastore, URL fixed to the
//     working tag docker://nginx:stable, Sha256 cleared),
//     b. a fresh Volume (new UUID) whose origin points at that fresh
//     ContentTree,
//     c. the app's VolumeRefList rewired to the fresh Volume,
//     d. the app's purge counter incremented.
//     This combination -- fixing the image while simultaneously purging --
//     is exactly what triggers the bug: EVE must tear down the
//     never-activated app and reprocess it from scratch instead of getting
//     stuck.
//  3. With the fix, the app eventually reaches RUNNING. (Without the fix,
//     this step is where the test would time out -- the app would remain
//     stuck indefinitely instead.)
//  4. Cleanup: delete the app, wait for ZSwState_INVALID.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//
// Suite placement
// ---------------
//   - TestAppsSuite.
func TestPurgeNeverActivatedApp(test *testing.T) {
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
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}

	// Step 1: deploy an app whose image tag does not exist, so it never
	// activates.
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "bad-image-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "nginx",
			Tag:       "purge-test-nonexistent-99999",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
	})
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	device.ApplyConfig(devConfig, false, false)

	log := evetest.Logger()
	log.Infof("Waiting for the app to fail to activate (nonexistent image tag)")
	timeout := 5 * time.Minute
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app never activates (bad image tag) and reports an error",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State != eveinfo.ZSwState_RUNNING && len(info.AppErr) > 0
		})))
	evetest.Checkpoint("app-never-activated")

	// Step 2: fix the image and purge, atomically.
	log.Infof("Fixing the image and purging the app in a single config apply")
	fixImageAndPurge(t, devConfig, appUUID, "nginx:stable")
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("app-fixed-and-purged")

	// Step 3: with the fix, the app recovers and reaches RUNNING. Without it,
	// this is where the test would time out.
	log.Infof("Waiting for the app to reach RUNNING after the purge")
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app reaches RUNNING after purge",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_RUNNING
		})))
	evetest.Checkpoint("app-running-after-purge")

	// Cleanup.
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app is gone", func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))
	stopAppWatch()
}

// fixImageAndPurge replicates, as a single EdgeDevConfig mutation, what a
// real app purge does (fresh Volume + ContentTree identities) while also
// fixing the app's image reference to a working one -- the exact
// combination that reproduces EVE commit a1582bb40. goodImageURL is the
// "<image>:<tag>" reference to switch the app's ContentTree to (same
// Datastore, only the URL and identity change).
func fixImageAndPurge(t *WithT, devConfig *evetest.EdgeDeviceConfig,
	appUUID uuid.UUID, goodImageURL string) {
	appUUIDStr := appUUID.String()

	var app *eveconfig.AppInstanceConfig
	for _, a := range devConfig.Apps {
		if a.GetUuidandversion().GetUuid() == appUUIDStr {
			app = a
			break
		}
	}
	t.Expect(app).ToNot(BeNil(), "app %s not found in config", appUUIDStr)
	t.Expect(app.VolumeRefList).To(HaveLen(1))

	oldVolUUID := app.VolumeRefList[0].Uuid
	oldVolIdx := -1
	for i, v := range devConfig.Volumes {
		if v.Uuid == oldVolUUID {
			oldVolIdx = i
			break
		}
	}
	t.Expect(oldVolIdx).To(BeNumerically(">=", 0),
		"volume %s not found in config", oldVolUUID)
	oldVolume := devConfig.Volumes[oldVolIdx]

	oldCTUUID := oldVolume.GetOrigin().GetDownloadContentTreeID()
	oldCTIdx := -1
	for i, ct := range devConfig.ContentInfo {
		if ct.Uuid == oldCTUUID {
			oldCTIdx = i
			break
		}
	}
	t.Expect(oldCTIdx).To(BeNumerically(">=", 0),
		"content tree %s not found in config", oldCTUUID)
	oldCT := devConfig.ContentInfo[oldCTIdx]

	newCTUUID, err := uuid.NewV4()
	t.Expect(err).ToNot(HaveOccurred())
	newVolUUID, err := uuid.NewV4()
	t.Expect(err).ToNot(HaveOccurred())

	// Fresh ContentTree: same Datastore reference, fixed (working) URL.
	newCT := proto.CloneOf(oldCT)
	newCT.Uuid = newCTUUID.String()
	newCT.URL = goodImageURL
	newCT.Sha256 = ""
	devConfig.ContentInfo[oldCTIdx] = newCT

	// Fresh Volume pointing at the fresh ContentTree.
	newVolume := proto.CloneOf(oldVolume)
	newVolume.Uuid = newVolUUID.String()
	newVolume.Origin.DownloadContentTreeID = newCTUUID.String()
	devConfig.Volumes[oldVolIdx] = newVolume

	// Rewire the app's volume reference and increment the purge counter --
	// together, this is exactly what a real purge does.
	app.VolumeRefList[0].Uuid = newVolUUID.String()
	purgeCounter := uint32(0)
	if app.Purge != nil {
		purgeCounter = app.Purge.Counter
	}
	app.Purge = &eveconfig.InstanceOpsCmd{Counter: purgeCounter + 1}
}

func appHasError(info *eveinfo.ZInfoApp) (string, bool) {
	stop := info.State == eveinfo.ZSwState_ERROR
	if stop {
		return "Application instance is in error state", true
	}
	return "", false
}
