// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"

	"github.com/lf-edge/eve/evetest"
)

// TestKvmToKAppRecreate asserts an app can be taken across the flavor seam by
// deleting it before the switch and redeploying it after, without its image
// being downloaded a second time.
//
// This is the recipe that works today: carrying a live app and its volume
// through the switch depends on machinery that a single-node EVE-K cannot yet
// schedule, whereas delete-and-redeploy only needs the cached blobs to outlive
// the gap. They do, but only because the deferred content delete is stretched
// past the length of the gap first -- otherwise EVE reclaims them as soon as
// the app that referenced them is gone, and the redeploy pays for a full
// download.
//
// Phases:
//  1. Deploy the app on the starting flavor and confirm it works.
//  2. Stretch the deferred content delete, then delete the app and its network.
//  3. Cross the flavor seam.
//  4. Redeploy the same app and assert it works and downloaded nothing.
func TestKvmToKAppRecreate(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	defineSharedParameters(altParameterDefinitions()...)
	p := resolveDeviceParams(t)
	altVersion := resolveAltVersion(p)
	altHV := altHypervisor(p.initialHypervisor)

	device := setupDevice(t, p, evetest.FilesystemEXT4, nil,
		evetest.CreateFromScratchWithLiveImage)
	log := evetest.Logger()

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	applyMgmtNetwork(device, devConfig)
	devConfig.SetConfigProperties(shortBaseImageCooldown())
	device.ApplyConfig(devConfig, true, true)

	log.Infof("deploying the app on %s", p.initialHypervisor)
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "eth0",
	})
	appUUID := addTestApp(devConfig, "konvert-recreate-app", niUUID)
	device.ApplyConfig(devConfig, false, false)
	assertAppReady(t, device, appUUID, 15*time.Minute)
	dumpAppNetwork(device, "before the flavor switch (working)")
	evetest.Checkpoint("app-running-before")

	// Without this the blobs are collected the moment the app is deleted, and
	// the redeploy below measures a fresh download instead of a reuse.
	log.Infof("stretching the deferred content delete past the switch")
	props := shortBaseImageCooldown()
	props.SetGlobalValueInt(pillartypes.DeferContentDelete, 24*60*60)
	devConfig.SetConfigProperties(props)
	device.ApplyConfig(devConfig, true, true)

	log.Infof("deleting the app and its network")
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, true, true)
	devConfig.DeleteNetworkInstance(niUUID)
	device.ApplyConfig(devConfig, true, true)
	assertNoLiveVolumes(t, device)
	evetest.Checkpoint("app-deleted")

	conversionOK := false
	defer func() {
		if !conversionOK {
			dumpConversionFailure(device)
		}
	}()
	log.Infof("crossing the flavor seam: %s → %s", p.initialHypervisor, altHV)
	upgradeAcrossFlavors(device, altVersion, altHV)
	conversionOK = true
	evetest.Checkpoint("crossed-to-alt-flavor")

	if altHV == evetest.HypervisorKubevirt {
		waitClusterStorageReady(t, device)
	}

	// After the crossing's reboot, for the reason snapshotDownloaderBytes gives.
	beforeBytes := snapshotDownloaderBytes(t, device)
	log.Infof("redeploying the same app on %s", altHV)
	newNIUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "eth0",
	})
	newAppUUID := addTestApp(devConfig, "konvert-recreate-app", newNIUUID)
	device.ApplyConfig(devConfig, false, false)

	appOK := false
	defer func() {
		if !appOK {
			dumpClusterStorage(device)
			dumpAppNetwork(device, "after the flavor switch (app FAILED)")
		}
	}()
	assertAppReady(t, device, newAppUUID, appRunningAfterSwitchTimeout)
	appOK = true
	assertBlobsReused(t, device, beforeBytes)
	evetest.Checkpoint("app-recreated")

	// Put the collector back the way it was, so a device reused by the next
	// test in the suite is not left holding blobs for a day.
	devConfig.SetConfigProperties(shortBaseImageCooldown())
	device.ApplyConfig(devConfig, true, true)
}
