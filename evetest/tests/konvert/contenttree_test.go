// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// TestKvmToKContentTree asserts image blobs already on the device survive the
// flavor switch, and that deploying from them afterwards downloads nothing.
//
// The point of staging a bare ContentTree rather than a volume is to ask only
// about the blobs. A volume would drag in the PVC and CDI machinery that EVE-K
// stands up after the switch, and a failure there would look identical to the
// blobs having been lost -- which is a different, and much less interesting,
// answer.
//
// Phases:
//  1. Stage a ContentTree on the starting flavor and wait for its blobs to land.
//  2. Cross the flavor seam.
//  3. Assert the ContentTree is still there, and that deploying an app from
//     the same image introduces no content the device did not already hold.
func TestKvmToKContentTree(test *testing.T) {
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

	log.Infof("staging a ContentTree on %s", p.initialHypervisor)
	ctUUID := devConfig.AddContentTree("konvert-staged-image",
		evetest.DockerContainer{ImageName: appImageName, Tag: appImageTag})
	device.ApplyConfig(devConfig, true, true)
	assertContentTreeAvailable(t, device, ctUUID, 20*time.Minute)
	evetest.Checkpoint("contenttree-staged")

	conversionOK := false
	defer func() {
		if !conversionOK {
			dumpConversionFailure(device)
		}
	}()
	log.Infof("crossing the flavor seam: %s → %s", p.initialHypervisor, altHV)
	upgradeAcrossFlavors(device, altVersion, altHV)
	conversionOK = true

	log.Infof("the staged ContentTree must still be on %s", altHV)
	assertContentTreeAvailable(t, device, ctUUID, 20*time.Minute)
	evetest.Checkpoint("contenttree-survived")

	if altHV == evetest.HypervisorKubevirt {
		waitClusterStorageReady(t, device)
	}

	// Snapshotted here, after the crossing's reboot: the downloader's byte
	// counter lives under /run and starts again at zero on every boot, so a
	// reading taken before the crossing could not be compared with one after.
	beforeBytes := snapshotDownloaderBytes(t, device)
	log.Infof("deploying from the staged image must download nothing")
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "eth0",
	})
	appUUID := addTestApp(devConfig, "konvert-reuse-app", niUUID)
	device.ApplyConfig(devConfig, false, false)

	appOK := false
	defer func() {
		if !appOK {
			dumpClusterStorage(device)
			dumpAppNetwork(device, "after the flavor switch")
		}
	}()
	assertAppReady(t, device, appUUID, appRunningAfterSwitchTimeout)
	appOK = true
	assertBlobsReused(t, device, beforeBytes)
	evetest.Checkpoint("blobs-reused")
}
