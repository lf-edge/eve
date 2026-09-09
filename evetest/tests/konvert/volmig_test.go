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

const (
	// dataVolumeSize is the app data volume carried across the conversion.
	// Small on purpose: what is being tested is that the data survives, and a
	// larger volume only lengthens the storage work between the assertions.
	dataVolumeSize = 256 * evetest.MiB
	// volumeMarker is written into that volume before the conversion and looked
	// for afterwards. Distinctive enough to be found by scanning a raw device.
	volumeMarker = "KONVERT-VOLMIG-MARKER-9f3a1c7e"
)

// TestKvmToKVolumeMigration asserts an application volume survives the
// cross-flavor conversion with its contents intact, without the app being
// deleted and redeployed around it.
//
// This is the case the other conversion tests deliberately avoid. They delete
// the app first, because the cross-flavor gate refuses to convert while a volume
// exists; here the device already has the EVE-K partition layout, so no
// repartition is needed, the gate allows the conversion with volumes present,
// and the volume has to be carried over rather than recreated. The code that
// does the carrying is what this test is about: upgradeconverter moves the
// volume out of the directory Longhorn takes ownership of on EVE-K, and
// volumemgr later rolls it into a PVC.
//
// Because no repartition is involved, the device starts on the build under test
// rather than a released image -- there is no old geometry to convert, and
// pinning a release would only add an upgrade this test is not about.
//
// The marker is read back off the volume's raw block device rather than from
// where it was written. On EVE-K a container's data volume is not auto-mounted
// at its MountDir (lf-edge/eve#6145), so a mount-based check would report the
// data lost when it is merely unmounted -- the exact false failure this test
// exists to distinguish from a real one.
//
// Phases:
//  1. The vault must be TPM-backed, and the layout already EVE-K's.
//  2. Deploy the app with a data volume and write a marker into it.
//  3. Convert to EVE-K with the app and volume kept in place.
//  4. Assert the layout is unchanged and the app comes back.
//  5. Assert the marker is still there, and that nothing was re-downloaded.
//
// Not covered: the escript this is ported from also carries a VM application's
// disk volume across the conversion. evetest has no VM application image and no
// cloud-init plumbing to reach a VM guest, so that half is not portable yet;
// adding it means a new test app and UserData support in the framework.
//
// Needs an EVE build carrying the conversion (lf-edge/eve#6036, #6063).
func TestKvmToKVolumeMigration(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	defineSharedParameters()
	p := resolveDeviceParams(t)
	// The build under test, not a release: this conversion needs a device that
	// is already on the EVE-K layout, which is what that build lays down.
	p.initialVersion = ""
	p.initialRepo = ""
	p.initialHypervisor = evetest.HypervisorKVM
	t.Expect(p.withTPM).To(BeTrue(),
		"this test needs a TPM: the volume it carries over is inside the vault")

	device := setupDevice(t, p, evetest.FilesystemEXT4, nil,
		evetest.CreateFromScratchWithLiveImage)
	log := evetest.Logger()

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	applyMgmtNetwork(device, devConfig)
	devConfig.SetConfigProperties(shortBaseImageCooldown())
	device.ApplyConfig(devConfig, true, true)

	// Phase 1. A vault that fell back to no-TPM would still hold the volume, so
	// the carry-over would appear to work while proving nothing about the
	// encrypted path the real thing takes.
	log.Infof("the vault must be TPM-backed")
	assertVaultIsTPMBacked(t, device)
	startGeometry := readGeometry(t, device)
	log.Infof("starting geometry: %s", startGeometry)
	t.Expect(isEVEKLayout(startGeometry)).To(BeTrue(),
		"this test needs a device already on the EVE-K layout, so that the "+
			"conversion takes the no-repartition path: %s", startGeometry)
	evetest.Checkpoint("baseline-ready")

	// Phase 2. Encrypted, not clear text: a clear-text volume sidesteps the
	// vault entirely, and the vault transition is half of what makes the
	// carry-over difficult.
	log.Infof("deploying the app with a data volume")
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "eth0",
	})
	dataVolUUID := devConfig.AddBlankVolume("konvert-volmig-data", dataVolumeSize, false)
	appUUID := addTestAppWithVolume(devConfig, "konvert-volmig-app", niUUID, dataVolUUID)
	device.ApplyConfig(devConfig, false, false)
	assertAppReady(t, device, appUUID, 20*time.Minute)

	log.Infof("writing a marker into the data volume")
	writeVolumeMarker(t, device, appUUID, dataMountDir, volumeMarker)
	dumpAppNetwork(device, "before the conversion (working)")
	evetest.Checkpoint("marker-written")

	// Phase 3. The app and its volume stay in the configuration across the
	// conversion; that is the whole point.
	conversionOK := false
	defer func() {
		if !conversionOK {
			dumpConversionFailure(device)
		}
	}()
	log.Infof("converting to EVE-K with the app and volume in place")
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKubevirt,
		evetest.BaseOSDatastoreHTTP, true, false)
	conversionOK = true
	evetest.Checkpoint("conversion-complete")

	// Phase 4. Unchanged rather than grown: there was nothing to repartition,
	// so a layout that moved would mean the conversion did work it should have
	// skipped.
	log.Infof("the layout must be unchanged")
	assertGeometryUnchanged(t, device, startGeometry)

	appOK := false
	defer func() {
		if !appOK {
			dumpClusterStorage(device)
			dumpAppNetwork(device, "after the conversion (app FAILED)")
		}
	}()
	waitClusterStorageReady(t, device)
	assertAppReady(t, device, appUUID, appRunningAfterSwitchTimeout)
	appOK = true
	evetest.Checkpoint("app-back")

	// Phase 5.
	log.Infof("the marker must still be in the volume")
	assertVolumeMarker(t, device, appUUID, volumeMarker)
	assertNothingDownloadedThisBoot(t, device)
	evetest.Checkpoint("volume-survived")
}

// assertVaultIsTPMBacked asserts the vault is sealed to a TPM at all, whichever
// key opened it this boot.
//
// Deliberately weaker than settleVaultLocal: this test does not need the seal to
// have settled, only for there to be one. A device that came up without a TPM
// would carry the volume over just as happily and prove nothing about the
// encrypted path.
func assertVaultIsTPMBacked(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func() string {
		return readVaultUnlockMethod(device)
	}, 12*time.Minute, 10*time.Second).Should(BeElementOf(unlockLocal, unlockController),
		"the vault is not TPM-backed, so the volume it holds is not encrypted")
}
