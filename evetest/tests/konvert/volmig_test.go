// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/evetest"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

const (
	// dataVolumeSize is the app data volume carried across the conversion, at
	// the size TestKvmToKRepartitionAppVolume uses.
	dataVolumeSize = appVolumeDataVolMiB * evetest.MiB
	// volumeMarker, made per run, is written into that volume before the
	// conversion and looked for afterwards.
	volumeMarker = "KONVERT-VOLMIG-MARKER"
	// downloadedVolumeSize is the downloaded volume carried beside the blank
	// one. Its contents do not matter, only which carry-over branch it takes.
	downloadedVolumeSize = 256 * evetest.MiB
	// downloadedMountDir is where the app mounts the downloaded volume.
	downloadedMountDir = "/mnt/downloaded"
	// downloadedMarker, made per run, is written into the downloaded volume.
	downloadedMarker = "KONVERT-VOLMIG-DOWNLOADED-MARKER"
	// vmMarkerBase, made per run, is written onto the VM app's boot disk.
	vmMarkerBase = "KONVERT-VOLMIG-VM-MARKER"
	// clearVolumeSize is the clear-text volume, as small as the downloaded one
	// for the same reason.
	clearVolumeSize = downloadedVolumeSize
	// clearMountDir is where the app mounts the clear-text volume.
	clearMountDir = "/mnt/clear"
	// clearMarker, made per run, is written into the clear-text volume.
	clearMarker = "KONVERT-VOLMIG-CLEAR-MARKER"
	// carriedCleanupTimeout bounds how long the carried-over kvm volumes may
	// remain once the app is back: the partition commit, then a volumemgr gc
	// tick (a tenth of timer.gc.vdisk, six minutes by default).
	carriedCleanupTimeout = 30 * time.Minute
	// holdDrainGCTime is the timer.gc.vdisk REBOOT_BEFORE_DRAIN sets before the
	// conversion. volumemgr builds its gc ticker, at a tenth of this, only when
	// it starts using config, from the persisted value; a later change does not
	// reset it. Ten hours gives every EVE-K boot an hour without a drain.
	holdDrainGCTime = 10 * pillartypes.HourInSec
	// carriedHeldTimeout bounds how long after a boot the carried-over volumes,
	// and on ZFS their zvol device nodes, may take to show up.
	carriedHeldTimeout = 5 * time.Minute
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
// does the carrying is what this test is about, and it differs by /persist
// filesystem (PERSIST_FILESYSTEM). On ext4 upgradeconverter moves the encrypted
// volumes out of the directory Longhorn takes ownership of on EVE-K; on ZFS the
// volumes are zvols, and the vault migration parks the kvm vault holding the
// encrypted ones. Either way volumemgr later rolls each volume into a PVC, and
// removes the kvm copies once the EVE-K partition is committed.
//
// Because no repartition is involved, the device starts on the build under test
// rather than a released image -- there is no old geometry to convert, and
// pinning a release would only add an upgrade this test is not about.
//
// The app carries three volumes, because EVE-K takes each origin down its own
// branch: a blank one, one downloaded from a datastore, and a blank clear-text
// one, which sidesteps the vault and is carried from elsewhere. The downloaded image
// is a blank qcow2, which the EVE-kvm shim formats on first mount like any disk
// without a filesystem; its marker is written after the download, so finding
// it on EVE-K means the kvm file was carried rather than the image re-imported.
//
// Each marker is read back by mounting the volume's block device read-only
// rather than from where it was written. On EVE-K a container's data volume is
// not auto-mounted at its MountDir (lf-edge/eve#6145), so a check there would
// report the data lost when it is merely unmounted -- the exact false failure
// this test exists to distinguish from a real one.
//
// Phases:
//  1. /persist must be the selected filesystem, the vault TPM-backed, and the
//     layout already EVE-K's.
//  2. Deploy the app with its three volumes, and write a marker into each.
//  3. Convert to EVE-K with the app and volumes kept in place.
//  4. Assert the layout is unchanged and the app comes back.
//  5. Assert every marker is still there, and that nothing was re-downloaded.
//  6. (REBOOT_BEFORE_DRAIN) With the drain held off, reboot EVE-K: the app,
//     every marker and the carried-over kvm volumes must survive it, and on ZFS
//     each carried zvol must have its device node again, which needs the
//     parked vault's key reloaded. Then restore timer.gc.vdisk and reboot again
//     so the drain can run.
//  7. Assert the carried-over kvm copies are removed.
//
// With VM_APP (default true) an Alpine VM app rides along too: its boot disk is
// a downloaded qcow2 that the guest itself mounts, and a marker written to it
// on EVE-kvm must be there when the guest boots on EVE-K.
//
// Needs an EVE build carrying the conversion (lf-edge/eve#6036, #6063) and
// lf-edge/eve#6658, which lets a conversion that does not shrink /persist
// through with volumes present, carries the volumes from ZFS, and removes the
// kvm copies after the commit. Master refuses any kvm→k update while volumes
// exist.
func TestKvmToKVolumeMigration(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()
	requireFlavorAwareTransport(t)

	defineSharedParameters(vmAppParameter(), persistFilesystemParameter(),
		rebootBeforeDrainParameter())
	withVM := evetest.GetTestParameter[bool](vmAppParamKey)
	rebootBeforeDrain := evetest.GetTestParameter[bool](rebootBeforeDrainParamKey)
	persistFS := evetest.GetTestParameter[string](persistFilesystemParamKey)
	t.Expect(persistFS).To(BeElementOf("ext4", "zfs"),
		"%s must be %q or %q", persistFilesystemParamKey, "ext4", "zfs")
	filesystem := evetest.FilesystemEXT4
	if persistFS == "zfs" {
		filesystem = evetest.FilesystemZFS
	}
	p := raiseFloorsForCarriedVolume(t, resolveDeviceParams(t))
	// The build under test, not a release: this conversion needs a device that
	// is already on the EVE-K layout, which is what that build lays down.
	p.initialVersion = ""
	p.initialRepo = ""
	p.initialHypervisor = evetest.HypervisorKVM
	t.Expect(p.withTPM).To(BeTrue(),
		"this test needs a TPM: the volume it carries over is inside the vault")

	device := setupDevice(t, p, filesystem, nil,
		evetest.CreateFromScratchWithLiveImage)
	log := evetest.Logger()

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	applyMgmtNetwork(device, devConfig)
	props := shortBaseImageCooldown()
	if rebootBeforeDrain {
		props.SetGlobalValueInt(pillartypes.VdiskGCTime, holdDrainGCTime)
	}
	devConfig.SetConfigProperties(props)
	device.ApplyConfig(devConfig, true, true)

	// Phase 1. A vault that fell back to no-TPM would still hold the volume, so
	// the carry-over would appear to work while proving nothing about the
	// encrypted path the real thing takes.
	log.Infof("/persist must be %s", persistFS)
	assertPersistType(t, device, persistFS)
	log.Infof("the vault must be TPM-backed")
	assertVaultIsTPMBacked(t, device)
	startGeometry := readGeometry(t, device)
	log.Infof("starting geometry: %s", startGeometry)
	t.Expect(isEVEKLayout(startGeometry)).To(BeTrue(),
		"this test needs a device already on the EVE-K layout, so that the "+
			"conversion takes the no-repartition path: %s", startGeometry)
	evetest.Checkpoint("baseline-ready")

	// Phase 2.
	log.Infof("deploying the app with a blank, a downloaded and a clear-text volume")
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "eth0",
	})
	dataVolUUID := devConfig.AddBlankVolume("konvert-volmig-data", dataVolumeSize, false)
	dlImage, dlSHA := evetest.CreateBlankImageFile("konvert-volmig-downloaded.qcow2",
		eveconfig.Format_QCOW2, downloadedVolumeSize)
	dlVolUUID := devConfig.AddVolume("konvert-volmig-downloaded", evetest.HTTPStorage{
		ImageFormat:       eveconfig.Format_QCOW2,
		ImageRelativePath: dlImage,
		ImageSHA256:       dlSHA,
		ServerAddress:     evetest.GetImageServerIPv4().String(),
		ServerPort:        evetest.GetImageServerPort(),
	}, downloadedVolumeSize)
	clearVolUUID := devConfig.AddBlankVolume("konvert-volmig-clear", clearVolumeSize, true)
	appConfig := testAppConfig("konvert-volmig-app", niUUID)
	appConfig.Mounts = []evetest.MountConfig{
		{VolumeUUID: dataVolUUID, MountDir: dataMountDir},
		{VolumeUUID: dlVolUUID, MountDir: downloadedMountDir},
		{VolumeUUID: clearVolUUID, MountDir: clearMountDir},
	}
	appUUID := devConfig.AddApplication(appConfig)
	device.ApplyConfig(devConfig, false, false)
	assertVolumeCreated(t, device, dlVolUUID, 10*time.Minute)
	assertAppReady(t, device, appUUID, 20*time.Minute)

	log.Infof("writing a marker into each volume")
	marker := perRunMarker(volumeMarker)
	dlMarker := perRunMarker(downloadedMarker)
	clrMarker := perRunMarker(clearMarker)
	writeVolumeMarker(t, device, appUUID, dataMountDir, marker)
	writeVolumeMarker(t, device, appUUID, downloadedMountDir, dlMarker)
	writeVolumeMarker(t, device, appUUID, clearMountDir, clrMarker)

	var vmUUID uuid.UUID
	var vmMarker string
	if withVM {
		log.Infof("deploying the VM app")
		vmUUID = addTestVM(t, device, devConfig, "konvert-volmig-vm", niUUID)
		device.ApplyConfig(devConfig, false, false)
		assertVMReady(t, device, vmUUID, 20*time.Minute)
		vmMarker = perRunMarker(vmMarkerBase)
		writeVMMarker(t, device, vmUUID, vmMarker)
	}
	dumpAppNetwork(device, "before the conversion (working)")
	evetest.Checkpoint("marker-written")

	// Phase 3. The app and its volumes stay in the configuration across the
	// conversion; that is the whole point.
	conversionOK := false
	defer func() {
		if !conversionOK {
			dumpConversionFailure(device)
		}
	}()
	log.Infof("converting to EVE-K with the app and volumes in place")
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKubevirt,
		evetest.BaseOSDatastoreHTTP, true, false, conversionUpgradeTimeout)
	conversionOK = true
	evetest.Checkpoint("conversion-complete")

	// Phase 4. Unchanged rather than grown: there was nothing to repartition,
	// so a layout that moved would mean the conversion did work it should have
	// skipped.
	log.Infof("the layout must be unchanged")
	assertGeometryUnchanged(t, device, startGeometry)
	assertFinalEVEKLayout(t, device)

	appOK := false
	defer func() {
		if !appOK {
			dumpClusterStorage(device)
			dumpAppNetwork(device, "after the conversion (app FAILED)")
		}
	}()
	waitClusterStorageReady(t, device)
	assertVolumeCarriedIntoPVC(t, device, dataVolUUID)
	assertVolumeCarriedIntoPVC(t, device, dlVolUUID)
	assertVolumeCarriedIntoPVC(t, device, clearVolUUID)
	assertAppReady(t, device, appUUID, appRunningAfterSwitchTimeout)
	if withVM {
		assertVMReady(t, device, vmUUID, appRunningAfterSwitchTimeout)
	}
	appOK = true
	evetest.Checkpoint("app-back")

	// Phase 5.
	log.Infof("every marker must still be in its volume")
	assertVolumeMarker(t, device, appUUID, marker)
	assertVolumeMarker(t, device, appUUID, dlMarker)
	assertVolumeMarker(t, device, appUUID, clrMarker)
	if withVM {
		assertVMMarker(t, device, vmUUID, vmMarker)
	}
	assertNothingDownloadedThisBoot(t, device)
	evetest.Checkpoint("volume-survived")

	// Phase 6.
	if rebootBeforeDrain {
		log.Infof("the carried-over kvm volumes must still be held")
		assertCarriedVolumesHeld(t, device, persistFS, dataVolUUID, dlVolUUID, clearVolUUID)
		bootID := rebootEVEK(t, device, appUUID)
		waitClusterStorageReady(t, device)
		assertAppReady(t, device, appUUID, appRunningAfterSwitchTimeout)
		if withVM {
			assertVMReady(t, device, vmUUID, appRunningAfterSwitchTimeout)
		}
		assertAppFreshBoot(t, device, appUUID, bootID)
		assertVolumeMarker(t, device, appUUID, marker)
		assertVolumeMarker(t, device, appUUID, dlMarker)
		assertVolumeMarker(t, device, appUUID, clrMarker)
		if withVM {
			assertVMMarker(t, device, vmUUID, vmMarker)
		}
		log.Infof("the carried-over kvm volumes must be held across the reboot")
		assertCarriedVolumesHeld(t, device, persistFS, dataVolUUID, dlVolUUID, clearVolUUID)
		evetest.Checkpoint("evek-reboot-reasserted")

		log.Infof("restoring timer.gc.vdisk, and rebooting so the gc ticker uses it")
		restore := shortBaseImageCooldown()
		restore.SetGlobalValueInt(pillartypes.VdiskGCTime, pillartypes.HourInSec)
		devConfig.SetConfigProperties(restore)
		device.ApplyConfig(devConfig, true, true)
		rebootEVEK(t, device, appUUID)
		waitClusterStorageReady(t, device)
		assertAppReady(t, device, appUUID, appRunningAfterSwitchTimeout)
	}

	// Phase 7.
	log.Infof("the carried-over kvm volumes must be removed")
	assertCarriedVolumesRemoved(t, device, persistFS, dataVolUUID, dlVolUUID, clearVolUUID)
	evetest.Checkpoint("carried-volumes-removed")
}

// rebootBeforeDrainParameter declares whether the test reboots EVE-K while
// the carried-over kvm volumes are still held.
func rebootBeforeDrainParameter() evetest.TestParameterDefinition {
	return evetest.TestParameterDefinition{
		Key:          rebootBeforeDrainParamKey,
		DefaultValue: false,
		Description: evetest.TestParameterDescription{
			Summary: "Hold off the drain and reboot EVE-K while the carried-over kvm volumes remain",
			Default: "false",
		},
	}
}

// persistFilesystemParameter declares the /persist filesystem axis.
func persistFilesystemParameter() evetest.TestParameterDefinition {
	return evetest.TestParameterDefinition{
		Key:          persistFilesystemParamKey,
		DefaultValue: "ext4",
		Description: evetest.TestParameterDescription{
			Summary:       "Filesystem of /persist",
			Default:       "ext4",
			AllowedValues: "ext4|zfs",
		},
	}
}

// assertCarriedVolumesHeld asserts each given volume is still on /persist in
// its EVE-kvm form. On ZFS it also asserts each one's zvol has a device node:
// csihandler reads a carried zvol through that node, and one in the parked
// vault has it only while that vault's key is loaded.
func assertCarriedVolumesHeld(t Gomega, device *evetest.EdgeDevice, persistFS string,
	volumeUUIDs ...fmt.Stringer) {
	script := "ls /persist/vault/volumes-kvm /persist/clear/volumes 2>/dev/null; echo LISTED"
	if persistFS == "zfs" {
		script = fmt.Sprintf(`eve exec pillar sh -c 'for d in $(zfs list -H -o name -t volume -r persist/clear %s 2>/dev/null); do if [ -b /dev/zvol/$d ]; then echo "$d node"; else echo "$d nonode"; fi; done; echo LISTED'`,
			vaultBackupDataset)
	}
	t.Eventually(func(g Gomega) {
		out, _ := runEVE(device, script)
		g.Expect(out).To(ContainSubstring("LISTED"), "the listing did not run:\n%s", out)
		for _, id := range volumeUUIDs {
			found := false
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, id.String()) &&
					(persistFS != "zfs" || strings.HasSuffix(line, " node")) {
					found = true
				}
			}
			g.Expect(found).To(BeTrue(),
				"no held kvm copy of volume %s (with a device node on ZFS):\n%s", id, out)
		}
	}, carriedHeldTimeout, 15*time.Second).Should(Succeed())
}

// assertCarriedVolumesRemoved asserts none of the given volumes is left on
// /persist in its EVE-kvm form: no file in the ext4 holding or clear
// directories, no zvol on ZFS, and on ZFS no parked kvm vault.
func assertCarriedVolumesRemoved(t Gomega, device *evetest.EdgeDevice, persistFS string,
	volumeUUIDs ...fmt.Stringer) {
	// Each listing names something that is always there, so a listing that did
	// not run cannot pass for one that found nothing.
	script := "ls -d /persist/clear/volumes; ls /persist/vault/volumes-kvm /persist/clear/volumes 2>/dev/null"
	alwaysListed := "/persist/clear/volumes"
	if persistFS == "zfs" {
		script = "eve exec pillar sh -c 'for d in persist/clear " + vaultBackupDataset +
			"; do zfs list -H -o name -r $d 2>/dev/null; done'"
		alwaysListed = "persist/clear"
	}
	t.Eventually(func(g Gomega) {
		out, _ := runEVE(device, script)
		g.Expect(out).To(ContainSubstring(alwaysListed), "the listing did not run:\n%s", out)
		for _, id := range volumeUUIDs {
			g.Expect(out).NotTo(ContainSubstring(id.String()),
				"a kvm copy of volume %s remains:\n%s", id, out)
		}
		if persistFS == "zfs" {
			g.Expect(strings.Fields(out)).NotTo(ContainElement(vaultBackupDataset),
				"the parked kvm vault remains:\n%s", out)
		}
	}, carriedCleanupTimeout, 30*time.Second).Should(Succeed())
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
