// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"

	"github.com/lf-edge/eve/evetest"
)

// The disk layouts the grow route is exercised on.
const (
	// topologyTwoDiskExt4 is an ext4 /persist on a disk of its own, and a boot
	// disk with no P3.
	topologyTwoDiskExt4 = "two-disk-ext4"
	// topologyTwoDiskZFS is the same, with the persist pool on the extra disk.
	topologyTwoDiskZFS = "two-disk-zfs"
	// topologyTwoDiskZFSWhole is the persist pool on the whole extra disk, as
	// the installer lays out a multi-disk ZFS install, and no P3 on any disk.
	topologyTwoDiskZFSWhole = "two-disk-zfs-whole"
	// topologyZFSTail is a ZFS P3 on the boot disk, with a free tail past it.
	topologyZFSTail = "zfs-tail"
	// topologyExt4Tail is an ext4 P3 with a free tail past it, the layout
	// TestKvmToKRepartitionNoVolmig's grow variant runs on.
	topologyExt4Tail = "ext4-tail"

	// zfsTailBootMiB is the boot disk the zfs-tail layout starts on
	// (prep-kvm-to-k-topology.sh ZFS_GROW_BASE_MB). A ZFS P3 never grows into
	// a tail added after it is created, so this base alone sets the pool size;
	// the 24 GiB tail that brings it to bootDiskMiB clears freeTailNeeded and
	// the conversion's own growth.
	zfsTailBootMiB = 40960

	// topologyDataVolMiB is the data volume carried by default, at the size
	// TestKvmToKRepartitionAppVolume uses.
	topologyDataVolMiB = appVolumeDataVolMiB
)

// diskTopology is how one layout is built and what the conversion must do to
// the boot disk's P3 on it.
type diskTopology struct {
	filesystem evetest.Filesystem
	bootMiB    uint32
	extraDisks []uint64
	// persistOnExtraDisk moves /persist to the extra disk, which is what frees
	// the boot disk's tail; otherwise the boot disk is grown to leave one.
	persistOnExtraDisk bool
	wantP3             p3Expectation
	// wholeDiskPool builds the persist pool on the whole extra disk, from a
	// device brought up on ext4; see buildWholeDiskPersistPool.
	wholeDiskPool bool
}

// setupFilesystem is the /persist filesystem the device is brought up on.
func (d diskTopology) setupFilesystem() evetest.Filesystem {
	if d.wholeDiskPool {
		return evetest.FilesystemEXT4
	}
	return d.filesystem
}

var diskTopologies = map[string]diskTopology{
	topologyTwoDiskExt4: {evetest.FilesystemEXT4, twodiskBootMiB,
		[]uint64{twodiskExtraDiskBytes}, true, p3MustBeAbsent, false},
	topologyTwoDiskZFS: {evetest.FilesystemZFS, twodiskBootMiB,
		[]uint64{twodiskExtraDiskBytes}, true, p3MustBeAbsent, false},
	topologyTwoDiskZFSWhole: {evetest.FilesystemZFS, twodiskBootMiB,
		[]uint64{twodiskExtraDiskBytes}, true, p3MustBeAbsent, true},
	topologyZFSTail: {evetest.FilesystemZFS, zfsTailBootMiB, nil, false,
		p3MustBeUnchanged, false},
	topologyExt4Tail: {evetest.FilesystemEXT4, splitBootDiskMiB, nil, false,
		p3MustBeUnchanged, false},
}

// TestKvmToKRepartitionTopology drives the in-field boot-disk conversion along
// the grow route on the disk layouts other than a single ext4 disk, and by
// default with an app data volume carried across it.
//
// The grow route leaves /persist alone, so it is the route a device with app
// volumes may take: the cross-flavor gate refuses only a conversion that would
// shrink /persist. Where the free space comes from is the layout: a /persist on
// a second disk leaves the boot disk's whole tail free, and a boot disk larger
// than its partitions leaves the space past them.
//
// The conversion is the same three hops as TestKvmToKRepartitionNoVolmig: a
// released small-geometry EVE-kvm image, a kvm→kvm hop that lands the
// conversion code, then the kvm→k hop that arms the offline grow.
//
// WITH_APP_VOLUME (default true) keeps a volverify app with a data volume on the
// device through the conversion and judges the volume twice afterwards: on the
// device, before EVE-K's storage takes it over, and from inside the app on
// EVE-K. Since a grow relocates no /persist data, a volume that comes back
// blank is data loss here. WITH_APP_VOLUME=false deletes the app before the
// conversion and redeploys it afterwards, asserting its blobs were reused.
//
// Phases:
//  1. Build the layout: move /persist to the extra disk (a P3 there, or a pool
//     on the whole disk), or grow the boot disk to leave a tail.
//  2. Baseline: the boot disk is on the released layout, has a free tail, and
//     /persist is the expected filesystem.
//  3. kvm→kvm hop: the geometry must be unchanged, and the pre-flight check must
//     now decide a grow.
//  4. Settle the vault to a local TPM unlock.
//  5. Deploy the app: with a volume filled with the volverify pattern, or
//     without one and then deleted.
//  6. kvm→k hop: the conversion runs the offline grow.
//  7. Assert the geometry, P3 unchanged or absent, and the TPM seal.
//  8. Judge the volume, or redeploy the app.
//  9. (REBOOT_AFTER_CONVERSION) Reboot EVE-K and repeat phase 8's volume
//     judgment or app gates, on a fresh guest boot.
//
// Needs an EVE build carrying the conversion (lf-edge/eve#6036, #6063). With
// WITH_APP_VOLUME it also needs lf-edge/eve#6658, which lets a conversion that
// does not shrink /persist through with volumes present; master refuses any
// kvm→k update while volumes exist.
func TestKvmToKRepartitionTopology(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()
	requireFlavorAwareTransport(t)

	defineSharedParameters(topologyParameterDefinitions()...)
	p := resolveDeviceParams(t)
	requirePinnedInitialVersion(t, p)
	topologyName := evetest.GetTestParameter[string](diskTopologyParamKey)
	topology, ok := diskTopologies[topologyName]
	t.Expect(ok).To(BeTrue(), "%s must be one of %q, %q, %q, %q or %q",
		diskTopologyParamKey, topologyTwoDiskExt4, topologyTwoDiskZFS,
		topologyTwoDiskZFSWhole, topologyZFSTail, topologyExt4Tail)
	withVolume := evetest.GetTestParameter[bool](withAppVolumeParamKey)
	if withVolume {
		p = raiseFloorsForCarriedVolume(t, p)
	}
	if evetest.GetDiskSizeMiBParameterValue() == 0 {
		p.diskMiB = topology.bootMiB
	}

	dataVolMiB := evetest.GetTestParameter[uint32](dataVolMiBParamKey)
	seed := evetest.GetTestParameter[uint64](seedParamKey)
	ops := evetest.GetTestParameter[uint64](opsParamKey)
	image := evetest.GetTestParameter[string](volverifyImageParamKey)
	args := volverifyArgs(dataVolMiB, seed, ops)

	device := setupDevice(t, p, topology.setupFilesystem(), topology.extraDisks,
		evetest.CreateFromScratchWithLiveImage,
		evetest.RequireCapabilities{
			Capabilities: []api.Capability{api.Capability_CAPABILITY_EDIT_DEVICE_DISK},
		})
	log := evetest.Logger()
	log.Infof("layout %s, app volume %t", topologyName, withVolume)

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	applyMgmtNetwork(device, devConfig)
	devConfig.SetConfigProperties(shortBaseImageCooldown())
	device.ApplyConfig(devConfig, true, true)

	// Phase 1.
	switch {
	case topology.wholeDiskPool:
		buildWholeDiskPersistPool(t, device, devConfig)
	case topology.persistOnExtraDisk:
		movePersistToExtraDisk(t, device, devConfig, topology.filesystem)
	default:
		growBootDiskTail(t, device, bootDiskMiB)
	}

	// Phase 2.
	log.Infof("baseline: the boot disk must be on the released layout")
	smallGeometry := assertSmallGeometry(t, device)
	log.Infof("baseline geometry: %s", smallGeometry)
	assertFreeTail(t, device)
	assertPersistType(t, device, persistTypeName(topology.filesystem))
	assertPersistRoomForLonghorn(t, device)
	evetest.Checkpoint("baseline-small")

	// Phase 3.
	conversionOK := false
	defer func() {
		if !conversionOK {
			dumpConversionFailure(device)
		}
	}()
	log.Infof("kvm→kvm hop: landing the conversion code at %s", p.targetVersion)
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKVM,
		evetest.BaseOSDatastoreHTTP, true, false, conversionUpgradeTimeout)
	kvmHopVersion := readRunningVersion(t, device)
	log.Infof("the hop must not have moved the geometry")
	assertSmallGeometry(t, device)
	log.Infof("the pre-flight check must decide %q", decisionGrow)
	assertCheckDecision(t, device, decisionGrow)
	evetest.Checkpoint("conversion-code-landed")

	// Phase 4.
	log.Infof("settling the vault on a local TPM unlock")
	settled := settleVaultLocal(t, device)
	evetest.Checkpoint("vault-settled")

	// Phase 5.
	var appUUID, niUUID, dataVolUUID uuid.UUID
	committed := -1
	if withVolume {
		log.Infof("deploying the volverify app with a %d MiB data volume", dataVolMiB)
		niUUID = devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
			DisplayName: "switch-ni",
			Port:        "eth0",
		})
		// Encrypted, not clear text: the conversion takes the vault across a
		// transition of its own, so the volume has to exercise that path.
		dataVolUUID = devConfig.AddBlankVolume("konvert-topology-data",
			uint64(dataVolMiB)*evetest.MiB, false)
		appUUID = addVolverifyApp(devConfig, "konvert-topology-app", image,
			niUUID, dataVolUUID)
		device.ApplyConfig(devConfig, false, false)
		assertAppReady(t, device, appUUID, 15*time.Minute)
		dumpAppNetwork(device, "before the conversion (working)")

		log.Infof("pre-conversion: filling the data volume with the volverify pattern")
		committed = writeVolverifyPattern(t, device, appUUID, args)
		log.Infof("volume filled through committed op %d", committed)
		evetest.Checkpoint("volume-filled")
	} else {
		niUUID = deployAppThenDeleteKeepingBlobs(t, device, devConfig, appNetworkSwitch)
	}
	// Recorded against no boundary, which reads as SKIP: a grow relocates none.
	criticalsBefore := recordCriticalBlocks(device, "pre-conversion", 0)

	// Phase 6.
	// The offline repartition boots once more than an upgrade does: its
	// intermediate resize boot is invisible to the controller, so the audit at
	// teardown would see one reboot the upgrade did not account for. Declared
	// before the update that causes it, so the declaration cannot race it.
	device.ExpectReboots(1)
	log.Infof("kvm→k hop: arming the offline grow")
	stopStates := logConversionStates(device)
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKubevirt,
		evetest.BaseOSDatastoreHTTP, true, false, conversionUpgradeTimeout)
	stopStates()
	conversionOK = true
	evetest.Checkpoint("conversion-complete")

	// Phase 7.
	log.Infof("asserting the boot disk reached the EVE-K layout via the grow")
	assertLargeGeometry(t, device, smallGeometry, topology.wantP3)
	assertPersistType(t, device, persistTypeName(topology.filesystem))
	if topology.filesystem == evetest.FilesystemZFS {
		log.Infof("asserting the ZFS vault was migrated to a zvol")
		assertZFSVaultMigrated(t, device)
	}
	evetest.Checkpoint("geometry-converted")
	recordResizeFault(device)

	integrity := logCriticalRelocation(device, criticalsBefore)
	captureOnConsoleAlarm(device)

	log.Infof("asserting the repartition preserved the TPM seal")
	assertSealSurvivedRepartition(t, device, kvmHopVersion, settled)
	evetest.Checkpoint("seal-preserved")

	// Phase 8.
	if !withVolume {
		appUUID = redeployAssertingBlobReuse(t, device, devConfig, niUUID, integrity.recreated)
		// Phase 9.
		if rebootAfterConversionRequested() {
			rebootAndReassertEVEK(t, device, appUUID)
		}
		return
	}
	// Before EVE-K's storage imports the volume: this is the reading that
	// survives an app that never comes back.
	assertVolumeCarriedIntoPVC(t, device, dataVolUUID)
	assertRelocatedVolumeIntact(t, device, dataVolMiB, seed, ops, committed, false)
	state := verifyVolumeFromGuest(t, device, appUUID, dataVolMiB, args, committed, 0)
	t.Expect(state).NotTo(Equal(volumeStateBlank),
		"the data volume came back blank after a grow, which relocates no /persist data")
	logPartitionState(device)

	// Phase 9.
	if rebootAfterConversionRequested() {
		bootID := rebootEVEK(t, device, appUUID)
		state = verifyVolumeFromGuest(t, device, appUUID, dataVolMiB, args, committed, 0)
		t.Expect(state).NotTo(Equal(volumeStateBlank),
			"the data volume came back blank after rebooting EVE-K")
		assertAppFreshBoot(t, device, appUUID, bootID)
		evetest.Checkpoint("evek-reboot-reasserted")
	}

	// The volume outlives the app and blocks its own delete while a VolumeRef
	// still points at it, so the app goes first.
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)
	devConfig.DeleteVolume(dataVolUUID)
	device.ApplyConfig(devConfig, false, false)
}

// topologyParameterDefinitions declares the axes this test adds.
func topologyParameterDefinitions() []evetest.TestParameterDefinition {
	return append(volverifyParameterDefinitions(),
		evetest.TestParameterDefinition{
			Key:          diskTopologyParamKey,
			DefaultValue: topologyTwoDiskExt4,
			Description: evetest.TestParameterDescription{
				Summary:       "Disk layout the conversion grows on",
				Default:       "two-disk-ext4",
				AllowedValues: "two-disk-ext4|two-disk-zfs|two-disk-zfs-whole|zfs-tail|ext4-tail",
			},
		},
		evetest.TestParameterDefinition{
			Key:          withAppVolumeParamKey,
			DefaultValue: true,
			Description: evetest.TestParameterDescription{
				Summary: "Carry an app data volume across the conversion; false deletes the app first",
				Default: "true",
			},
		},
		evetest.TestParameterDefinition{
			Key:          dataVolMiBParamKey,
			DefaultValue: uint32(topologyDataVolMiB),
			Description: evetest.TestParameterDescription{
				Summary: "App data-volume size in MiB carried across the conversion",
				Default: "2048",
			},
		},
		rebootAfterConversionParameter(),
	)
}
