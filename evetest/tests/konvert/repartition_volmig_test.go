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
	// volmigDataVolMiB is the app data volume this test carries across the
	// repartition. Small on purpose: what is being tested is that the volume
	// survives, and above roughly 256 MiB EVE-K's CSI path wedges provisioning
	// it (see TestKvmToKRepartitionAppVolume), which would mask the result.
	volmigDataVolMiB = 256
	// volmigMarker is written into the volume before the conversion and looked
	// for afterwards. Distinctive enough to be found by scanning a raw device.
	volmigMarker = "KONVERT-REPARTITION-VOLMIG-MARKER-4d17ba90"
)

// TestKvmToKRepartitionVolmig drives the in-field boot-disk conversion with an
// application and its data volume kept in place across it, and asserts the
// volume's contents come back.
//
// The conversion is the same three hops TestKvmToKRepartitionNoVolmig drives --
// a released small-geometry EVE-kvm image, a kvm→kvm hop that lands the
// conversion code, then the kvm→k hop whose cross-flavor seam arms the offline
// shrink -- and the difference is the whole point: that test deletes the app
// first, so the repartition runs with nothing to carry, while here the volume is
// present when the boot disk is rewritten and has to be relocated and then
// picked up by EVE-K's storage. It takes an EVE that can convert with a volume
// on the device; where the cross-flavor gate still refuses one, the sibling test
// is the route that works.
//
// The volume is small and /persist is not filled, so the shrink has little to
// relocate and this says only that a carried volume survives the conversion.
// Whether the contents survive being relocated out of the region the shrink
// evacuates -- and an interruption while that happens -- is
// TestKvmToKRepartitionAppVolume's subject.
//
// The marker is read back off the volume's raw block device rather than from
// where it was written, because on EVE-K a container's data volume is not
// auto-mounted at its MountDir (lf-edge/eve#6145) and a mount-based check would
// report the data lost when the volume is merely unmounted.
//
// Phases:
//  1. Baseline: the boot disk is on the released layout.
//  2. kvm→kvm hop: the geometry must be unchanged, and the pre-flight check must
//     now decide a shrink.
//  3. Settle the vault to a local TPM unlock, which is the state the conversion
//     has to preserve.
//  4. Deploy the app with a data volume and write a marker into it.
//  5. kvm→k hop with the app and volume in place: the offline shrink runs.
//  6. Assert the geometry converted and the repartition did not cost the seal.
//  7. Assert the app comes back and the marker is still in its volume.
//
// Needs an EVE build carrying the conversion (lf-edge/eve#6036, #6063).
func TestKvmToKRepartitionVolmig(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	defineSharedParameters(volmigRepartitionParameterDefinitions()...)
	p := resolveDeviceParams(t)
	p = raiseFloorsForCarriedVolume(t, p)
	requirePinnedInitialVersion(t, p)
	dataVolMiB := evetest.GetTestParameter[uint32](dataVolMiBParamKey)

	device := setupDevice(t, p, evetest.FilesystemEXT4, nil, provisionPolicy())
	log := evetest.Logger()

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	applyMgmtNetwork(device, devConfig)
	devConfig.SetConfigProperties(shortBaseImageCooldown())
	device.ApplyConfig(devConfig, true, true)

	// Phase 1.
	log.Infof("baseline: the boot disk must be on the released layout")
	smallGeometry := assertSmallGeometry(t, device)
	log.Infof("baseline geometry: %s", smallGeometry)
	evetest.Checkpoint("baseline-small")

	// Phase 2.
	log.Infof("kvm→kvm hop: landing the conversion code at %s", p.targetVersion)
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKVM,
		evetest.BaseOSDatastoreHTTP, true, false, conversionUpgradeTimeout)
	log.Infof("the hop must not have moved the geometry")
	assertSmallGeometry(t, device)
	log.Infof("the pre-flight check must decide %q", decisionShrink)
	assertCheckDecision(t, device, decisionShrink)
	evetest.Checkpoint("conversion-code-landed")

	// Phase 3.
	log.Infof("settling the vault on a local TPM unlock")
	settleVaultLocal(t, device)
	evetest.Checkpoint("vault-settled")

	// Phase 4. Encrypted, not clear text: the conversion takes the vault across
	// a transition of its own, so the volume has to exercise that path.
	log.Infof("deploying the app with a %d MiB data volume", dataVolMiB)
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "eth0",
	})
	dataVolUUID := devConfig.AddBlankVolume("konvert-repartition-volmig-data",
		uint64(dataVolMiB)*evetest.MiB, false)
	appUUID := addTestAppWithVolume(devConfig, "konvert-repartition-volmig-app",
		niUUID, dataVolUUID)
	device.ApplyConfig(devConfig, false, false)
	assertAppReady(t, device, appUUID, 15*time.Minute)

	log.Infof("writing a marker into the data volume")
	writeVolumeMarker(t, device, appUUID, dataMountDir, volmigMarker)
	dumpAppNetwork(device, "before the conversion (working)")
	evetest.Checkpoint("marker-written")

	// Phase 5.
	conversionOK := false
	defer func() {
		if !conversionOK {
			dumpConversionFailure(device)
		}
	}()
	// The offline repartition boots once more than an upgrade does: its
	// intermediate resize boot is invisible to the controller, so the audit at
	// teardown would see one reboot the upgrade did not account for. Declared
	// before the update that causes it, so the declaration cannot race it.
	device.ExpectReboots(1)
	log.Infof("kvm→k hop with the app and volume in place: arming the offline shrink")
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKubevirt,
		evetest.BaseOSDatastoreHTTP, true, false, conversionUpgradeTimeout)
	conversionOK = true
	evetest.Checkpoint("conversion-complete")

	// Phase 6.
	log.Infof("asserting the boot disk reached the EVE-K layout via the shrink")
	assertLargeGeometry(t, device, smallGeometry, p3MustShrink)
	log.Infof("asserting the repartition preserved the TPM seal")
	assertSealSurvivedRepartition(t, device)
	evetest.Checkpoint("geometry-converted")

	// Phase 7.
	appOK := false
	defer func() {
		if !appOK {
			dumpClusterStorage(device)
			dumpAppNetwork(device, "after the conversion (app FAILED)")
		}
	}()
	waitClusterStorageReady(t, device)
	assertAppReady(t, device, appUUID, appRunningAfterRepartitionTimeout)
	appOK = true

	log.Infof("the marker must still be in the carried volume")
	assertVolumeMarker(t, device, appUUID, volmigMarker)
	evetest.Checkpoint("volume-survived")

	// The volume outlives the app and blocks its own delete while a VolumeRef
	// still points at it, so the app goes first. Left behind, both would be on
	// the device the next test in the suite is handed.
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)
	devConfig.DeleteVolume(dataVolUUID)
	device.ApplyConfig(devConfig, false, false)
}

// volmigRepartitionParameterDefinitions declares the axes this test adds.
func volmigRepartitionParameterDefinitions() []evetest.TestParameterDefinition {
	return []evetest.TestParameterDefinition{
		useInstallerParameter(),
		{
			Key:          dataVolMiBParamKey,
			DefaultValue: uint32(volmigDataVolMiB),
			Description: evetest.TestParameterDescription{
				Summary: "App data-volume size in MiB carried across the conversion",
				Default: "256",
			},
		},
	}
}
