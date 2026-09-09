// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"

	"github.com/lf-edge/eve/evetest"
)

// deferContentDeleteSeconds keeps a deleted app's blobs alive across the
// conversion. Without it EVE reclaims them as soon as the app referencing them
// goes away, and the redeploy afterwards measures a fresh download rather than
// the reuse the test is about.
const deferContentDeleteSeconds = 24 * 60 * 60

// TestKvmToKRepartition drives the in-field boot-disk conversion end to end:
// a released small-geometry EVE-kvm image, a kvm→kvm hop that lands the
// conversion code without moving the geometry, and then the kvm→k hop whose
// cross-flavor seam arms the offline repartition.
//
// Three hops rather than one because that is the shape of the real thing. A
// device in the field is on an old release that has no conversion code, so the
// code has to arrive first, on an image of the same flavor that leaves the disk
// alone; only then can the flavor change, and it is the flavor change that
// triggers the repartition. Going straight to EVE-K would test an upgrade path
// no fielded device can take.
//
// The route the conversion takes to free the space is the axis:
//
//   - EXPECT_DECISION=shrink -- the boot disk is full, so /persist must shrink to
//     make room. This is the field layout, and the harder path: resize2fs has to
//     relocate live blocks, which is where data can be lost.
//   - EXPECT_DECISION=grow -- the boot disk has unallocated space past the last
//     partition, so the new partitions grow into it and /persist is untouched.
//
// Both routes end at the same 2+2+10+10 EVE-K layout, which is why the decision
// is asserted before the conversion: afterwards the geometry alone cannot say
// which way it got there. The P3 assertion afterwards is the second half of that
// -- shrunk for one route, untouched for the other.
//
// Phases:
//  1. Baseline: the boot disk is on the released layout, and (grow only) has a
//     free tail to grow into.
//  2. kvm→kvm hop: the geometry must be unchanged, and the pre-flight check must
//     now decide the expected route.
//  3. Settle the vault to a local TPM unlock, so the seal assertion afterwards
//     has a settled boot to look at.
//  4. (shrink only) Fill /persist so the shrink has real blocks to relocate.
//  5. Deploy an app, confirm it works, then delete it with the content-delete
//     timer stretched so its blobs outlive the conversion.
//  6. kvm→k hop: the conversion runs offline across reboots.
//  7. Assert the geometry, and that the repartition did not cost the TPM seal.
//  8. Free the fill, which the shrink has now made into most of a smaller
//     /persist, so EVE-K's storage has room to come up.
//  9. Redeploy the same app and assert it downloaded nothing.
//
// Needs an EVE build carrying the conversion (lf-edge/eve#6036, #6063); on a
// stock build the kvm→k hop is refused outright.
func TestKvmToKRepartition(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	defineSharedParameters(repartitionParameterDefinitions()...)
	p := resolveDeviceParams(t)
	requirePinnedInitialVersion(t, p)
	decision := evetest.GetTestParameter[string](expectDecisionParamKey)
	fillGiB := int(evetest.GetTestParameter[uint32](fillPersistGiBParamKey))
	t.Expect(decision).To(BeElementOf(decisionShrink, decisionGrow),
		"%s must be %q or %q", expectDecisionParamKey, decisionShrink, decisionGrow)

	// The grow route needs unallocated space past the last partition, and EVE's
	// image generator sizes the partitions to fill whatever disk it is given --
	// so the device is built on a smaller disk and the tail is added afterwards.
	// That also makes the disk edit a requirement only this route declares.
	var requirements []evetest.Requirement
	diskParams := p
	if decision == decisionGrow {
		diskParams.diskMiB = splitBootDiskMiB
		requirements = append(requirements, evetest.RequireCapabilities{
			Capabilities: []api.Capability{api.Capability_CAPABILITY_EDIT_DEVICE_DISK},
		})
	}

	device := setupDevice(t, diskParams, evetest.FilesystemEXT4, nil,
		evetest.CreateFromScratchWithLiveImage, requirements...)
	log := evetest.Logger()

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	applyMgmtNetwork(device, devConfig)
	devConfig.SetConfigProperties(shortBaseImageCooldown())
	device.ApplyConfig(devConfig, true, true)

	if decision == decisionGrow {
		growBootDiskTail(t, device, bootDiskMiB)
	}

	// Phase 1.
	log.Infof("baseline: the boot disk must be on the released layout")
	smallGeometry := assertSmallGeometry(t, device)
	log.Infof("baseline geometry: %s", smallGeometry)
	if decision == decisionGrow {
		log.Infof("baseline: the boot disk must have a free tail to grow into")
		assertFreeTail(t, device)
	}
	evetest.Checkpoint("baseline-small")

	// Phase 2.
	log.Infof("kvm→kvm hop: landing the conversion code at %s", p.targetVersion)
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKVM,
		evetest.BaseOSDatastoreHTTP, true, false)
	log.Infof("the hop must not have moved the geometry")
	assertSmallGeometry(t, device)
	log.Infof("the pre-flight check must decide %q", decision)
	assertCheckDecision(t, device, decision)
	evetest.Checkpoint("conversion-code-landed")

	// Phase 3.
	// Also the pre-conversion half of the seal check: this establishes live that
	// the last boot before the conversion unsealed from the device's own TPM.
	log.Infof("settling the vault on a local TPM unlock")
	settleVaultLocal(t, device)
	evetest.Checkpoint("vault-settled")

	// Phase 4.
	if decision == decisionShrink {
		fillPersist(t, device, fillGiB)
		evetest.Checkpoint("persist-filled")
	}

	// Phase 5.
	log.Infof("deploying the app before the conversion")
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "eth0",
	})
	appUUID := addTestApp(devConfig, "konvert-repartition-app", niUUID)
	device.ApplyConfig(devConfig, false, false)
	assertAppReady(t, device, appUUID, 15*time.Minute)
	dumpAppNetwork(device, "before the conversion (working)")

	log.Infof("stretching the deferred content delete past the conversion")
	props := shortBaseImageCooldown()
	props.SetGlobalValueInt(pillartypes.DeferContentDelete, deferContentDeleteSeconds)
	devConfig.SetConfigProperties(props)
	device.ApplyConfig(devConfig, true, true)

	// The conversion's cross-flavor gate refuses to run while a volume exists,
	// so the app goes first; its blobs stay behind under the stretched timer,
	// and its network instance stays in the configuration to be redeployed onto.
	log.Infof("deleting the app, keeping its network and blobs")
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, true, true)
	assertNoLiveVolumes(t, device)
	evetest.Checkpoint("app-deleted")

	// Phase 6.
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
	log.Infof("kvm→k hop: arming the offline %s", decision)
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKubevirt,
		evetest.BaseOSDatastoreHTTP, true, false)
	conversionOK = true
	evetest.Checkpoint("conversion-complete")

	// Phase 7.
	wantP3 := p3MustShrink
	if decision == decisionGrow {
		wantP3 = p3MustBeUnchanged
	}
	log.Infof("asserting the boot disk reached the EVE-K layout via the %s route", decision)
	assertLargeGeometry(t, device, smallGeometry, wantP3)
	evetest.Checkpoint("geometry-converted")

	log.Infof("asserting the repartition preserved the TPM seal")
	assertSealSurvivedRepartition(t, device)
	evetest.Checkpoint("seal-preserved")

	// The fill has done its job now that the resize is over, and it has to go
	// before EVE-K brings its storage up: the shrink left /persist smaller, so
	// what was a third of it is now nearly all of it, and Longhorn reports
	// unhealthy storage forever rather than place a replica with no room.
	if decision == decisionShrink {
		freePersistFill(t, device)
		evetest.Checkpoint("fill-freed")
	}

	// Phase 8. The snapshot is taken before the redeploy and after the
	// conversion's last reboot, so both readings belong to the same boot.
	beforeBytes := snapshotDownloaderBytes(t, device)
	// Redeployed onto the network instance the device already has. Only the
	// app was deleted; adding a second switch instance on the same port here
	// would leave two of them bound to eth0, and the app never starts.
	log.Infof("redeploying the app on EVE-K")
	newAppUUID := addTestApp(devConfig, "konvert-repartition-app", niUUID)
	device.ApplyConfig(devConfig, false, false)

	appOK := false
	defer func() {
		if !appOK {
			dumpClusterStorage(device)
			dumpAppNetwork(device, "after the conversion (app FAILED)")
		}
	}()
	waitClusterStorageReady(t, device)
	assertAppReady(t, device, newAppUUID, appRunningAfterRepartitionTimeout)
	appOK = true
	assertBlobsReused(t, device, beforeBytes)
	evetest.Checkpoint("app-redeployed")

	// Leave the collector as it was found, so a device reused by the next test
	// in the suite is not holding blobs for a day.
	devConfig.SetConfigProperties(shortBaseImageCooldown())
	device.ApplyConfig(devConfig, true, true)
}

// repartitionParameterDefinitions declares the axes this test adds.
func repartitionParameterDefinitions() []evetest.TestParameterDefinition {
	return []evetest.TestParameterDefinition{
		{
			Key:          expectDecisionParamKey,
			DefaultValue: decisionShrink,
			Description: evetest.TestParameterDescription{
				Summary:       "Which way the conversion must free the space it needs",
				Default:       "shrink",
				AllowedValues: "shrink|grow",
			},
		},
		{
			Key:          fillPersistGiBParamKey,
			DefaultValue: uint32(defaultFillPersistGiB),
			Description: evetest.TestParameterDescription{
				Summary: "GiB written into /persist before a shrink, so it has blocks to relocate (0 disables)",
				Default: "33",
			},
		},
	}
}
