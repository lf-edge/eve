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

const (
	// appVolumeDataVolMiB is the data-volume size this test defaults to. The app
	// redeploy on EVE-K wedges in a Longhorn CSI create race above roughly 256
	// MiB (sweep: 100 and 256 MiB pass, 512 MiB and above wedge), which would
	// mask the corruption result behind an unrelated failure.
	appVolumeDataVolMiB = 256

	// cdiSampleSecsParamKey is how often the import is sampled while it runs.
	cdiSampleSecsParamKey = "CDI_SAMPLE_SECS"
	defaultCDISampleSecs  = 5

	// appVolumeKeepCorruptMarker makes EVE quarantine a volume its post-resize
	// check finds torn, instead of deleting it.
	appVolumeKeepCorruptMarker = "/persist/volmanifest-keep-corrupt"
)

// TestKvmToKRepartitionAppVolume asks what the EVE-kvm→EVE-K offline boot-disk
// shrink does to an application's data when it has to relocate the volume
// holding it, and whether damage would be detectable.
//
// It drives the same conversion as TestKvmToKRepartitionVolmig and differs in
// what the volume is made to be: /persist is filled before the app exists, so the
// volume is allocated in the high blocks the shrink must evacuate, and it is
// filled with the volverify pattern rather than a single marker, so what comes
// back can be judged file by file. Where the shrink is also interrupted -- by the
// chipset watchdog on a build whose resizer stops feeding it -- the question
// becomes what a half-finished relocation leaves behind.
//
// The verdict is taken on the volume itself, on the device, before Longhorn
// ingests it and long before the app is asked to boot. That ordering is
// deliberate: a post-conversion app that never reaches RUNNING has repeatedly
// cost otherwise complete runs their result, and whether the app comes back is a
// separate question from whether the bytes survived. The app-side checks that
// follow re-take the same verdict from inside the guest and add the filesystem's
// own opinion, which is the comparison worth having -- a structural check is
// blind to blocks relocated wrongly but left self-consistent.
//
// A run that finds nothing to verify is reported as such rather than as a pass,
// since a failing volume verdict is the finding being hunted.
//
// Phases:
//  1. Baseline: the boot disk is on the released layout and the guest has a
//     watchdog driver, without which nothing can interrupt the resize.
//  2. kvm→kvm hop: the geometry must be unchanged and the check decide a shrink.
//  3. Settle the vault to a local TPM unlock.
//  4. Fill /persist to its peak, deploy the app on top of it, write the pattern
//     into its volume, then free the low blocks and assert the volume really
//     does lie above the shrink boundary.
//  5. kvm→k hop: the conversion runs the offline shrink with the volume in it.
//  6. Take the volume verdict on the device, app-independently.
//  7. Bring the app back on EVE-K and re-judge the volume from inside it, with
//     fsck before and after the content verify.
//
// Needs an EVE build carrying the conversion (lf-edge/eve#6036, #6063). The
// interruption is a property of the build under test, not of this test: a
// resizer that runs under a no-pet watchdog is cut mid shrink and a later attempt
// converges, while an ordinary build gives the same measurement with nothing
// injected.
func TestKvmToKRepartitionAppVolume(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	defineSharedParameters(appVolumeParameterDefinitions()...)
	p := resolveDeviceParams(t)
	p = raiseFloorsForCarriedVolume(t, p)
	requirePinnedInitialVersion(t, p)

	dataVolMiB := evetest.GetTestParameter[uint32](dataVolMiBParamKey)
	fillPeakPct := int(evetest.GetTestParameter[uint32](fillPeakPctParamKey))
	fillKeepGiB := int(evetest.GetTestParameter[uint32](fillKeepGiBParamKey))
	seed := evetest.GetTestParameter[uint64](seedParamKey)
	ops := evetest.GetTestParameter[uint64](opsParamKey)
	image := evetest.GetTestParameter[string](volverifyImageParamKey)
	args := volverifyArgs(dataVolMiB, seed, ops)

	device := setupDevice(t, p, evetest.FilesystemEXT4, nil, provisionPolicy())
	log := evetest.Logger()
	log.Infof("volverify app %s:%s on a %d MiB data volume", image, volverifyImageTag, dataVolMiB)

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	applyMgmtNetwork(device, devConfig)
	props := shortBaseImageCooldown()
	if fillPeakPct > 0 {
		// The volume is deliberately created on a nearly-full /persist, which
		// EVE would otherwise refuse: volumemgr declines a volume whose size
		// exceeds the remaining space, counting a dom0 reservation of 20% on
		// top. The fill is transient and trimmed away before the conversion, so
		// the check is what is wrong here, not the request.
		props.SetGlobalValueBool(pillartypes.IgnoreDiskCheckForApps, true)
	}
	devConfig.SetConfigProperties(props)
	device.ApplyConfig(devConfig, true, true)

	// Phase 1.
	log.Infof("baseline: the boot disk must be on the released layout")
	smallGeometry := assertSmallGeometry(t, device)
	log.Infof("baseline geometry: %s", smallGeometry)
	assertWatchdogDriverBound(t, device)
	evetest.Checkpoint("baseline-small")

	// Phase 2.
	conversionOK := false
	defer func() {
		if !conversionOK {
			dumpConversionFailure(device)
		}
	}()
	log.Infof("kvm→kvm hop: landing the conversion code at %s", p.targetVersion)
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKVM,
		evetest.BaseOSDatastoreHTTP, true, false, conversionUpgradeTimeout)
	assertSmallGeometry(t, device)
	log.Infof("the pre-flight check must decide %q", decisionShrink)
	assertCheckDecision(t, device, decisionShrink)
	evetest.Checkpoint("conversion-code-landed")

	// Phase 3.
	log.Infof("settling the vault on a local TPM unlock")
	settleVaultLocal(t, device)
	evetest.Checkpoint("vault-settled")

	// Phase 4. Filling before the app exists is what puts its volume at the top
	// of the filesystem, inside the range the shrink has to evacuate. On an
	// almost-empty /persist the volume lands low, the shrink finishes in about a
	// second, and an interruption only ever lands in the grow.
	if fillPeakPct > 0 {
		log.Infof("filling /persist to %d%% so the app's volume lands in the shrink's evacuation zone",
			fillPeakPct)
		fillPersistToPeak(t, device, fillPeakPct, dataVolMiB)
		evetest.Checkpoint("persist-filled")
	}

	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "eth0",
	})
	// Encrypted, not clear text: the conversion takes the vault across a
	// transition of its own, so the volume has to exercise that path.
	dataVolUUID := devConfig.AddBlankVolume("konvert-appvolume-data",
		uint64(dataVolMiB)*evetest.MiB, false)
	appUUID := addVolverifyApp(devConfig, "konvert-appvolume-app", image,
		niUUID, dataVolUUID)
	device.ApplyConfig(devConfig, false, false)
	assertAppReady(t, device, appUUID, 15*time.Minute)
	dumpAppNetwork(device, "before the conversion (working)")
	dumpLostFound(device, "pre-conversion")

	// Filled on EVE-kvm, where the runx shim has formatted and mounted the
	// volume at its MountDir. The writer stops at the op count or when the
	// volume fills, whichever comes first, and reports the committed high-water
	// mark the verify is held to.
	log.Infof("pre-conversion: filling the data volume with the volverify pattern")
	committed := writeVolverifyPattern(t, device, appUUID, args)
	log.Infof("volume filled through committed op %d", committed)

	// Free the low blocks now that the volume is placed. This is what lets the
	// shrink fit at all, and it leaves the relocation work -- the volume
	// included -- concentrated above the boundary.
	if fillPeakPct > 0 {
		log.Infof("trimming the filler back to %d GiB (lowest blocks first)", fillKeepGiB)
		trimPersistFill(t, device, fillKeepGiB)
		log.Infof("asserting the data volume actually lies above the shrink boundary")
		assertVolumeAboveShrinkBoundary(t, device)
		evetest.Checkpoint("volume-placed-high")
	}
	dumpPersistAccounting(device, "pre-conversion (volume filled)")
	evetest.Checkpoint("volume-filled")

	// EVE's post-resize check hashes each volume against a pre-resize manifest
	// and DELETES any that mismatches, so a torn volume is gone before this test
	// can look at it -- which is why nine corruptions at 8 GiB were recorded as
	// "nothing to measure". The marker makes EVE quarantine it instead, leaving
	// the damaged bytes for fsck and volverify to characterize.
	out, err := runEVE(device, "eve exec pillar touch "+appVolumeKeepCorruptMarker)
	t.Expect(err).NotTo(HaveOccurred(),
		"could not arm the corrupt-volume quarantine marker:\n%s", out)
	log.Infof("armed %s so a torn volume is kept, not deleted", appVolumeKeepCorruptMarker)

	// Phase 5.
	log.Infof("kvm→k hop: arming the offline shrink with the volume in it")
	// Not waiting for EVE to commit the new partition. Committing is a trial
	// period that runs long after the device is already up on the target, and
	// nothing asserted here depends on it: the geometry is converted by then and
	// what matters is the volume. Waiting for it only delays -- and can fail --
	// a conversion that is doing fine. The partition state is recorded at the
	// end instead, where it costs nothing.
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKubevirt,
		evetest.BaseOSDatastoreHTTP, false, false)
	waitDeviceOnTarget(t, device, evetest.HypervisorKubevirt, conversionUpgradeTimeout)
	conversionOK = true
	// The offline repartition boots once more than an upgrade does; declared
	// here rather than before the update because UpgradeEVE was not asked to
	// wait, so nothing can race the declaration.
	device.ExpectReboots(1)
	dumpResizeEvidence(device)
	dumpLostFound(device, "post-conversion")
	evetest.Checkpoint("conversion-complete")

	log.Infof("asserting the boot disk reached the EVE-K layout via the shrink")
	assertLargeGeometry(t, device, smallGeometry, p3MustShrink)
	evetest.Checkpoint("geometry-converted")
	assertResizeFaultAccounted(t, device)

	stopPersistSampler := startPersistSampler(device, 45*time.Second)
	defer stopPersistSampler()

	// Phase 6. The only reading that survives a post-conversion app that never
	// comes back, which has cost every verdict it has hit.
	assertRelocatedVolumeIntact(t, device, dataVolMiB, seed, ops, committed)

	// The volume verdict is complete here, and the rest of the run is the
	// app-side half. At data-volume sizes where the post-conversion app reliably
	// wedges, that half re-derives a known failure, so a corruption soak can
	// stop here and collect several times as many volume verdicts per day. It
	// forfeits the wedge diagnostics, which the app-failure path produces and
	// nothing else does: leave it off when the run is meant to investigate why
	// the app does not come back.
	if evetest.GetTestParameter[bool](devsideOnlyParamKey) {
		log.Infof("DEVSIDE_ONLY: volume verdict taken; skipping the app-side checks")
		evetest.Checkpoint("devside-only-complete")
		return
	}

	// Phase 7. The EVE-K storage stack is waited on stage by stage, starting
	// with the node, so that a stall names the stage it happened in.
	log.Infof("waiting for the k3s node to be ready")
	waitK3sNodeReady(t, device, 30*time.Minute)
	waitClusterStorageReady(t, device)

	// Registered above the wait, not below it: the app failing to reach RUNNING
	// is the most common way this test fails, and a defer set up after the wait
	// never runs on that path -- which is exactly where the evidence is needed.
	appRunning := false
	appSSHOK := false
	defer func() {
		if appSSHOK {
			return
		}
		stage := "never reached RUNNING"
		if appRunning {
			stage = "RUNNING but unreachable"
		}
		dumpAppNetwork(device, "after the conversion (app "+stage+")")
		dumpAppPVCWedge(device)
	}()

	log.Infof("waiting for the app to reach RUNNING on EVE-K")
	// A failing import keeps its upload pod for the whole recovery budget, but
	// one that succeeds finishes inside a minute, so only a few seconds of
	// interval catches a success at all. That cadence also perturbs what it
	// measures: at five seconds no run has passed in seventeen, against roughly
	// one in five without it. Sampling stays on by default because the diagnosis
	// is worth more than the rare pass; set the interval to 0 to measure the
	// untouched rate.
	stopCDISampler := func() {}
	if secs := evetest.GetTestParameter[uint32](cdiSampleSecsParamKey); secs > 0 {
		stopCDISampler = startCDISampler(device, time.Duration(secs)*time.Second)
	}
	waitAppRunningWithPVCRecovery(t, device, appUUID, dataVolMiB)
	stopCDISampler()
	appRunning = true
	log.Infof("waiting for the app to report a routable IPv4")
	waitAppHasRoutableIPv4(t, device, appUUID, 10*time.Minute)
	assertAppSSH(t, device, appUUID)
	appSSHOK = true

	log.Infof("re-verifying the data-volume pattern from inside the app")
	dumpVolumeManifest(device)

	// Checked before anything mounts it, so the structural verdict can be set
	// against the content verdict below: a mount would replay the journal and
	// could repair what is being measured.
	volDev := findDataVolumeDevice(t, device, appUUID, dataVolMiB)
	fsckRC, fsckOut := fsckDataVolume(device, appUUID, volDev)

	state := mountDataVolumeRO(t, device, appUUID, dataMountDir)
	if state == volumeStateBlank {
		logVolumeOutcome(dataVolMiB, state, fsckRC, "", fsckOut, -1, "")
		// The pattern is gone but the volume is intact and empty: either the
		// post-resize manifest check found it torn and removed it, so EVE
		// recreated it blank, or the shrink destroyed the filesystem outright.
		// The manifest capture above says which. Either way nothing corrupt is
		// being served to the app, so this is not what the test gates on.
		log.Errorf("data volume came back BLANK -- the pattern did not survive; " +
			"the volume-manifest capture says whether the detector removed it")
		evetest.Checkpoint("volume-recreated-blank")
		return
	}

	report := verifyVolverifyPattern(t, device, appUUID, args, committed)
	log.Infof("volverify report:\n%s", report)

	// Content is captured, so the filesystem can now be checked with the journal
	// replayed -- the only reading that distinguishes real damage from the stale
	// accounting an unclean unmount leaves behind.
	log.Infof("re-checking the volume filesystem with the journal replayed")
	replayRC, replayOut := fsckDataVolumeAfterVerify(device, appUUID, volDev, dataMountDir)
	logVolumeOutcome(dataVolMiB, state, fsckRC, report, fsckOut, replayRC, replayOut)

	// present-corrupt is the silent case: a torn-but-present volume EVE would
	// serve to the app as-is, invisible to fsck and to qemu-img. Orphaned and
	// lost files are the recoverable modes -- EVE recreates a missing volume
	// file blank -- so they are surfaced but not gated on.
	presentCorrupt := reportField(report, "present-corrupt")
	t.Expect(presentCorrupt).To(BeNumerically(">=", 0),
		"could not parse present-corrupt from the volverify report:\n%s", report)
	t.Expect(presentCorrupt).To(Equal(0),
		"the data volume is served corrupt-but-present after the shrink:\n%s", report)
	evetest.Checkpoint("volume-verified")

	// Whether EVE committed the new partition is recorded rather than asserted:
	// the volume result does not depend on it, but a target still in its trial
	// period here, or one that reverted, would explain an otherwise puzzling
	// later failure.
	logPartitionState(device)

	// The volume outlives the app and blocks its own delete while a VolumeRef
	// still points at it, so the app goes first.
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)
	devConfig.DeleteVolume(dataVolUUID)
	device.ApplyConfig(devConfig, false, false)
}

// appVolumeParameterDefinitions declares the axes this test adds: how the volume
// is placed, how the pattern is shaped, and how the import is observed.
func appVolumeParameterDefinitions() []evetest.TestParameterDefinition {
	return append(volverifyParameterDefinitions(),
		useInstallerParameter(),
		evetest.TestParameterDefinition{
			Key:          dataVolMiBParamKey,
			DefaultValue: uint32(appVolumeDataVolMiB),
			Description: evetest.TestParameterDescription{
				Summary: "App data-volume size in MiB (stay at or below 256 to avoid the EVE-K CSI create race)",
				Default: "256",
			},
		},
		evetest.TestParameterDefinition{
			Key:          fillPeakPctParamKey,
			DefaultValue: uint32(defaultFillPeakPct),
			Description: evetest.TestParameterDescription{
				Summary: "Fill /persist to this % before deploying the app, so its volume lands in the blocks the shrink evacuates (0 disables)",
				Default: "90",
			},
		},
		evetest.TestParameterDefinition{
			Key:          fillKeepGiBParamKey,
			DefaultValue: uint32(defaultFillKeepGiB),
			Description: evetest.TestParameterDescription{
				Summary: "GiB of filler left after the volume is written; the rest is deleted so EVE-K has room. Measures the filler alone, not total /persist usage",
				Default: "2",
			},
		},
		evetest.TestParameterDefinition{
			Key:          cdiSampleSecsParamKey,
			DefaultValue: uint32(defaultCDISampleSecs),
			Description: evetest.TestParameterDescription{
				Summary: "Seconds between samples of the CDI import while it runs; 0 disables sampling, which is the only way to measure the untouched pass rate",
				Default: "5",
			},
		},
		evetest.TestParameterDefinition{
			Key:          devsideOnlyParamKey,
			DefaultValue: false,
			Description: evetest.TestParameterDescription{
				Summary: "Stop once the volume verdict is taken, skipping the app-side checks",
				Default: "false",
			},
		},
	)
}
