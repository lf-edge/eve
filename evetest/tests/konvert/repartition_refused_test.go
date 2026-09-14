// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// tooFullPercent is how full /persist is made for the too-full case. The
// resizer will not shrink a filesystem past its own fullness limit, so filling
// well beyond what the conversion would need to free is what makes the refusal
// certain rather than marginal.
const tooFullPercent = 70

// TestKvmToKRepartitionRefused asserts that a device which cannot be repartitioned declines
// the conversion cleanly, rather than attempting it and stranding itself.
//
// This is the sibling of TestKvmToKRepartition, and the more important of the
// two to get right: a conversion that fails halfway leaves a device with a
// half-written partition table and no way back. The contract is that EVE works
// out beforehand that it cannot free the space, refuses, says why, and carries
// on exactly as it was.
//
// Two ways to arrive there, both real:
//
//   - REFUSE_REASON=zfs -- /persist is ZFS, which cannot be shrunk at all, and
//     the boot disk has no free tail to take the space from instead.
//   - REFUSE_REASON=too-full -- /persist is ext4 and could in principle shrink,
//     but holds too much to give up what is needed.
//
// They matter separately because they fail at different points in the resizer's
// reasoning: the ZFS case never gets as far as considering a shrink, while the
// too-full case considers one and finds it does not fit.
//
// Phases:
//  1. Baseline: the released layout, and /persist is the filesystem this
//     variant is about.
//  2. (too-full only) Fill /persist past what a shrink could give back.
//  3. kvm→kvm hop, then assert the pre-flight check refuses for this reason.
//  4. Push the kvm→k update and assert it is declined: an error is reported,
//     the device is still on the kvm image, and it is still reachable.
//  5. Assert the partition table was not touched.
//
// Needs an EVE build carrying the conversion (lf-edge/eve#6036, #6063).
func TestKvmToKRepartitionRefused(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	defineSharedParameters(refusedParameterDefinitions()...)
	p := resolveDeviceParams(t)
	requirePinnedInitialVersion(t, p)
	reason := evetest.GetTestParameter[string](refuseReasonParamKey)
	t.Expect(reason).To(BeElementOf(refuseZFS, refuseTooFull),
		"%s must be %q or %q", refuseReasonParamKey, refuseZFS, refuseTooFull)

	// Both variants need a boot disk with no free tail, which is what a device
	// gets by default: EVE's image generator fills whatever disk it is given.
	filesystem := evetest.FilesystemEXT4
	wantPersistType := "ext4"
	if reason == refuseZFS {
		filesystem = evetest.FilesystemZFS
		wantPersistType = "zfs"
	}

	device := setupDevice(t, p, filesystem, nil, evetest.CreateFromScratchWithLiveImage)
	log := evetest.Logger()

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	applyMgmtNetwork(device, devConfig)
	devConfig.SetConfigProperties(shortBaseImageCooldown())
	device.ApplyConfig(devConfig, true, true)

	// Phase 1. The filesystem is checked rather than assumed: a device that came
	// up ext4 when the test meant ZFS would refuse for the wrong reason, and the
	// refusal assertion alone could not tell the difference.
	log.Infof("baseline: /persist must be %s", wantPersistType)
	assertPersistType(t, device, wantPersistType)
	log.Infof("baseline: the boot disk must be on the released layout")
	smallGeometry := assertSmallGeometry(t, device)
	log.Infof("baseline geometry: %s", smallGeometry)
	evetest.Checkpoint("baseline-small")

	// Phase 2.
	if reason == refuseTooFull {
		fillPersistToPercent(t, device, tooFullPercent)
		evetest.Checkpoint("persist-filled")
	}

	// Phase 3.
	log.Infof("kvm→kvm hop: landing the conversion code at %s", p.targetVersion)
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKVM,
		evetest.BaseOSDatastoreHTTP, true, false)
	assertSmallGeometry(t, device)
	kvmHopVersion := readRunningVersion(t, device)
	log.Infof("the pre-flight check must refuse, for the %q reason", reason)
	assertCheckRefuses(t, device, reason)
	evetest.Checkpoint("check-refuses")

	// Phase 4. Not UpgradeEVE: a refusal installs nothing and reboots not at
	// all, so there is neither an upgrade nor a revert to wait for, and booking
	// a reboot that cannot happen would fail the run at teardown.
	log.Infof("pushing the kvm→k update, which must be declined")
	device.RequestRefusedEVEUpgrade(p.targetVersion, evetest.HypervisorKubevirt,
		evetest.BaseOSDatastoreHTTP)
	assertConversionDeclined(t, device, kvmHopVersion)
	evetest.Checkpoint("conversion-declined")

	// Phase 5. The whole point of refusing early is that nothing was touched.
	log.Infof("the partition table must be exactly as it was")
	assertGeometryUnchanged(t, device, smallGeometry)
	evetest.Checkpoint("geometry-untouched")
}

// refusedParameterDefinitions declares the axis this test adds.
func refusedParameterDefinitions() []evetest.TestParameterDefinition {
	return []evetest.TestParameterDefinition{
		{
			Key:          refuseReasonParamKey,
			DefaultValue: refuseZFS,
			Description: evetest.TestParameterDescription{
				Summary:       "Why the conversion must be refused",
				Default:       "zfs",
				AllowedValues: "zfs|too-full",
			},
		},
	}
}
