// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// TestKvmToKUpgrade asserts EVE accepts a base-OS image of the other flavor
// when the device holds no volumes, and comes back on it.
//
// The flavor switch is normally refused outright: /persist is laid out
// differently for EVE-K, so baseosmgr blocks a kvm↔k update rather than risk
// meeting a layout it cannot read. Relaxing that to "allowed while no volume
// exists" is the first step towards the in-field conversion, and this is the
// happy path of it -- no repartition involved, both images released, the flavor
// the only variable.
//
// Phases:
//  1. Assert the device holds no live volumes, which is the precondition the
//     relaxation is conditioned on.
//  2. Upgrade across the flavor seam and wait for the device to report itself
//     active on the new flavor.
//  3. Push the reverse update and assert it is refused. EVE-K is a one-way
//     door -- docs/EVE-K.md states an upgrade from HV=k to another HV type is
//     not supported, and baseosmgr blocks it unconditionally, with none of the
//     conditions that let the forward direction through. Asserting the refusal
//     pins that, and keeps a future relaxation from going unnoticed.
func TestKvmToKUpgrade(test *testing.T) {
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

	log.Infof("pre-flight: the device must hold no live volumes")
	assertNoLiveVolumes(t, device)
	evetest.Checkpoint("no-volumes")

	conversionOK := false
	defer func() {
		if !conversionOK {
			dumpConversionFailure(device)
		}
	}()

	log.Infof("crossing the flavor seam: %s → %s at %s", p.initialHypervisor, altHV, altVersion)
	upgradeAcrossFlavors(device, altVersion, altHV)
	conversionOK = true
	evetest.Checkpoint("crossed-to-alt-flavor")

	// The reverse is not a supported upgrade, so it is pushed as one that must
	// be refused rather than one that must succeed.
	altRunningVersion := readRunningVersion(t, device)
	log.Infof("the reverse update (%s → %s) must be refused", altHV, p.initialHypervisor)
	device.RequestRefusedEVEUpgrade(p.initialVersion, p.initialHypervisor,
		evetest.BaseOSDatastoreHTTP)
	assertConversionDeclined(t, device, altRunningVersion)
	evetest.Checkpoint("reverse-refused")
}
