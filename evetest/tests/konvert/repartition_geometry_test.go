// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// TestKvmToKRepartitionGeometry asserts that the conversion ends at the full EVE-K
// partition layout -- ESP-A 2 GiB, the reserved ESP-B 2 GiB, IMGA and IMGB
// 10 GiB each -- whatever layout the device started on.
//
// It deliberately does nothing else. No app, no data volume, no vault settle,
// no blob-reuse check: those all belong to TestKvmToKRepartition, and mixing
// them in here would mean a geometry regression could be masked by, or mistaken
// for, an app or storage failure. What is left is one claim, stated absolutely
// rather than relative to the starting sizes, because a conversion that grew
// every partition but stopped short of the target would pass a relative check
// and still leave a disk unlike a fresh EVE-K install.
//
// The axis is INITIAL_EVE_VERSION: point it at each release whose geometry
// matters and the same claim must hold from all of them. The starting layout is
// observed rather than declared, and only has to differ from the target -- a
// device that is already laid out correctly would pass without the conversion
// having done anything.
//
// Needs an EVE build carrying the conversion (lf-edge/eve#6036, #6063).
func TestKvmToKRepartitionGeometry(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	defineSharedParameters()
	p := resolveDeviceParams(t)
	requirePinnedInitialVersion(t, p)

	device := setupDevice(t, p, evetest.FilesystemEXT4, nil,
		evetest.CreateFromScratchWithLiveImage)
	log := evetest.Logger()

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	applyMgmtNetwork(device, devConfig)
	devConfig.SetConfigProperties(shortBaseImageCooldown())
	device.ApplyConfig(devConfig, true, true)

	startGeometry := readGeometry(t, device)
	log.Infof("starting geometry on %s: %s", p.initialVersion, startGeometry)
	t.Expect(isEVEKLayout(startGeometry)).To(BeFalse(),
		"%s is already laid out like EVE-K, so a conversion from it would prove nothing: %s",
		p.initialVersion, startGeometry)
	evetest.Checkpoint("baseline-captured")

	log.Infof("kvm→kvm hop: landing the conversion code at %s", p.targetVersion)
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKVM,
		evetest.BaseOSDatastoreHTTP, true, false)
	log.Infof("the hop must not have moved the geometry")
	assertGeometryUnchanged(t, device, startGeometry)
	evetest.Checkpoint("conversion-code-landed")

	conversionOK := false
	defer func() {
		if !conversionOK {
			dumpConversionFailure(device)
		}
	}()
	// The offline repartition boots once more than an upgrade does; declared
	// before the update that causes it.
	device.ExpectReboots(1)
	log.Infof("kvm→k hop: running the repartition")
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKubevirt,
		evetest.BaseOSDatastoreHTTP, true, false)
	conversionOK = true
	evetest.Checkpoint("conversion-complete")

	log.Infof("the boot disk must be at the full EVE-K layout")
	assertFinalEVEKLayout(t, device)
	evetest.Checkpoint("layout-final")
}
