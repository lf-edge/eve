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

// TestFirstBootEVEKAppVolume asserts that an application volume asked for
// before EVE-K's cluster storage exists eventually gets created, rather than
// parking forever.
//
// EVE-K cannot create a volume until k3s, Longhorn and CDI are up, which takes
// somewhere around a quarter of an hour from a cold boot. A device that is
// handed an application in its very first configuration therefore asks for a
// volume that cannot be satisfied yet, and the question is what happens next:
// volumemgr has to defer the request and retry it when storage arrives, and
// creation has to be idempotent so a retry does not trip over its own earlier
// attempt. Without that the volume sits at CREATING_VOLUME and the app never
// starts.
//
// The timing is the test. The app is deployed immediately after onboarding,
// while cluster storage is still minutes away -- deliberately not after waiting
// for storage to be ready, which would test nothing, since by then the request
// is one that can simply be granted. Everything else here exists to make that
// one window real: a native EVE-K boot with no conversion, no upgrade and no
// prior volumes.
//
// A device that reboots its way out of the problem has not solved it either.
// Nothing here asks for a reboot, and the framework audits observed reboots
// against expected ones at teardown, so a device that restarts to recover fails
// the run without a separate assertion.
//
// Phases:
//  1. A native EVE-K device, on the EVE-K layout, holding no volumes.
//  2. Deploy an app with a volume at once, before storage can exist.
//  3. Cluster storage comes up.
//  4. The volume is created and the app runs and answers.
func TestFirstBootEVEKAppVolume(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	defineSharedParameters()
	p := resolveDeviceParams(t)
	// A native EVE-K boot of the build under test: no release to start from and
	// no conversion, because the subject is the first configuration a fresh
	// EVE-K device ever receives.
	p.initialVersion = ""
	p.initialRepo = ""
	p.initialHypervisor = evetest.HypervisorKubevirt

	device := setupDevice(t, p, evetest.FilesystemEXT4, nil,
		evetest.CreateFromScratchWithLiveImage)
	log := evetest.Logger()

	// Phase 1. Checked before anything is deployed, so that a device which was
	// not actually a clean EVE-K boot is caught here rather than misread later
	// as a volume that failed to converge.
	log.Infof("the device must be a clean EVE-K boot")
	assertNoLiveVolumes(t, device)
	startGeometry := readGeometry(t, device)
	t.Expect(isEVEKLayout(startGeometry)).To(BeTrue(),
		"this is not an EVE-K boot disk: %s", startGeometry)
	evetest.Checkpoint("fresh-evek-boot")

	// Phase 2. The management network and the app go out together, so the
	// volume request reaches the device as early as it possibly can. Shortening
	// the config poll only narrows the gap further.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	props := pillartypes.NewConfigItemValueMap()
	props.SetGlobalValueInt(pillartypes.ConfigInterval, 10)
	devConfig.SetConfigProperties(props)
	applyMgmtNetwork(device, devConfig)

	log.Infof("deploying an app with a volume immediately, before cluster storage exists")
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "eth0",
	})
	dataVolUUID := devConfig.AddBlankVolume("firstboot-data", dataVolumeSize, false)
	appUUID := addTestAppWithVolume(devConfig, "firstboot-app", niUUID, dataVolUUID)
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("app-requested-before-storage")

	appOK := false
	defer func() {
		if !appOK {
			dumpClusterStorage(device)
			dumpAppNetwork(device, "first boot (app FAILED)")
		}
	}()

	// Phase 3.
	log.Infof("waiting for EVE-K cluster storage to come up")
	waitClusterStorageReady(t, device)
	evetest.Checkpoint("cluster-storage-ready")

	// Phase 4. The volume is asserted in its own right before the app: an app
	// that never starts because its volume was never created is a different
	// finding from one that fails for its own reasons, and waiting on the app
	// alone would not separate them.
	log.Infof("the deferred volume must now be created")
	assertVolumeCreated(t, device, dataVolUUID, 45*time.Minute)
	log.Infof("and the app must run on it")
	assertAppReady(t, device, appUUID, appRunningAfterSwitchTimeout)
	appOK = true
	evetest.Checkpoint("app-running-on-deferred-volume")
}
