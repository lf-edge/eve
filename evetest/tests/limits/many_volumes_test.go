// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package limits_test

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	uuid "github.com/satori/go.uuid"
)

// volumesParamKey selects how many volumes TestManyVolumesPerApp attaches to
// its application.
const volumesParamKey = "VOLUMES"

// defaultVolumes is the volume count at which the application status
// outgrows a pubsub message with margin; see the test's description.
const defaultVolumes = 100

// TestManyVolumesPerApp verifies that an application with many volumes is
// handled without crashing the device: it is reported running with all of
// them, or in error, and the device stays up either way.
//
// Every volume attached to an application adds a VolumeRefStatus of about
// 560 bytes to the AppInstanceStatus zedmanager publishes, the status with
// the most per-volume state of all. Measured on the real types: 80 volumes
// put it at 65 KB on the wire, right at the 64 KiB a pubsub message may
// carry, while the AppInstanceConfig zedagent publishes (22 KB) and the
// DomainConfig zedmanager derives (29 KB) stay well under. Nothing limits the
// number of volumes a controller may attach, so the default of 100 (81 KB on
// the wire) is where an unfixed zedmanager exits with "Too large message"
// the moment the volumes have been created, before any domain exists.
//
// A fix may let the status through (spilling the list to a file, as other
// large fields are, or changing the transport) or refuse the application
// with a config error; the test accepts both, since its subject is that the
// device survives and reports, not whether a hundred disks can be attached.
//
// Network model: netmodels.SingleEthWithDHCP.
//
// Device config: one DHCP management port, a 5-second metrics interval, and
// one container application with VOLUMES blank volumes of 16 MiB attached as
// raw block devices.
//
// Phases:
//  1. Apply the base configuration and wait until it is processed.
//  2. Add the volumes and the application, apply, and wait until the
//     application is reported running or in error, with the device still
//     reporting metrics afterwards. Stop at once if the device crashes.
//  3. Delete the application and its volumes and wait until it is gone.
//
// Parameters: HYPERVISOR (shared with the suite), VOLUMES (default 100).
//
// Suite placement: TestLimitsSuite.
func TestManyVolumesPerApp(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TestParameterDefinition{
			Key:          volumesParamKey,
			DefaultValue: defaultVolumes,
			Description: evetest.TestParameterDescription{
				Summary: "Number of volumes attached to the application",
				Default: fmt.Sprint(defaultVolumes),
			},
		},
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	numVolumes := evetest.GetTestParameter[int](volumesParamKey)

	device := setupDevice(hypervisor, 0)
	evetest.Checkpoint("setup-done")
	log := evetest.Logger()
	devConfig, _ := applyBaseConfig(device, hypervisor)
	evetest.Checkpoint("base-config-applied")
	crash := device.WatchForCrash()
	defer crash.Stop()

	// Phase 2: the application and its volumes.
	app := containerApp("many-volumes-app")
	volumes := make([]uuid.UUID, 0, numVolumes)
	for i := range numVolumes {
		volUUID := devConfig.AddBlankVolume(
			fmt.Sprintf("many-volumes-app-vol-%03d", i), 16*evetest.MiB, false)
		volumes = append(volumes, volUUID)
		app.Mounts = append(app.Mounts, evetest.MountConfig{VolumeUUID: volUUID})
	}
	appUUID := devConfig.AddApplication(app)
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, true, false)
	evetest.Checkpoint("app-deployed")

	var latest *eveinfo.ZInfoApp
	awaitWhileAlive(t, device, crash,
		"the application is reported running or in error", 15*time.Minute,
		func() bool {
			for drained := false; !drained; {
				select {
				case info, ok := <-appUpdates:
					drained = !ok
					if ok {
						latest = info
					}
				default:
					drained = true
				}
			}
			return latest.GetState() == eveinfo.ZSwState_RUNNING ||
				len(latest.GetAppErr()) > 0
		})
	log.Infof("The application with %d volumes is reported in state %s with %d "+
		"volume references and %d error(s)", numVolumes, latest.GetState(),
		len(latest.GetVolumeRefs()), len(latest.GetAppErr()))
	evetest.Checkpoint("app-reported")

	// Phase 3: cleanup.
	devConfig.DeleteApplication(appUUID)
	for _, volUUID := range volumes {
		devConfig.DeleteVolume(volUUID)
	}
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(appUpdates, 10*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"application is gone",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		})))
}
