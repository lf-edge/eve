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
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// appsParamKey and vifsPerAppParamKey select how many applications
// TestManyAppInterfaces deploys and how many network adapters each gets.
const (
	appsParamKey       = "APPS"
	vifsPerAppParamKey = "VIFS_PER_APP"
)

// Defaults: the interface count at which the network metrics outgrow a pubsub
// message with margin; see the test's description.
const (
	defaultApps       = 15
	defaultVIFsPerApp = 20
)

// networkInstances is how many local network instances the adapters are
// spread over.
const networkInstances = 4

// deviceRAMInMiB is the memory of the device: EVE accounts every one of
// these applications at about 650 MB (its 256 MiB plus the overhead it
// reckons for a VM with 20 adapters) and refuses to start what does not fit,
// so the default 8 GiB holds ten of them and 15 need 16 GiB.
const deviceRAMInMiB = 16384

// TestManyAppInterfaces verifies that a device with hundreds of application
// network adapters keeps reporting: every application reaches the running
// state and the device keeps reporting metrics, which it collects for every
// interface, afterwards.
//
// zedrouter publishes the counters of every interface of the device, ports,
// bridges and application adapters alike, as one NetworkMetrics object every
// metrics interval. Measured on the real types: 200 interfaces put it at
// 59 KB on the wire and 250 at 74 KB, over the 64 KiB a pubsub message may
// carry, so the default of 15 applications with 20 adapters each (300
// adapters, 4 bridges and the port: 90 KB) is where an unfixed zedrouter
// exits with "Too large message" at the first metrics collection after the
// adapters exist, and every application restarts.
//
// Network model: netmodels.SingleEthWithDHCP, on a device with 16 GiB of
// memory (deviceRAMInMiB), which is what EVE's accounting of 15 such
// applications needs; the suite recreates the device for this test.
//
// Device config: one DHCP management port, a 5-second metrics interval, four
// local network instances, and APPS container applications with VIFS_PER_APP
// network adapters each, spread over the network instances.
//
// Phases:
//  1. Apply the base configuration and wait until it is processed.
//  2. Add the network instances and the applications, apply, and wait until
//     every application is reported running, with the device still reporting
//     metrics afterwards. Stop at once if the device crashes.
//  3. Delete the applications and wait until they are gone; delete the
//     network instances.
//
// Parameters: HYPERVISOR (shared with the suite), APPS (default 15),
// VIFS_PER_APP (default 20).
//
// Suite placement: TestLimitsSuite.
func TestManyAppInterfaces(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TestParameterDefinition{
			Key:          appsParamKey,
			DefaultValue: defaultApps,
			Description: evetest.TestParameterDescription{
				Summary: "Number of applications deployed",
				Default: fmt.Sprint(defaultApps),
			},
		},
		evetest.TestParameterDefinition{
			Key:          vifsPerAppParamKey,
			DefaultValue: defaultVIFsPerApp,
			Description: evetest.TestParameterDescription{
				Summary: "Number of network adapters of every application",
				Default: fmt.Sprint(defaultVIFsPerApp),
			},
		},
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	numApps := evetest.GetTestParameter[int](appsParamKey)
	vifsPerApp := evetest.GetTestParameter[int](vifsPerAppParamKey)

	device := setupDevice(hypervisor, deviceRAMInMiB)
	evetest.Checkpoint("setup-done")
	log := evetest.Logger()
	devConfig, _ := applyBaseConfig(device, hypervisor)
	evetest.Checkpoint("base-config-applied")
	crash := device.WatchForCrash()
	defer crash.Stop()

	// Phase 2: the network instances and the applications.
	nis := make([]uuid.UUID, 0, networkInstances)
	for i := range networkInstances {
		nis = append(nis, devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
			DisplayName: fmt.Sprintf("many-vifs-ni-%d", i),
			Port:        mgmtPort,
			Subnet:      evetest.IPSubnet(fmt.Sprintf("10.21.%d.0/24", i)),
			DHCPRange: types.IPRange{
				Start: evetest.IPAddress(fmt.Sprintf("10.21.%d.2", i)),
				End:   evetest.IPAddress(fmt.Sprintf("10.21.%d.254", i)),
			},
			Gateway: evetest.IPAddress(fmt.Sprintf("10.21.%d.1", i)),
			MTU:     1500,
		}))
	}
	apps := make([]uuid.UUID, 0, numApps)
	updates := make(map[uuid.UUID]<-chan *eveinfo.ZInfoApp, numApps)
	for i := range numApps {
		app := containerApp(fmt.Sprintf("many-vifs-app-%02d", i))
		for j := range vifsPerApp {
			app.NetworkAdapters = append(app.NetworkAdapters, evetest.VirtualNetworkAdapter{
				LogicalLabel:        fmt.Sprintf("vif%02d", j),
				NetworkInstanceUUID: nis[j%networkInstances],
			})
		}
		appUUID := devConfig.AddApplication(app)
		apps = append(apps, appUUID)
		ch, stop := device.WatchAppInfo(appUUID)
		defer stop()
		updates[appUUID] = ch
	}
	device.ApplyConfig(devConfig, true, false)
	evetest.Checkpoint("apps-deployed")

	states := make(map[uuid.UUID]eveinfo.ZSwState, numApps)
	running := func() int {
		n := 0
		for _, state := range states {
			if state == eveinfo.ZSwState_RUNNING {
				n++
			}
		}
		return n
	}
	awaitWhileAlive(t, device, crash,
		fmt.Sprintf("all %d applications are reported running", numApps),
		30*time.Minute, func() bool {
			for appUUID, ch := range updates {
				for drained := false; !drained; {
					select {
					case info, ok := <-ch:
						drained = !ok
						if ok {
							states[appUUID] = info.GetState()
						}
					default:
						drained = true
					}
				}
			}
			return running() == numApps
		})
	log.Infof("All %d applications with %d network adapters each are running",
		numApps, vifsPerApp)
	evetest.Checkpoint("apps-running")

	// Phase 3: cleanup.
	deleteAppsAndWait(t, device, devConfig, apps)
	for _, niUUID := range nis {
		devConfig.DeleteNetworkInstance(niUUID)
	}
	device.ApplyConfig(devConfig, true, true)
}
