// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestWorkerPoolSaturation verifies that volumemgr does not lose work when
// its background worker pool is saturated: a submission refused by the full
// pool must surface as a deferral warning on the affected content tree or
// volume, be retried once a worker frees up, and every application must
// still reach RUNNING with the warning cleared. Regression test for app
// instances getting permanently stuck in LOADING with no error reported when
// the pool (20 workers by default) filled up under a large parallel
// deployment.
//
// Instead of relying on load to fill the pool by accident, the pool is
// shrunk to a single worker via the volumemgr.worker.pool.size config item,
// which makes the refusals deterministic: all content trees of the same
// image become ready to progress at the moment their shared CAS ingest
// completes, and the resulting burst of volume work cannot fit one worker.
// Two distinct images are used so that two independent CAS ingest chains
// also compete for the single worker.
//
// Network model: SingleEthWithDHCP -- the test only needs the device online
// and the images downloadable; application connectivity is not asserted.
//
// Device config: one mgmt+apps port, the shared local NI, and six container
// applications (three per image) with one VIF each and no port forwarding.
//
// Phases:
//  1. Apply the base configuration (port, NI) together with
//     volumemgr.worker.pool.size=1 and wait until device info reports the
//     item as accepted, so that the pool resize cannot race the deployment.
//  2. Add the six applications, watching every app volume and content tree
//     from before the config is applied, and wait for all apps to reach
//     RUNNING.
//  3. Assert that at least one worker-pool deferral warning ("... deferred:
//     ...") was reported on some volume or content tree while the pool was
//     saturated.
//  4. Assert that the successful retries cleared the warnings: the latest
//     info of every volume and content tree carries no error.
//
// Parameters: HYPERVISOR (shared with the rest of the suite).
func TestWorkerPoolSaturation(test *testing.T) {
	// Mirrors types.VolumemgrWorkerPoolSize, which the pillar module version
	// currently pinned by evetest/go.mod predates.
	const volumemgrWorkerPoolSize = "volumemgr.worker.pool.size"
	const (
		appsPerImage = 3
		countApps    = 2 * appsPerImage
	)

	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()

	// Phase 1: base config with the worker pool shrunk to a single worker.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	cfgProps := types.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(types.GlobalSettingKey(volumemgrWorkerPoolSize), 1)
	devConfig.SetConfigProperties(cfgProps)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	niUUID := addLocalNI(devConfig)
	device.ApplyConfig(devConfig, true, true)

	t.Eventually(devUpdates, 5*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"Device accepted volumemgr.worker.pool.size=1",
		func(dinfo *eveinfo.ZInfoDevice) bool {
			item := dinfo.GetConfigItemStatus().GetConfigItems()[volumemgrWorkerPoolSize]
			return item.GetValue() == "1" && item.GetError() == ""
		})))
	evetest.Checkpoint("pool-size-configured")

	// Phase 2: deploy the applications, alternating between the two images.
	images := []evetest.DockerContainer{
		{ImageName: ubuntuCtrImage, Tag: ubuntuCtrTag},
		{ImageName: loggerCtrImage, Tag: loggerCtrTag},
	}
	appUUIDs := make([]uuid.UUID, 0, countApps)
	for i := range countApps {
		appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
			DisplayName:        fmt.Sprintf("pool-app-%d", i),
			Activate:           true,
			Image:              images[i%len(images)],
			VirtualizationMode: eveconfig.VmMode_HVM, // PV does not work in xen
			CPUs:               1,
			MemoryBytes:        500 * evetest.MiB,
			NetworkAdapters: []evetest.AppNetworkAdapter{
				evetest.VirtualNetworkAdapter{
					LogicalLabel:        fmt.Sprintf("vif%d", i),
					NetworkInstanceUUID: niUUID,
					ACLAllowRules: []evetest.ACLAllowRule{
						{
							Protocol:     evetest.NetworkProtocolAny,
							RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
						},
					},
				},
			},
		})
		appUUIDs = append(appUUIDs, appUUID)
	}

	// Track, per app volume and per content tree, the latest reported error
	// text and the first worker-pool deferral warning seen. The watches start
	// before the config is applied, so the buffered channels retain the full
	// info history, including the transient deferral warnings.
	type objErrs struct {
		name     string
		lastErr  string
		deferral string
	}
	vols := make([]*objErrs, 0, countApps)
	volChans := make([]<-chan *eveinfo.ZInfoVolume, 0, countApps)
	for _, vol := range devConfig.Volumes {
		volUUID, err := uuid.FromString(vol.Uuid)
		t.Expect(err).ToNot(HaveOccurred())
		updates, stop := device.WatchVolumeInfo(volUUID)
		defer stop()
		vols = append(vols, &objErrs{name: "volume " + vol.DisplayName})
		volChans = append(volChans, updates)
	}
	trees := make([]*objErrs, 0, countApps)
	treeChans := make([]<-chan *eveinfo.ZInfoContentTree, 0, countApps)
	for _, ct := range devConfig.ContentInfo {
		ctUUID, err := uuid.FromString(ct.Uuid)
		t.Expect(err).ToNot(HaveOccurred())
		updates, stop := device.WatchContentTreeInfo(ctUUID)
		defer stop()
		trees = append(trees, &objErrs{name: "content tree " + ct.DisplayName})
		treeChans = append(treeChans, updates)
	}

	device.ApplyConfig(devConfig, true, true)

	// give it a bit more time for slow laptops
	timeoutExcludingDownload := 15 * time.Minute
	for _, appUUID := range appUUIDs {
		device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	}
	evetest.Checkpoint("apps-running")

	recordErr := func(o *objErrs, errDesc string) {
		o.lastErr = errDesc
		if o.deferral == "" && strings.Contains(errDesc, "deferred: ") {
			o.deferral = errDesc
		}
	}
	drainAll := func() (deferrals []string) {
		for i, ch := range volChans {
			for drained := false; !drained; {
				select {
				case vinfo := <-ch:
					if vinfo == nil {
						drained = true
						break
					}
					recordErr(vols[i], vinfo.GetVolumeErr().GetDescription())
				default:
					drained = true
				}
			}
		}
		for i, ch := range treeChans {
			for drained := false; !drained; {
				select {
				case cinfo := <-ch:
					if cinfo == nil {
						drained = true
						break
					}
					recordErr(trees[i], cinfo.GetErr().GetDescription())
				default:
					drained = true
				}
			}
		}
		for _, o := range vols {
			if o.deferral != "" {
				deferrals = append(deferrals, o.name+": "+o.deferral)
			}
		}
		for _, o := range trees {
			if o.deferral != "" {
				deferrals = append(deferrals, o.name+": "+o.deferral)
			}
		}
		return deferrals
	}

	// Phase 3: the saturated pool must have refused at least one submission,
	// reported as a deferral warning on some volume or content tree.
	var deferrals []string
	t.Eventually(func() int {
		deferrals = drainAll()
		return len(deferrals)
	}, 2*time.Minute, 5*time.Second).Should(BeNumerically(">=", 1),
		"no worker-pool deferral warning was reported by any volume or content tree")
	log := evetest.Logger()
	for _, deferral := range deferrals {
		log.Infof("Observed worker-pool deferral: %s", deferral)
	}

	// Phase 4: the retries succeeded (apps are RUNNING), so every deferral
	// warning must be cleared from the latest volume and content tree info.
	t.Eventually(func(t Gomega) {
		drainAll()
		for _, o := range vols {
			t.Expect(o.lastErr).To(BeEmpty(), "%s still reports an error", o.name)
		}
		for _, o := range trees {
			t.Expect(o.lastErr).To(BeEmpty(), "%s still reports an error", o.name)
		}
	}, 3*time.Minute, 5*time.Second).Should(Succeed())
}
