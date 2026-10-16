// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"google.golang.org/protobuf/proto"
)

const (
	bulkContainerAppsParamKey = "BULK_CONTAINER_APPS"
	bulkVMAppsParamKey        = "BULK_VM_APPS"
	bulkVMDataMiBParamKey     = "BULK_VM_DATA_MIB"
	bulkCtrDataMiBParamKey    = "BULK_CTR_DATA_MIB"
	bulkAppChurnParamKey      = "BULK_APP_CHURN"
	bulkChurnLogLinesParamKey = "BULK_CHURN_LOG_LINES"
	bulkRestartStormsParamKey = "BULK_RESTART_STORMS"
	bulkDeployStormsParamKey  = "BULK_STORMS_DURING_DEPLOY"
	bulkStormDelayMinParamKey = "BULK_STORM_DELAY_MIN"
	bulkLinkDelayMsParamKey   = "BULK_LINK_DELAY_MS"
	bulkLinkRateKBpsParamKey  = "BULK_LINK_RATE_KBPS"
	bulkRealImagesParamKey    = "BULK_REAL_IMAGES"
	bulkCtrMemoryMiBParamKey  = "BULK_CTR_MEMORY_MIB"
)

// TestBulkAppDeployment deploys a batch of application instances in one
// configuration change -- the way a bulk API call, a Terraform plan or a
// CI pipeline rolls out a whole workload -- and verifies that the device
// survives it and the restart storm that follows a reboot: every instance
// reaches RUNNING, the device does not reboot on its own, and no EVE
// service stalls for so long that the software watchdog arms.
//
// Regression test for a server with plenty of CPU and RAM resetting itself
// every few minutes under a 24-instance deployment. EVE's own services run
// inside fixed budgets that do not scale with the hardware -- the eve
// cgroup is capped at 800 MB and confined to one CPU by default -- and a
// deployment of that size exhausts them: the services thrash, miss their
// watchdog deadlines, the watchdog resets the device, every instance
// restarts at once after the boot, and the cycle repeats. The device is
// therefore booted with EVE's default budgets, on a VM far larger than
// what those budgets allow EVE to use, like the servers the bug was
// reported on.
//
// The defaults are the smallest configuration that reproduces the field
// reset on a 16-vCPU QEMU device: 50 containers of the test image with 384
// MiB each and nothing else. What exhausts the budget is the number of
// instances -- each brings a containerd shim, an swtpm and pillar state
// that cannot be reclaimed -- not the image traffic: about 20 minutes into
// the deployment newlogd and wwan stop touching their watchdog files, the
// watchdog arms at 500 s, and the device resets without managing to record
// a reason, so nodeagent then reports "Unknown reboot reason". The other
// parameters reproduce the field deployment more literally (VMs, distinct
// images, churn, power cycles, an impaired uplink) and stress the device
// as hard, but 24 such instances only stall the agents for up to four
// minutes on this hardware.
//
// Network model: SingleEthWithDHCP -- the device needs the controller and
// the image server, and the apps take their addresses from the SDN's DHCP
// server through the switch NI; application connectivity is not asserted.
//
// Device config: one mgmt+apps port, a switch NI on it (what the field
// deployment used, and the only NI type on which nistate's packet capture
// sees the churn), and the batch: BULK_CONTAINER_APPS container instances
// of evetest-ubuntu-ctr -- or, with BULK_REAL_IMAGES, of the real workload
// images in realImages, re-served from evetest's local registry -- and
// BULK_VM_APPS VM instances of the pinned Alpine cloud image, one VIF each
// on the switch NI. With BULK_VM_DATA_MIB and BULK_CTR_DATA_MIB, each
// instance additionally attaches a data volume of random content that is
// distinct per instance, so every app has an image of its own to download,
// verify and copy, like the diversified images of a real deployment; the
// device disk is sized to hold them all twice. EVE's admission check for
// application memory is switched off: it pads every instance by the VMM
// overhead it estimates, which would make the default batch need a 40 GiB
// device, while EVE's own budgets, which are what runs out, do not depend
// on it.
//
// Phases:
//  1. Apply the base configuration (port, NI) and record the device's boot
//     time and the budgets EVE's services run within.
//  2. Serve the VM images from evetest's image server, subscribe to the
//     device logs for watchdog stall reports and slow-agent warnings, and
//     start sampling the eve cgroup and the load average, so the whole
//     deployment is covered.
//  3. Add every application to the configuration and apply it at once.
//     BULK_STORMS_DURING_DEPLOY times, after BULK_STORM_DELAY_MIN minutes
//     of deployment, power-cycle the device in the middle of it -- the
//     field's resets hit while volumes were still being created, and
//     every boot then redid that heaviest phase. Then wait until every
//     application reports RUNNING, however long the starved control plane
//     takes within the timeout (the framework's own wait would give up on
//     a download that shows no progress for a few minutes, which is
//     exactly what a starved pillar looks like).
//  4. With BULK_APP_CHURN, start the churn inside every container.
//  5. Watch the device for a settle period and assert it survived: boot
//     time unchanged and no watchdog stall reported.
//  6. BULK_RESTART_STORMS times: power-cycle the device (the reboots the
//     test expects), wait until every application is RUNNING again,
//     restart the churn, and watch the device for a longer settle period
//     before asserting again. The framework independently fails the test
//     on any reboot beyond the requested ones.
//  7. Assert that every application is still RUNNING. The worst
//     slow-agent delays are logged for diagnosis, not asserted: the
//     warning threshold is tens of seconds and trips on slow hosts too.
//
// Parameters: HYPERVISOR, CPUS, RAM_SIZE_MB and DISK_SIZE_MB (shared with
// the rest of the suite; the test raises them to its own floors),
// BULK_CONTAINER_APPS, BULK_VM_APPS, BULK_CTR_MEMORY_MIB, BULK_VM_DATA_MIB
// and BULK_CTR_DATA_MIB (0 attaches no data volume), BULK_REAL_IMAGES,
// BULK_APP_CHURN, BULK_CHURN_LOG_LINES, BULK_RESTART_STORMS,
// BULK_STORMS_DURING_DEPLOY, BULK_STORM_DELAY_MIN, BULK_LINK_DELAY_MS and
// BULK_LINK_RATE_KBPS (the last two impair the uplink on the SDN side, to
// place the controller as far away as a cloud controller is).
func TestBulkAppDeployment(test *testing.T) {
	const (
		// Floors for the device: large enough to hold the default batch,
		// and far above what EVE's own services are allowed to use.
		minCPUs    = 8
		minRAMMiB  = 32768
		minDiskMiB = 65536
		vmMemory   = 1024 * evetest.MiB
		// For every application to reach RUNNING, downloads included.
		runningTimeout = 50 * time.Minute
		// Per container, for its sshd to become reachable for the churn.
		churnStartTimeout = 5 * time.Minute
		// How long the device is watched after the deployment, and after
		// the restart storm, which is where the field resets came.
		deploySettleTime = 5 * time.Minute
		stormSettleTime  = 15 * time.Minute
		sampleInterval   = 30 * time.Second
	)

	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.CPUsParameter(),
		evetest.RAMSizeMiBParameter(),
		evetest.DiskSizeMiBParameter(),
		evetest.TestParameterDefinition{
			Key:          bulkContainerAppsParamKey,
			DefaultValue: 50,
			Description: evetest.TestParameterDescription{
				Summary: "Number of container applications in the batch",
				Default: "50",
			},
		},
		evetest.TestParameterDefinition{
			Key:          bulkVMAppsParamKey,
			DefaultValue: 0,
			Description: evetest.TestParameterDescription{
				Summary: "Number of VM applications in the batch",
				Default: "0",
			},
		},
		evetest.TestParameterDefinition{
			Key:          bulkVMDataMiBParamKey,
			DefaultValue: 512,
			Description: evetest.TestParameterDescription{
				Summary: "Size in MiB of the random-content data volume " +
					"attached to each VM application; 0 attaches none",
				Default: "512",
			},
		},
		evetest.TestParameterDefinition{
			Key:          bulkCtrMemoryMiBParamKey,
			DefaultValue: 384,
			Description: evetest.TestParameterDescription{
				Summary: "Memory in MiB of each container application " +
					"(real images bring their own)",
				Default: "384",
			},
		},
		evetest.TestParameterDefinition{
			Key:          bulkCtrDataMiBParamKey,
			DefaultValue: 0,
			Description: evetest.TestParameterDescription{
				Summary: "Size in MiB of the random-content data volume " +
					"attached to each container application, standing in " +
					"for a distinct image per container; 0 attaches none",
				Default: "0",
			},
		},
		evetest.TestParameterDefinition{
			Key:          bulkRealImagesParamKey,
			DefaultValue: false,
			Description: evetest.TestParameterDescription{
				Summary: "Deploy real workload images (databases, a search " +
					"engine, a CI server, ...; see realImages) in the " +
					"containers instead of the test container; no churn then",
				Default: "false",
			},
		},
		evetest.TestParameterDefinition{
			Key:          bulkAppChurnParamKey,
			DefaultValue: false,
			Description: evetest.TestParameterDescription{
				Summary: "Run an IP-address and console-log churn inside " +
					"every container application",
				Default: "false",
			},
		},
		evetest.TestParameterDefinition{
			Key:          bulkChurnLogLinesParamKey,
			DefaultValue: 20,
			Description: evetest.TestParameterDescription{
				Summary: "Console lines each container prints per churn " +
					"step (two steps a second)",
				Default: "20",
			},
		},
		evetest.TestParameterDefinition{
			Key:          bulkRestartStormsParamKey,
			DefaultValue: 1,
			Description: evetest.TestParameterDescription{
				Summary: "Number of power cycles after the deployment, each " +
					"restarting every application at once; 0 skips them",
				Default: "1",
			},
		},
		evetest.TestParameterDefinition{
			Key:          bulkDeployStormsParamKey,
			DefaultValue: 0,
			Description: evetest.TestParameterDescription{
				Summary: "Number of power cycles in the middle of the " +
					"deployment, each BULK_STORM_DELAY_MIN minutes after the " +
					"batch was applied or the previous boot",
				Default: "0",
			},
		},
		evetest.TestParameterDefinition{
			Key:          bulkStormDelayMinParamKey,
			DefaultValue: 8,
			Description: evetest.TestParameterDescription{
				Summary: "Minutes of deployment to allow before a " +
					"mid-deployment power cycle",
				Default: "8",
			},
		},
		evetest.TestParameterDefinition{
			Key:          bulkLinkDelayMsParamKey,
			DefaultValue: 0,
			Description: evetest.TestParameterDescription{
				Summary: "Latency in ms added to the device's uplink for " +
					"the whole test, to place the controller far away; " +
					"0 leaves the link alone",
				Default: "0",
			},
		},
		evetest.TestParameterDefinition{
			Key:          bulkLinkRateKBpsParamKey,
			DefaultValue: 0,
			Description: evetest.TestParameterDescription{
				Summary: "Rate cap in KB/s on the device's uplink once " +
					"the deployment is running (so that image downloads " +
					"are not throttled); 0 leaves the link alone",
				Default: "0",
			},
		},
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	countCtrApps := evetest.GetTestParameter[int](bulkContainerAppsParamKey)
	countVMApps := evetest.GetTestParameter[int](bulkVMAppsParamKey)
	vmDataMiB := evetest.GetTestParameter[int](bulkVMDataMiBParamKey)
	ctrDataMiB := evetest.GetTestParameter[int](bulkCtrDataMiBParamKey)
	ctrMemory := uint64(evetest.GetTestParameter[int](bulkCtrMemoryMiBParamKey)) * evetest.MiB
	withRealImages := evetest.GetTestParameter[bool](bulkRealImagesParamKey)
	withChurn := evetest.GetTestParameter[bool](bulkAppChurnParamKey) &&
		!withRealImages
	churnLogLines := evetest.GetTestParameter[int](bulkChurnLogLinesParamKey)
	storms := evetest.GetTestParameter[int](bulkRestartStormsParamKey)
	deployStorms := evetest.GetTestParameter[int](bulkDeployStormsParamKey)
	stormDelay := time.Duration(
		evetest.GetTestParameter[int](bulkStormDelayMinParamKey)) * time.Minute
	linkDelayMs := evetest.GetTestParameter[int](bulkLinkDelayMsParamKey)
	linkRateKBps := evetest.GetTestParameter[int](bulkLinkRateKBpsParamKey)
	cpus := max(evetest.GetCPUsParameterValue(), minCPUs)
	ramMiB := max(evetest.GetRAMSizeMiBParameterValue(), minRAMMiB)
	// Every data volume lands on the device twice, as the downloaded blob
	// and as the volume, on top of the base disk floor.
	dataMiB := countVMApps*vmDataMiB + countCtrApps*ctrDataMiB
	diskMiB := max(evetest.GetDiskSizeMiBParameterValue(),
		uint32(2*dataMiB)+minDiskMiB)

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			MinCPUs:           cpus,
			MinRAMInMiB:       ramMiB,
			MinDiskSizeInMiB:  diskMiB,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")
	log := evetest.Logger()

	vmImage, known := alpineCloudImages[device.GetArch()]
	if countVMApps > 0 && !known {
		test.Skipf("no pinned Alpine cloud image for %s", device.GetArch())
	}

	// currentBootTime returns the boot time the device reports once it
	// differs from previous, or any reported boot time when previous is
	// zero.
	currentBootTime := func(previous time.Time) (bootTime time.Time) {
		t.Eventually(func() bool {
			info := device.GetDeviceInfo()
			if info == nil || info.GetBootTime() == nil {
				return false
			}
			bootTime = info.GetBootTime().AsTime()
			return previous.IsZero() ||
				bootTime.Sub(previous).Abs() >= 5*time.Second
		}, 3*time.Minute, 5*time.Second).Should(BeTrue(),
			"device info with a new boot time was not received")
		return bootTime
	}

	// Phase 1: base configuration, boot time and budgets.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	// EVE admits an instance only if its memory plus the VMM overhead it
	// estimates (about 380 MiB even for a small container) still fits in
	// the device's RAM, which would make the default batch need a 40 GiB
	// device for the fraction of it the batch really uses. The field
	// devices had RAM to spare, and what runs out here are EVE's own
	// budgets, which this check does not touch.
	cfgProps := types.NewConfigItemValueMap()
	cfgProps.SetGlobalValueBool(types.IgnoreMemoryCheckForApps, true)
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
	niUUID := devConfig.AddNetworkInstance(evetest.SwitchNetworkInstanceConfig{
		DisplayName: "switch-ni",
		Port:        "ethernet0",
	})
	device.ApplyConfig(devConfig, true, true)
	bootTime := currentBootTime(time.Time{})
	logControlPlaneBudget(device)
	evetest.Checkpoint("base-config-applied")

	// impairLink applies traffic control to the device's uplink on the SDN
	// side; the model is restored on exit so a failure cannot leave the SDN
	// altered for the next test.
	impairLink := func(tc *api.TrafficControl) {
		model := proto.Clone(netmodels.SingleEthWithDHCP).(*api.NetworkModel)
		for _, port := range model.Ports {
			if port.LogicalLabel == "eth0" {
				port.TrafficControl = tc
			}
		}
		evetest.UpdateNetworkModel(model)
	}
	if linkDelayMs > 0 || linkRateKBps > 0 {
		defer evetest.UpdateNetworkModel(netmodels.SingleEthWithDHCP)
	}
	if linkDelayMs > 0 {
		log.Infof("Adding %d ms of latency to the uplink", linkDelayMs)
		impairLink(&api.TrafficControl{Delay: uint32(linkDelayMs)})
	}

	// Phase 2: images, log watches and the sampler.
	imageServer := func(format eveconfig.Format, path, sha256 string,
		sizeBytes uint64) evetest.HTTPStorage {
		return evetest.HTTPStorage{
			ImageFormat:       format,
			ImageSHA256:       sha256,
			MaxDownloadBytes:  sizeBytes,
			ImageRelativePath: path,
			ServerAddress:     evetest.GetImageServerIPv4().String(),
			ServerPort:        evetest.GetImageServerPort(),
		}
	}
	var pushed []pushedRealImage
	if withRealImages && countCtrApps > 0 {
		pushed = pushRealImages(t)
		evetest.Checkpoint("real-images-published")
	}
	var vmRootImage evetest.HTTPStorage
	if countVMApps > 0 {
		path := evetest.FetchAndServeImageFile(
			"https://dl-cdn.alpinelinux.org"+vmImage.relativePath,
			"bulk-alpine.qcow2", vmImage.sha256)
		vmRootImage = imageServer(eveconfig.Format_QCOW2, path,
			vmImage.sha256, vmImage.sizeBytes)
	}

	stalls, stopStallWatch := watchWatchdogStalls(device)
	defer stopStallWatch()
	slowAgents, stopSlowAgentWatch := watchSlowAgents(device)
	defer stopSlowAgentWatch()
	stopSampler := startControlPlaneSampler(device, sampleInterval)
	defer stopSampler()

	// Phase 3: the batch.
	vif := func(i int) []evetest.AppNetworkAdapter {
		return []evetest.AppNetworkAdapter{
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
		}
	}
	// dataVolume attaches a data volume of random content, distinct per
	// app, as a raw block device; nil when sizeMiB is 0.
	dataVolume := func(appName string, sizeMiB int) []evetest.MountConfig {
		if sizeMiB <= 0 {
			return nil
		}
		sizeBytes := uint64(sizeMiB) * evetest.MiB
		name := appName + "-data"
		path, sha256 := evetest.CreateRandomImageFile(name+".img", sizeBytes)
		volUUID := devConfig.AddVolume(name,
			imageServer(eveconfig.Format_RAW, path, sha256, sizeBytes),
			sizeBytes)
		return []evetest.MountConfig{{VolumeUUID: volUUID}}
	}
	appUUIDs := make([]uuid.UUID, 0, countCtrApps+countVMApps)
	for i := range countCtrApps {
		name := fmt.Sprintf("bulk-ctr-%d", i)
		config := evetest.ApplicationInstanceConfig{
			DisplayName: name,
			Activate:    true,
			Image: evetest.DockerContainer{
				ImageName: ubuntuCtrImage,
				Tag:       ubuntuCtrTag,
			},
			VirtualizationMode: eveconfig.VmMode_HVM,
			CPUs:               1,
			MemoryBytes:        ctrMemory,
			NetworkAdapters:    vif(i),
			Mounts:             dataVolume(name, ctrDataMiB),
		}
		if len(pushed) > 0 {
			img := pushed[i%len(pushed)]
			config.Image = img.container
			config.UserData = img.userData
			config.MemoryBytes = img.memory
		}
		appUUIDs = append(appUUIDs, devConfig.AddApplication(config))
	}
	ctrUUIDs := append([]uuid.UUID(nil), appUUIDs...)
	for i := range countVMApps {
		name := fmt.Sprintf("bulk-vm-%d", i)
		appUUIDs = append(appUUIDs, devConfig.AddApplication(
			evetest.ApplicationInstanceConfig{
				DisplayName:        name,
				Activate:           true,
				Image:              vmRootImage,
				VirtualizationMode: eveconfig.VmMode_HVM,
				CPUs:               1,
				MemoryBytes:        vmMemory,
				NetworkAdapters:    vif(countCtrApps + i),
				Mounts:             dataVolume(name, vmDataMiB),
			}))
	}
	log.Infof("Deploying %d container and %d VM applications at once",
		countCtrApps, countVMApps)
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("bulk-config-applied")

	waitAllRunning := func(phase string, notBefore time.Time) {
		errs := waitAppsRunning(device, appUUIDs, notBefore, runningTimeout)
		t.Expect(errs).To(BeEmpty(),
			"%s: not every application reached RUNNING:\n%s", phase,
			describeErrors(errs))
	}
	startChurn := func(phase string) {
		if !withChurn {
			return
		}
		log.Infof("%s: starting the churn inside %d containers", phase,
			len(ctrUUIDs))
		// A container the churn cannot reach is reported, not fatal: the
		// device under observation matters more than one app's sshd, and
		// the final RUNNING check still covers the app itself.
		errs := startAppChurn(device, ctrUUIDs, churnStartTimeout, churnLogLines)
		if len(errs) > 0 {
			log.Warnf("%s: the churn could not be started in %d of %d "+
				"containers:\n%s", phase, len(errs), len(ctrUUIDs),
				describeErrors(errs))
		}
	}
	assertSurvived := func(phase string, expectedBootTime time.Time) {
		bootTimeNow := currentBootTime(time.Time{})
		t.Expect(bootTimeNow).To(BeTemporally("~", expectedBootTime, 5*time.Second),
			"device rebooted during the %s", phase)
		stallReports := drainLogs(stalls)
		t.Expect(stallReports).To(BeEmpty(),
			"EVE services stalled long enough to arm the watchdog during "+
				"the %s:\n%s", phase, describeLogs(stallReports))
		log.Infof("%s: worst slow-agent delays: %s", phase,
			summarizeSlowAgents(drainLogs(slowAgents)))
	}
	settleAndAssert := func(phase string, expectedBootTime time.Time,
		settle time.Duration) {
		log.Infof("%s: all %d applications are running; watching the "+
			"device for %s", phase, len(appUUIDs), settle)
		time.Sleep(settle)
		assertSurvived(phase, expectedBootTime)
	}

	// Phase 3b: power cycles in the middle of the deployment, where the
	// field's resets hit; after each one the deployment resumes from the
	// volumes it had not finished.
	for storm := 1; storm <= deployStorms; storm++ {
		phase := fmt.Sprintf("mid-deployment storm %d", storm)
		log.Infof("%s: letting the deployment run for %s before the "+
			"power cycle", phase, stormDelay)
		time.Sleep(stormDelay)
		assertSurvived(phase, bootTime)
		log.Infof("%s: power-cycling the device in the middle of the "+
			"deployment", phase)
		device.HardReboot(true)
		bootTime = currentBootTime(bootTime)
		evetest.Checkpoint(fmt.Sprintf("mid-deployment-rebooted-%d", storm))
	}

	waitAllRunning("deployment", bootTime)
	evetest.Checkpoint("apps-running")
	if linkRateKBps > 0 {
		log.Infof("Capping the uplink at %d KB/s", linkRateKBps)
		impairLink(&api.TrafficControl{
			Delay:      uint32(linkDelayMs),
			RateLimit:  uint32(linkRateKBps),
			QueueLimit: 256,
			BurstLimit: 64,
		})
	}

	// Phase 4 and 5: churn, then the device must survive the deployment.
	startChurn("deployment")
	settleAndAssert("deployment", bootTime, deploySettleTime)
	evetest.Checkpoint("deployment-settled")

	// Phase 6: the restart storms.
	for storm := 1; storm <= storms; storm++ {
		phase := fmt.Sprintf("restart storm %d", storm)
		log.Infof("%s: power-cycling the device so that all %d "+
			"applications restart at once", phase, len(appUUIDs))
		device.HardReboot(true)
		bootTime = currentBootTime(bootTime)
		evetest.Checkpoint(fmt.Sprintf("rebooted-%d", storm))
		waitAllRunning(phase, bootTime)
		evetest.Checkpoint(fmt.Sprintf("apps-running-after-reboot-%d", storm))
		startChurn(phase)
		settleAndAssert(phase, bootTime, stormSettleTime)
		evetest.Checkpoint(fmt.Sprintf("storm-%d-settled", storm))
	}
	stopSampler()

	// Phase 7: every application is still running.
	for _, appUUID := range appUUIDs {
		info := device.GetAppInfo(appUUID)
		t.Expect(info).ToNot(BeNil())
		t.Expect(info.State).To(Equal(eveinfo.ZSwState_RUNNING),
			"application %s is no longer running", appUUID)
	}
}
