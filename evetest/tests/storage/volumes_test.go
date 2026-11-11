// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// TestVolumes exercises the lifecycle of standalone (app-unreferenced)
// volumes: creation from every supported content source/disk format and
// deletion, plus how volumemgr behaves when /persist runs low on space --
// both for a standalone volume and for an application's own root volume.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- only needed for controller reachability
//     and to pull docker images; volumemgr creates standalone
//     (app-unreferenced) volumes on its own, so no network instance is
//     needed for the standalone-volume part of this test.
//
// Phases
// ------
//  1. Set up a device with a single DHCP mgmt port.
//  2. Create 5 standalone volumes, one per supported disk format/source
//     (docker, qcow2, qcow, vmdk, vhdx -- the qcow2/qcow/vmdk/vhdx images are
//     blank files generated locally via CreateBlankImageFile and served
//     by evetest's built-in HTTP image server). Wait for all 5 to reach
//     ZSwState_CREATED_VOLUME.
//     On ZFS only: set timer.gc.vdisk to its minimum (60s), reboot the
//     device and wait until all 5 volumes are reported as CREATED_VOLUME
//     again. This checks that the zvols survive a reboot and are picked up
//     again by volumemgr at boot. volumemgr runs its garbage collection
//     every timer.gc.vdisk/10, i.e. every 6 minutes by default, and the
//     new value takes effect only from the next boot (the GC ticker is
//     not recreated when the setting changes). After the reboot, the GC
//     therefore runs every 6 seconds while the zvols exist. Then create an
//     unused zvol directly on the device (in persist/clear/volumes, named
//     like a volume EVE has no config for) and verify that the GC destroys
//     it, while the zvols of the configured volumes are kept.
//  3. Disk-space-exhaustion scenario:
//     a. Read the device's current /persist disk metric (total/free).
//     b. Create "blank-vol-1", sized so that the free space remaining after
//     it is allocated drops just below half of /persist's total size --
//     small enough to fit itself, but leaving too little room for a
//     second, half-total-sized volume.
//     c. Attempt to create "blank-vol-2" sized at half of /persist's total.
//     Verify it fails with a VolumeErr mentioning "Remaining" (insufficient
//     disk space), instead of reaching CREATED_VOLUME.
//     d. Delete "blank-vol-1" (freeing space) and verify "blank-vol-2" then
//     succeeds (reaches CREATED_VOLUME).
//     e. Deploy an app whose root volume is also sized at half of
//     /persist's total (competing with blank-vol-2 for the same space).
//     Verify it fails to activate with an AppErr mentioning "Remaining".
//     f. Delete "blank-vol-2" (freeing space) and verify the app then
//     reaches RUNNING.
//     g. Purge the app (PurgeApplication) and verify it goes through
//     PURGING and back to RUNNING.
//     h. Delete the app.
//  4. Delete all 5 standalone volumes from step 2 and verify they are all
//     reported as gone (ZSwState_INVALID).
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//   - FILESYSTEM (ext4|zfs, defaults to ext4). With ZFS, volumes are backed
//     by zvols instead of files, which exercises a different volume handler,
//     and the device is rebooted with a shortened volume GC interval once
//     the standalone volumes are created.
func TestVolumes(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.FilesystemParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			WithFilesystem:    filesystem,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
		evetest.RequireInternetConnectivity{},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
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
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("mgmt-network-ready")

	timeout := 15 * time.Minute
	log := evetest.Logger()

	// Step 2: create one standalone volume per supported format/source.
	const perVolSize = 200 * evetest.MiB
	type namedVolume struct {
		name    string
		uuid    uuid.UUID
		updates <-chan *eveinfo.ZInfoVolume
		stop    func()
	}
	vols := []namedVolume{
		{name: "v-docker"},
		{name: "v-qcow2"},
		{name: "v-qcow"},
		{name: "v-vmdk"},
		{name: "v-vhdx"},
	}
	vols[0].uuid = devConfig.AddVolume("v-docker", evetest.DockerContainer{
		ImageName: "lfedge/evetest-ubuntu-ctr", Tag: "1.0"}, perVolSize)

	qcow2Path, qcow2SHA256 := evetest.CreateBlankImageFile(
		"v-qcow2.qcow2", eveconfig.Format_QCOW2, perVolSize)
	vols[1].uuid = devConfig.AddVolume("v-qcow2", evetest.HTTPStorage{
		ImageFormat:       eveconfig.Format_QCOW2,
		ImageRelativePath: qcow2Path,
		ImageSHA256:       qcow2SHA256,
		ServerAddress:     evetest.GetImageServerIPv4().String(),
	}, perVolSize)

	qcowPath, qcowSHA256 := evetest.CreateBlankImageFile(
		"v-qcow.qcow", eveconfig.Format_QCOW, perVolSize)
	vols[2].uuid = devConfig.AddVolume("v-qcow", evetest.HTTPStorage{
		ImageFormat:       eveconfig.Format_QCOW,
		ImageRelativePath: qcowPath,
		ImageSHA256:       qcowSHA256,
		ServerAddress:     evetest.GetImageServerIPv4().String(),
	}, perVolSize)

	vmdkPath, vmdkSHA256 := evetest.CreateBlankImageFile(
		"v-vmdk.vmdk", eveconfig.Format_VMDK, perVolSize)
	vols[3].uuid = devConfig.AddVolume("v-vmdk", evetest.HTTPStorage{
		ImageFormat:       eveconfig.Format_VMDK,
		ImageRelativePath: vmdkPath,
		ImageSHA256:       vmdkSHA256,
		ServerAddress:     evetest.GetImageServerIPv4().String(),
	}, perVolSize)

	vhdxPath, vhdxSHA256 := evetest.CreateBlankImageFile(
		"v-vhdx.vhdx", eveconfig.Format_VHDX, perVolSize)
	vols[4].uuid = devConfig.AddVolume("v-vhdx", evetest.HTTPStorage{
		ImageFormat:       eveconfig.Format_VHDX,
		ImageRelativePath: vhdxPath,
		ImageSHA256:       vhdxSHA256,
		ServerAddress:     evetest.GetImageServerIPv4().String(),
	}, perVolSize)

	for i := range vols {
		vols[i].updates, vols[i].stop = device.WatchVolumeInfo(vols[i].uuid)
	}
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("standalone-volumes-config-applied")

	log.Infof("Waiting for all 5 standalone volumes to be created")
	for _, v := range vols {
		v := v
		t.Eventually(v.updates, timeout).Should(Receive(matchers.SatisfyPredicate(
			fmt.Sprintf("volume %s is created", v.name),
			func(info *eveinfo.ZInfoVolume) bool {
				return info.State == eveinfo.ZSwState_CREATED_VOLUME
			}).StopIf(volumeHasError)))
	}
	evetest.Checkpoint("standalone-volumes-created")

	// On ZFS, check that the zvols survive a reboot, and make volumemgr run its
	// GC often after it, while the zvols exist. The GC interval is read at
	// boot, hence it is set before the reboot. Watch only the volume info
	// published after the reboot request, so that a CREATED_VOLUME reported
	// before the reboot does not satisfy the check.
	if filesystem == evetest.FilesystemZFS {
		cfgProps := pillartypes.NewConfigItemValueMap()
		cfgProps.SetGlobalValueInt(pillartypes.VdiskGCTime, 60)
		devConfig.SetConfigProperties(cfgProps)
		device.ApplyConfig(devConfig, true, true)
		for i := range vols {
			vols[i].stop()
			vols[i].updates, vols[i].stop = device.WatchVolumeInfo(vols[i].uuid)
		}
		device.RequestReboot(false, true)
		evetest.Checkpoint("rebooted-with-zvols")
		for _, v := range vols {
			t.Eventually(v.updates, timeout).Should(Receive(matchers.SatisfyPredicate(
				fmt.Sprintf("volume %s is created again after the reboot", v.name),
				func(info *eveinfo.ZInfoVolume) bool {
					return info.State == eveinfo.ZSwState_CREATED_VOLUME
				}).StopIf(volumeHasError)))
		}
		evetest.Checkpoint("standalone-volumes-survived-reboot")

		// The GC must destroy a zvol that belongs to no known volume...
		listZVols := func() string {
			out, _, err := device.RunShellScript(
				"eve exec pillar zfs list -H -o name -t volume -r "+
					pillartypes.PersistDataset, 30*time.Second, 0)
			t.Expect(err).ToNot(HaveOccurred())
			return out
		}
		unusedZVol := fmt.Sprintf("%s/%s.0",
			pillartypes.VolumeClearZFSDataset, uuid.Must(uuid.NewV4()))
		_, stderr, err := device.RunShellScript(
			"eve exec pillar zfs create -V 16M "+unusedZVol, 30*time.Second, 0)
		t.Expect(err).ToNot(HaveOccurred(), "zfs create failed: %s", stderr)
		t.Expect(listZVols()).To(ContainSubstring(unusedZVol))
		t.Eventually(listZVols, 2*time.Minute, 5*time.Second).ShouldNot(
			ContainSubstring(unusedZVol), "unused zvol %s was not garbage-collected",
			unusedZVol)
		// ...but keep the zvols of the configured volumes (all but the docker
		// one, which is a container and not stored in a zvol).
		zvols := listZVols()
		for _, v := range vols[1:] {
			t.Expect(zvols).To(ContainSubstring(v.uuid.String()),
				"zvol of the configured volume %s was garbage-collected", v.name)
		}
		evetest.Checkpoint("unused-zvol-garbage-collected")
	}

	// Step 3: disk-space-exhaustion scenario.
	const mib = evetest.MiB
	const safetyMarginMiB = 200

	metricsUpdates, stopMetricsWatch := device.WatchDeviceMetrics()
	var persistDisk *evemetrics.DiskMetric
	t.Eventually(metricsUpdates, 5*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"device reports a non-zero /persist disk metric",
		func(m *evemetrics.DeviceMetric) bool {
			for _, d := range m.GetDisk() {
				if d.GetMountPath() == "/persist" && d.GetTotal() > 0 {
					persistDisk = d
					return true
				}
			}
			return false
		})))
	stopMetricsWatch()

	totalMiB := persistDisk.GetTotal()
	freeMiB := persistDisk.GetFree()
	halfTotalMiB := totalMiB / 2
	log.Infof("/persist: total=%d MiB free=%d MiB half_total=%d MiB",
		totalMiB, freeMiB, halfTotalMiB)
	t.Expect(freeMiB-halfTotalMiB).To(BeNumerically(">=", safetyMarginMiB),
		"insufficient /persist free space for the test "+
			"(free=%d MiB, half_total=%d MiB, need free >= half_total + %d MiB)",
		freeMiB, halfTotalMiB, safetyMarginMiB)
	// blankVol1Size: large enough that the free space remaining after
	// blank-vol-1 is below half_total (so blank-vol-2 cannot fit), but
	// bounded by current free space so blank-vol-1 itself still fits.
	blankVol1SizeMiB := freeMiB - halfTotalMiB + safetyMarginMiB
	halfTotalBytes := halfTotalMiB * mib
	blankVol1Bytes := blankVol1SizeMiB * mib

	blankVol1UUID := devConfig.AddBlankVolume("blank-vol-1", blankVol1Bytes, true)
	blankVol1Updates, stopBlankVol1Watch := device.WatchVolumeInfo(blankVol1UUID)
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("blank-vol-1-config-applied")

	t.Eventually(blankVol1Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"blank-vol-1 is created",
		func(info *eveinfo.ZInfoVolume) bool {
			return info.State == eveinfo.ZSwState_CREATED_VOLUME
		}).StopIf(volumeHasError)))
	stopBlankVol1Watch()
	evetest.Checkpoint("blank-vol-1-created")

	// blank-vol-2 is expected to fail: not enough free space remains.
	blankVol2UUID := devConfig.AddBlankVolume("blank-vol-2", halfTotalBytes, true)
	blankVol2Updates, stopBlankVol2Watch := device.WatchVolumeInfo(blankVol2UUID)
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("blank-vol-2-config-applied")

	log.Infof("Waiting for blank-vol-2 to fail due to insufficient disk space")
	t.Eventually(blankVol2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"blank-vol-2 reports insufficient remaining disk space",
		func(info *eveinfo.ZInfoVolume) bool {
			return containsIgnoreCase(info.GetVolumeErr().GetDescription(), "Remaining")
		})))
	evetest.Checkpoint("blank-vol-2-failed-as-expected")

	// Delete blank-vol-1 to free up space for blank-vol-2.
	devConfig.DeleteVolume(blankVol1UUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(blankVol2Updates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"blank-vol-2 is created after blank-vol-1 is freed",
		func(info *eveinfo.ZInfoVolume) bool {
			return info.State == eveinfo.ZSwState_CREATED_VOLUME
		})))
	stopBlankVol2Watch()
	evetest.Checkpoint("blank-vol-2-created")

	// Deploy an app whose root volume competes with blank-vol-2 for the same
	// space; it is expected to fail to activate.
	appUUID := devConfig.AddApplication(evetest.ApplicationInstanceConfig{
		DisplayName: "vol-space-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr", Tag: "1.0"},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		DiskBytes:          halfTotalBytes,
	})
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("vol-space-app-config-applied")

	log.Infof("Waiting for vol-space-app to fail due to insufficient disk space")
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"vol-space-app reports insufficient remaining disk space",
		func(info *eveinfo.ZInfoApp) bool {
			for _, appErr := range info.GetAppErr() {
				if containsIgnoreCase(appErr.GetDescription(), "Remaining") {
					return true
				}
			}
			return false
		})))
	evetest.Checkpoint("vol-space-app-failed-as-expected")

	// Delete blank-vol-2 to free up space; the app should then start.
	devConfig.DeleteVolume(blankVol2UUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"vol-space-app reaches RUNNING",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_RUNNING
		})))
	evetest.Checkpoint("vol-space-app-running")

	// Purge the app and verify it comes back up.
	log.Infof("Purging vol-space-app")
	device.PurgeApplication(appUUID, evetest.BumpVolumeGeneration, false, 0)
	t.Eventually(appUpdates, 2*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"vol-space-app enters a transient purge state",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_PURGING ||
				info.State == eveinfo.ZSwState_HALTING
		})))
	device.WaitUntilAppIsRunning(appUUID, timeout)
	evetest.Checkpoint("vol-space-app-purged")

	// Resync devConfig with the config as mutated by PurgeApplication before
	// deleting the app through it.
	devConfig = device.GetConfig()
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"vol-space-app is gone",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))
	stopAppWatch()

	// Step 4: delete the 5 standalone volumes from step 2 and verify they
	// are all gone.
	for _, v := range vols {
		devConfig.DeleteVolume(v.uuid)
	}
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("standalone-volumes-delete-applied")

	for _, v := range vols {
		v := v
		t.Eventually(v.updates, timeout).Should(Receive(matchers.SatisfyPredicate(
			fmt.Sprintf("volume %s is gone", v.name),
			func(info *eveinfo.ZInfoVolume) bool {
				return info.State == eveinfo.ZSwState_INVALID
			})))
		v.stop()
	}
}

// containsIgnoreCase reports whether s contains substr, ignoring case.
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
