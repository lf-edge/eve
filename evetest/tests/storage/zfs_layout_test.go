// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// TestZFSDiskLayout exercises EVE's ZFS disk-array layout/RAID
// reconfiguration end to end, using a fixed set of 5 extra virtio disks
// provisioned up front (RequireEdgeDevice.ExtraDisks) so every stage always
// runs regardless of the test environment: raid1 (2 disks) -> raid10 (4
// disks) -> offline one disk (degraded) -> restore -> replace one disk with
// the 5th (spare) disk.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- only needed for controller reachability.
//
// Phases
// ------
//  1. Set up a device with WithFilesystem: FilesystemZFS and 5 extra 2 GiB
//     virtio disks (/dev/vdb.../dev/vdf; /dev/vda is the boot disk). At this
//     point the extra disks are not yet part of the zpool (EVE's installer
//     only ever creates the pool from the boot disk's own P3 partition).
//     Reduce timer.metric.diskscan.interval to its minimum so config-driven
//     disk changes are picked up quickly.
//  2. Verify the initial pool (boot disk only) is reported
//     STORAGE_STATUS_ONLINE.
//  3. Apply a RAID1 layout (DiskLayoutRAID1, disks vdb+vdc) via
//     SetDisksLayout. Verify StorageInfo reports vdb.
//  4. Apply a RAID10 layout (DiskLayoutRAID10, disks vdb-vde). Verify
//     StorageInfo reports vdc and vdd.
//  5. Mark the first disk (vdb) offline. Verify it is reported
//     STORAGE_STATUS_OFFLINE and the pool becomes STORAGE_STATUS_DEGRADED.
//  6. Bring the disk back online (remove the offline marker). Verify no
//     disk is reported DEGRADED/OFFLINE anymore.
//  7. Replace the first disk (vdb) with the spare (vdf, the 5th extra disk).
//     Verify StorageInfo reports vdf and no longer reports vdb.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM). ZFS disk-layout/RAID configuration
//     itself is independent of hypervisor choice; the parameter exists for
//     consistency with the rest of TestStorageSuite. Note that DiskName's
//     /dev/vdX naming for the extra disks has only been verified under KVM.
func TestZFSDiskLayout(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	const extraDiskSize = 2 * evetest.GiB
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:           devName,
			WithHypervisor: hypervisor,
			WithFilesystem: evetest.FilesystemZFS,
			ExtraDisks: []uint64{
				extraDiskSize, extraDiskSize, extraDiskSize, extraDiskSize, extraDiskSize},
			DeviceReusePolicy: evetest.CreateFromScratchWithLiveImage,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.DiskScanMetricInterval, 15)
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
	device.ApplyConfig(devConfig, true, true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(20 * time.Minute)
	}
	evetest.Checkpoint("mgmt-network-ready")

	devInfoUpdates, stopDevInfoWatch := device.WatchDeviceInfo()
	defer stopDevInfoWatch()

	timeout := 10 * time.Minute
	log := evetest.Logger()

	// Step 2: the initial pool (boot disk only) must be online.
	log.Infof("Waiting for the initial (boot-disk-only) pool to be online")
	t.Eventually(devInfoUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"storage pool is online",
		func(info *eveinfo.ZInfoDevice) bool {
			for _, pool := range info.GetStorageInfo() {
				if pool.GetStorageState() == eveinfo.StorageStatus_STORAGE_STATUS_ONLINE {
					return true
				}
			}
			return false
		})))
	evetest.Checkpoint("initial-pool-online")

	// Step 3: RAID1 layout (vdb + vdc).
	log.Infof("Applying RAID1 layout (vdb+vdc)")
	devConfig.SetDisksLayout(evetest.DisksLayout{LayoutType: evetest.DiskLayoutRAID1})
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("raid1-config-applied")

	t.Eventually(devInfoUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"storage info reports /dev/vdb online",
		func(info *eveinfo.ZInfoDevice) bool {
			status, found := diskStatus(
				flattenStorageDisks(info.GetStorageInfo()), evetest.DiskName(0))
			return found && status == eveinfo.StorageStatus_STORAGE_STATUS_ONLINE
		})))
	evetest.Checkpoint("raid1-applied")

	// Step 4: grow to RAID10 layout (vdb-vde).
	log.Infof("Applying RAID10 layout (vdb-vde)")
	devConfig.SetDisksLayout(evetest.DisksLayout{LayoutType: evetest.DiskLayoutRAID10})
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("raid10-config-applied")

	t.Eventually(devInfoUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"storage info reports /dev/vdc and /dev/vdd online",
		func(info *eveinfo.ZInfoDevice) bool {
			disks := flattenStorageDisks(info.GetStorageInfo())
			statusC, foundC := diskStatus(disks, evetest.DiskName(1))
			statusD, foundD := diskStatus(disks, evetest.DiskName(2))
			return foundC && statusC == eveinfo.StorageStatus_STORAGE_STATUS_ONLINE &&
				foundD && statusD == eveinfo.StorageStatus_STORAGE_STATUS_ONLINE
		})))
	evetest.Checkpoint("raid10-applied")

	// Step 5: take the first disk (vdb) offline; pool becomes degraded.
	log.Infof("Marking /dev/vdb offline")
	devConfig.SetDisksLayout(evetest.DisksLayout{
		LayoutType:   evetest.DiskLayoutRAID10,
		OfflineDisks: []uint{0},
	})
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("disk-offline-config-applied")

	t.Eventually(devInfoUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"/dev/vdb is offline and the pool is degraded",
		func(info *eveinfo.ZInfoDevice) bool {
			disks := flattenStorageDisks(info.GetStorageInfo())
			status, found := diskStatus(disks, evetest.DiskName(0))
			if !found || status != eveinfo.StorageStatus_STORAGE_STATUS_OFFLINE {
				return false
			}
			for _, pool := range info.GetStorageInfo() {
				if pool.GetStorageState() == eveinfo.StorageStatus_STORAGE_STATUS_DEGRADED {
					return true
				}
			}
			return false
		})))
	evetest.Checkpoint("disk-offlined")

	// Step 6: bring the disk back online; the pool should no longer be degraded.
	log.Infof("Bringing /dev/vdb back online")
	devConfig.SetDisksLayout(evetest.DisksLayout{LayoutType: evetest.DiskLayoutRAID10})
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("disk-restore-config-applied")

	t.Eventually(devInfoUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"no disk is degraded or offline",
		func(info *eveinfo.ZInfoDevice) bool {
			for _, pool := range info.GetStorageInfo() {
				if pool.GetStorageState() == eveinfo.StorageStatus_STORAGE_STATUS_DEGRADED {
					return false
				}
			}
			disks := flattenStorageDisks(info.GetStorageInfo())
			status, found := diskStatus(disks, evetest.DiskName(0))
			return found && status == eveinfo.StorageStatus_STORAGE_STATUS_ONLINE
		})))
	evetest.Checkpoint("disk-restored")

	// Step 7: replace the first disk (vdb) with the spare (vdf).
	log.Infof("Replacing /dev/vdb with the spare disk /dev/vdf")
	devConfig.SetDisksLayout(evetest.DisksLayout{
		LayoutType:   evetest.DiskLayoutRAID10,
		ReplaceDisks: []uint{0},
	})
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("disk-replace-config-applied")

	t.Eventually(devInfoUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"/dev/vdf replaced /dev/vdb and the pool is not degraded",
		func(info *eveinfo.ZInfoDevice) bool {
			for _, pool := range info.GetStorageInfo() {
				if pool.GetStorageState() == eveinfo.StorageStatus_STORAGE_STATUS_DEGRADED {
					return false
				}
			}
			disks := flattenStorageDisks(info.GetStorageInfo())
			_, oldFound := diskStatus(disks, evetest.DiskName(0))
			newStatus, newFound := diskStatus(disks, evetest.DiskName(4))
			return newFound && newStatus == eveinfo.StorageStatus_STORAGE_STATUS_ONLINE && !oldFound
		})))
	evetest.Checkpoint("disk-replaced")
}
