// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"strings"
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

// TestZVolProvisionedSizeReported verifies that a ZFS zvol-backed volume reports
// its provisioned size (the zvol "volsize"), rather than 0, in the disk metrics.
//
// Regression context
// ------------------
// zfs.fillImgInfo() populated ImgInfo.ActualSize (from "usedbydataset") but
// never set ImgInfo.VirtualSize. volumeHandlerZVol.GetVolumeDetails() returns
// VirtualSize as the volume's max size, so every zvol reported a provisioned
// size of 0: volumemgr's AppDiskMetric.ProvisionedBytes was 0, and hence the
// controller-visible ZMetricVolume.TotalBytes and VolumeResources.MaxSizeBytes
// were 0 too -- even though the zvol has a non-zero volsize. The fix reads the
// zvol "volsize" property into VirtualSize.
//
// Scenario
// --------
// The test is intentionally minimal and hermetic: it does NOT deploy an
// application and does NOT write any data. The bug is about the *provisioned*
// (allotted) size, which is fixed at volume-creation time and independent of
// usage, so a standalone empty block-device volume is sufficient to exercise
// it. volumemgr creates standalone (app-unreferenced) volumes on its own, so no
// application is needed to trigger creation.
//
// Requires a KVM device whose /persist is ZFS: a non-container, non-ISO volume
// is only backed by a zvol when /persist is ZFS. On EXT4 there is no zvol and
// the code path under test does not run, so the test skips.
//
// Phases
// ------
//  1. Set up a KVM + ZFS device with a single DHCP mgmt port.
//  2. Apply a config that declares one standalone empty 1 GiB block-device
//     volume (no app, no network instance).
//  3. Wait for volumemgr to create the volume (state CREATED_VOLUME) and,
//     once its disk metrics have been (re)computed, assert the provisioned
//     size is the zvol volsize (== 1 GiB), not 0. This is checked both via
//     the controller-visible EVE API (ZInfoVolume/ZMetricVolume) and via
//     volumemgr's own AppDiskMetric pubsub object.
func TestZVolProvisionedSizeReported(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// A 1 GiB volume is an exact multiple of the ZFS volblocksize (16 KiB), so
	// the resulting zvol volsize -- and therefore the reported provisioned size
	// -- is exactly 1 GiB with no block-size rounding.
	const blankVolumeSize = 1 * evetest.GiB

	// Set up a KVM device with ZFS persist. ZFS is required: only then is the
	// blank RAW volume backed by a zvol (see VolumeStatus.UseZVolDisk).
	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    evetest.HypervisorKVM,
			WithFilesystem:    evetest.FilesystemZFS,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// Build the device config: keep the mgmt port (so the device stays
	// reachable) and add a single standalone empty block-device volume.
	// Shorten the disk-scan and metric report intervals to their minimum so the
	// provisioned size is (re)computed and reported to the controller quickly.
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.DiskScanMetricInterval, 5)
	cfgProps.SetGlobalValueInt(pillartypes.MetricInterval, 5)
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
	volUUID := devConfig.AddBlankVolume("zvol-provisioned-test", blankVolumeSize)

	volInfoUpdates, stopVolInfoWatch := device.WatchVolumeInfo(volUUID)
	defer stopVolInfoWatch()
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("blank-volume-config-applied")

	// Wait for the volume to be created. CREATED_VOLUME is the volume-equivalent
	// of ONLINE; by this point volumemgr has created the zvol and knows its
	// volsize. Resources.MaxSizeBytes is VolumeResources, derived from the same
	// AppDiskMetric.ProvisionedBytes the fix corrects.
	timeout := 3 * time.Minute
	var volInfo *eveinfo.ZInfoVolume
	t.Eventually(volInfoUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"Volume is created with a non-zero provisioned (max) size",
		func(info *eveinfo.ZInfoVolume) bool {
			volInfo = info
			return info.GetState() == eveinfo.ZSwState_CREATED_VOLUME &&
				info.GetResources().GetMaxSizeBytes() > 0
		})))
	evetest.Checkpoint("blank-volume-created")

	// EVE API (info): the volume resources max size is the provisioned size.
	t.Expect(volInfo.GetResources().GetMaxSizeBytes()).To(
		BeNumerically("~", uint64(blankVolumeSize), evetest.MiB),
		"ZInfoVolume.Resources.MaxSizeBytes should be the zvol volsize (~1 GiB), was 0 before the fix")

	// EVE API (metrics): ZMetricVolume.TotalBytes mirrors ProvisionedBytes.
	// Metrics are reported periodically, so poll until the volume appears.
	t.Eventually(func() uint64 {
		vm := device.GetVolumeMetrics(volUUID)
		if vm == nil {
			return 0
		}
		return vm.GetTotalBytes()
	}, timeout, 5*time.Second).Should(
		BeNumerically("~", uint64(blankVolumeSize), evetest.MiB),
		"ZMetricVolume.TotalBytes should be the zvol volsize (~1 GiB), was 0 before the fix")

	// volumemgr pubsub object: AppDiskMetric.ProvisionedBytes is the value the
	// fix populates. The zvol device path embeds the volume UUID, so match on
	// it. Poll because volumemgr recomputes disk metrics on its own interval.
	t.Eventually(func() uint64 {
		for _, m := range evetest.ReadAllPublications[pillartypes.AppDiskMetric](
			device, "volumemgr", false) {
			if strings.Contains(m.DiskPath, volUUID.String()) {
				return m.ProvisionedBytes
			}
		}
		return 0
	}, timeout, 5*time.Second).Should(
		BeNumerically("~", uint64(blankVolumeSize), evetest.MiB),
		"volumemgr AppDiskMetric.ProvisionedBytes should be the zvol volsize (~1 GiB), was 0 before the fix")
}
