// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestVolumeSizeAlignment creates two image-backed volumes on the same device,
// one whose size is a multiple of 2 MiB and one whose size is not, and requires
// both to be delivered.
//
// On EVE-k an image-backed volume is imported into its PVC by CDI, which refuses
// an import whose target size is smaller than the volume Longhorn actually
// provisioned:
//
//	Virtual image size <V> is larger than the reported available storage <T>.
//	A larger PVC is required.
//
// Longhorn rounds a claim up to a 2 MiB multiple, and EVE passes the requested
// size through unrounded, so a size that is not already a 2 MiB multiple yields
// V > T and the import then retries forever. Measured on a device: a claim for
// 2147487744 was provisioned 2050Mi, while a 2 MiB-aligned claim for 201326592
// was provisioned exactly.
//
// The aligned volume is the control: it isolates alignment from everything else
// about the import, so a run where only the unaligned volume fails implicates
// the size and nothing else. Blank volumes cannot show this on EVE-k — they are
// created directly and never reach CDI — hence image-backed volumes here.
//
// Test params
// -----------
//   - HYPERVISOR: run with kubevirt to exercise CDI; under KVM this passes
//     trivially, since no PVC is involved.
func TestVolumeSizeAlignment(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:           devName,
			WithHypervisor: hypervisor,
			// EVE-k runs k3s, KubeVirt, Longhorn and CDI alongside EVE itself, and
			// Longhorn documents a 4 GiB per-node floor for its own use. Below these
			// the cluster never comes up and the volumes fail for want of a node
			// rather than for their size.
			MinRAMInMiB:       16384,
			MinCPUs:           8,
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

	// Content stays well under both volumes so the image is never the binding
	// constraint; the sizes below are what the volumes are declared as.
	const contentSize = 4 * evetest.MiB
	imgFile, sha256Hex := evetest.CreateRandomImageFile(
		"volume-size-alignment.bin", contentSize)
	image := evetest.HTTPStorage{
		ImageFormat:       eveconfig.Format_RAW,
		ImageRelativePath: imgFile,
		ImageSHA256:       sha256Hex,
		ServerAddress:     evetest.GetImageServerIPv4().String(),
		ServerPort:        evetest.GetImageServerPort(),
	}

	const alignedSize = 96 * evetest.MiB // 100663296, a multiple of 2 MiB
	const unalignedSize = 100000000      // 95.37 MiB, not a multiple of 2 MiB

	expectVolumeDelivered(t, device, devConfig, "size-aligned", image, alignedSize)
	evetest.Checkpoint("aligned-volume-delivered")

	expectVolumeDelivered(t, device, devConfig, "size-unaligned", image, unalignedSize)
	evetest.Checkpoint("unaligned-volume-delivered")
}

// expectVolumeDelivered declares one image-backed volume of the given size and
// requires it to reach CREATED_VOLUME, then removes it. Failing the wait names
// the size, because the size is the variable under test.
func expectVolumeDelivered(t *WithT, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig, displayName string,
	image evetest.ApplicationImageStorage, sizeBytes uint64) {
	log := evetest.Logger()
	log.Infof("declaring volume %s of %d bytes (%d past a 2 MiB boundary)",
		displayName, sizeBytes, sizeBytes%(2*evetest.MiB))

	volUUID := devConfig.AddVolume(displayName, image, sizeBytes)
	updates, stop := device.WatchVolumeInfo(volUUID)
	defer stop()
	device.ApplyConfig(devConfig, false, false)

	t.Eventually(updates, 15*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"volume "+displayName+" is delivered",
		func(info *eveinfo.ZInfoVolume) bool {
			return info.State == eveinfo.ZSwState_CREATED_VOLUME
		})), "volume %s (%d bytes) was never delivered", displayName, sizeBytes)

	devConfig.DeleteVolume(volUUID)
	device.ApplyConfig(devConfig, false, false)
}
