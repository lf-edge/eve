// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"strconv"
	"strings"
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
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// TestExtraDiskAttach  verifies that an additional (non-root) volume can be attached
// to a running application as a raw block device -- i.e. with no MountDir, so the
// guest sees it as a plain disk rather than a mounted filesystem -- and shows
// up inside the guest.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port; also provides
//     Internet access to pull the app's container image.
//
// Phases
// ------
//  1. Setup: one Local NI ("disk-ni") on ethernet0. Deploy "disk-app"
//     (lfedge/evetest-ubuntu-ctr:1.0, HVM) with an SSH port-forward
//     (2222->22) and no extra volumes. Wait for RUNNING and for the app's SSH
//     daemon to become reachable. Record the baseline disk count (via
//     `lsblk -d -o TYPE`, counting entries of type "disk").
//  2. Create a standalone blank volume (AddBlankVolume) and mount it on the
//     app with an empty MountDir (UpdateApplication). An empty MountDir
//     attaches the volume as a raw block device instead of a mounted
//     filesystem (see MountConfig.MountDir). Adding a mount changes the
//     app's VolumeRefList count, which zedmanager always treats as
//     requiring a purge (a restart of the domain that preserves the app
//     instance's identity -- not a full delete+recreate); UpdateApplication
//     bumps the purge counter for this automatically. Wait through
//     PURGING -> RUNNING, then verify the guest's disk count increases by
//     exactly one.
//  3. Cleanup: delete the app, wait for ZSwState_INVALID, then delete the
//     extra disk's volume (independent of the app's own lifecycle -- see
//     MountConfig).
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestExtraDiskAttach(test *testing.T) {
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
			Name:              devName,
			WithHypervisor:    hypervisor,
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

	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "disk-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.22.22.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.22.22.2"),
			End:   evetest.IPAddress("10.22.22.254"),
		},
		Gateway: evetest.IPAddress("10.22.22.1"),
		MTU:     1500,
	})

	// Step 1: deploy the app with no extra volumes. appConfig is kept around
	// so the later UpdateApplication call only changes Mounts, leaving
	// every other field as originally deployed.
	appConfig := evetest.ApplicationInstanceConfig{
		DisplayName: "disk-app",
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        512 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				PortFwdRules: []evetest.PortFwdRule{
					{Protocol: evetest.NetworkProtocolTCP, EdgeNodePort: 2222, AppPort: 22},
				},
			},
		},
	}
	appUUID := devConfig.AddApplication(appConfig)
	appUpdates, stopAppWatch := device.WatchAppInfo(appUUID)
	defer stopAppWatch()
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("app-deployed")

	timeout := 15 * time.Minute
	timeoutExcludingDownload := 5 * time.Minute
	device.WaitUntilAppIsRunning(appUUID, timeoutExcludingDownload)
	evetest.Checkpoint("app-running")

	sshTimeout := 20 * time.Second
	polling := 5 * time.Second
	log := evetest.Logger()

	log.Infof("Waiting for disk-app's SSH daemon to become reachable")
	t.Eventually(func(t Gomega) {
		_, _, err := device.RunShellScriptInsideApp(
			appUUID, ubuntuCtrAppAuth, "hostname", sshTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred())
	}, timeout, polling).Should(Succeed())
	evetest.Checkpoint("ssh-ready")

	baselineDisks, _, err := countGuestDisks(device, appUUID, sshTimeout)
	t.Expect(err).ToNot(HaveOccurred())
	log.Infof("Baseline guest disk count: %d", baselineDisks)

	// Step 2: create a standalone blank volume and mount it with an empty
	// MountDir -- attached as a raw (unmounted) disk.
	const extraDiskSize = 16 * evetest.MiB
	extraDiskVolUUID := devConfig.AddBlankVolume("disk-app-extra-disk", extraDiskSize, true)
	appConfig.Mounts = []evetest.MountConfig{
		{VolumeUUID: extraDiskVolUUID, MountDir: ""},
	}
	devConfig.UpdateApplication(appUUID, appConfig)
	device.ApplyConfig(devConfig, false, false)
	evetest.Checkpoint("extra-disk-attached")

	log.Infof("Waiting for disk-app to purge (restart) with the extra disk")
	t.Eventually(appUpdates, 2*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"disk-app enters a transient purge state",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_PURGING ||
				info.State == eveinfo.ZSwState_HALTING
		})))
	device.WaitUntilAppIsRunning(appUUID, timeout)
	evetest.Checkpoint("extra-disk-purged")

	log.Infof("Waiting for the extra disk to show up inside the guest")
	t.Eventually(func() (int, error) {
		n, _, err := countGuestDisks(device, appUUID, sshTimeout)
		return n, err
	}, timeout, polling).Should(Equal(baselineDisks + 1))

	// Step 3: cleanup.
	devConfig.DeleteApplication(appUUID)
	device.ApplyConfig(devConfig, false, false)
	t.Eventually(appUpdates, timeout).Should(Receive(matchers.SatisfyPredicate(
		"app is gone",
		func(info *eveinfo.ZInfoApp) bool {
			return info.State == eveinfo.ZSwState_INVALID
		}).StopIf(appHasError)))

	// The extra disk's volume is independent of the app and outlives it;
	// remove it explicitly.
	devConfig.DeleteVolume(extraDiskVolUUID)
	device.ApplyConfig(devConfig, false, false)
}

// countGuestDisks returns the number of block devices of type "disk" (i.e.
// excluding partitions, loop devices, etc.) reported by lsblk inside the
// application identified by appUUID.
func countGuestDisks(device *evetest.EdgeDevice, appUUID uuid.UUID,
	timeout time.Duration) (int, string, error) {
	out, stderr, err := device.RunShellScriptInsideApp(appUUID, ubuntuCtrAppAuth,
		"lsblk -d -n -o TYPE | grep -c disk", timeout, 0)
	if err != nil {
		return 0, stderr, err
	}
	n, convErr := strconv.Atoi(strings.TrimSpace(out))
	if convErr != nil {
		return 0, stderr, convErr
	}
	return n, stderr, nil
}
