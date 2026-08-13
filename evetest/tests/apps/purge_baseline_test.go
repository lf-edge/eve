// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TestVMAppPurgeBaseline exercises a plain purge of a healthy, undisturbed
// app: exactly one VMIRS must exist both before and after, and it must be
// named for the new purge generation afterward. It is used as the control
// case for the other tests in this suite (TestVMAppPurgeAfterPowerCycle,
// TestVMAppPurgeDuringFailover) and as a general regression guard for the
// purge path.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port, SDN DNS, controller
//     reachable.
//
// Device configuration
// --------------------
//   - purgeDeviceRequirements (fixtures_test.go), called with
//     HypervisorKubevirt - this test needs a cluster and is not run on any
//     other hypervisor;
//     DeviceReusePolicy=CreateFromScratchWithLiveImage (a stale VMIRS
//     generation or purge counter from a prior test must never leak into
//     this one), default ext4 (configurable via FILESYSTEM), grub options
//     capping dom0/eve/ctrd vcpus for faster cluster formation.
//   - SystemAdapter on eth0 (DHCP, mgmt+app).
//   - One Local NI "local-ni" (10.11.12.0/24) and one shim-VM app
//     (vmShimApplication in fixtures_test.go: evetest-ubuntu-ctr:1.0,
//     VirtualizationMode=HVM, so it runs as a VMIRS).
//
// Test parameters
// ---------------
//   - TPM via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// Phases
// ------
//  1. setup-done -> app-is-running: bring up the single-node eve-k cluster,
//     deploy the app, wait for RUNNING.
//  2. baseline-recorded: capture the volume's generation key, the running
//     domain's DomainId, and the persisted purge counter (0 or absent).
//  3. purge-issued -> purge-complete: device.PurgeApplication(waitUntilPurged
//     =true) - this exercises the framework's own PURGING/HALTING -> RUNNING
//     wait, i.e. the "normal" zedmanager state-machine path.
//  4. End-state assertions: exactly one VMIRS, named for the NEW generation;
//     persisted purge counter advanced by exactly one; purge phase back to
//     NotInprogress with the app RUNNING; exactly one volume; a DomainId
//     different from the baseline, i.e. the domain really was recreated; no PVC
//     in the cluster left orphaned (unreferenced by any current VolumeStatus);
//     and a volume generation key different from the baseline, i.e. the disk was
//     rebuilt (which holds because PurgeApplication bumps the referenced
//     volumes' generationCount the way a controller does - see the note in
//     appvolumes_test.go).
//
// Suite placement
// ---------------
//   - TestVMAppPurgeSuite (all tests in this suite are pinned to Kubevirt).
func TestVMAppPurgeBaseline(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	devName := "edge-dev"
	requiredDevice := purgeDeviceRequirements(devName, withTPM, filesystem,
		evetest.HypervisorKubevirt)
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SingleEthWithDHCP,
	}
	evetest.Setup(requiredDevice, requiredNetModel)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	devConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})

	niUUID := devConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.12.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.12.2"),
			End:   evetest.IPAddress("10.11.12.254"),
		},
		Gateway:       evetest.IPAddress("10.11.12.1"),
		EnableFlowlog: true,
		MTU:           1500,
		ForwardLLDP:   false,
	})
	const appDisplayName = "purge-app"
	appUUID := devConfig.AddApplication(vmShimApplication(appDisplayName, niUUID))

	device := evetest.GetEdgeDevice(devName)
	device.ApplyConfig(devConfig, true, true)
	log := evetest.Logger()
	log.Infof("Submitted config with application UUID=%v", appUUID)
	// k3s and Longhorn must be up before the app can start; without this the
	// app sits in INITIAL and consumes the app-ready budget.
	device.WaitForClusterNodeIsReady(clusterReadyTimeout)
	evetest.Checkpoint("config-applied")

	device.WaitUntilAppIsRunning(appUUID, appReadyTimeout)
	evetest.Checkpoint("app-is-running")

	// The volume generation and the domain's identity before the purge. Nothing
	// else restarts the app in this test, so a DomainId that has not changed
	// afterwards means the purge advanced its counter without recreating the
	// domain.
	baselineVolGen := ""
	baselineDomainID := 0
	t.Eventually(func(g Gomega) {
		baselineVolGen = soleVolumeStatus(g, device).Key()
		domStatus, found := appDomainStatus(device, appUUID)
		g.Expect(found).To(BeTrue(), "expected a published DomainStatus for the app")
		g.Expect(domStatus.DomainId).NotTo(BeZero(), "expected a live DomainId")
		baselineDomainID = domStatus.DomainId
	}, baselineTimeout, assertPollInterval).Should(Succeed())
	baselineCounter, _ := purgeCounter(device, appUUID)
	evetest.Checkpoint("baseline-recorded")

	device.PurgeApplication(appUUID, true, purgeCompleteTimeout)
	evetest.Checkpoint("purge-complete")

	wantCounter := baselineCounter + 1
	t.Eventually(func(g Gomega) {
		assertPurgeCompleted(g, device, appUUID, wantCounter, baselineVolGen)
		assertDomainReplaced(g, device, appUUID, baselineDomainID)
		assertKubePurgeEndState(g, device, appUUID, appDisplayName, wantCounter)
	}, purgeEndStateTimeout, assertPollInterval).Should(Succeed())
	evetest.Checkpoint("purge-verified")

	// The old generation's PVC is reclaimed after the purge completes, not as
	// part of it - see assertOldVolumeReclaimed for why this gets its own clock.
	t.Eventually(func(g Gomega) {
		assertNoOrphanedPVCs(g, device)
	}, storageReclaimTimeout, storageReclaimPollInterval).Should(Succeed())
	evetest.Checkpoint("old-storage-reclaimed")
}
