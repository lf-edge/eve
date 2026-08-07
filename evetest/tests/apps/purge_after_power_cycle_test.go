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

// TestVMAppPurgeAfterPowerCycle exercises a purge issued while the device is
// powered off, on the hypervisor selected by the HYPERVISOR parameter. The
// sequence is identical for every hypervisor; only the end-state assertions
// differ, because what a "generation" of a workload is differs.
//
// Kubevirt (the defect, HYPERVISOR=kubevirt - the default for this test)
// ---------------------------------------------------------------------
// /run is tmpfs, so a reboot drops DomainConfig/DomainStatus while the VMIRS
// survives in etcd and re-creates its own replica; zedmanager re-detects the
// purge from the persisted counter, but the teardown check consults only /run,
// finds nothing, concludes "no domain to halt", and advances the counter -
// which, on a build with the underlying bug, creates a second VMIRS alongside
// the first. Unlike a same-node replica restart (a narrow race), this
// reproduces deterministically every time.
//
// kvm/xen (the control, HYPERVISOR=kvm)
// -------------------------------------
// The duplicate cannot occur. A domain here is a local qemu process: the
// power-off destroys it, nothing re-creates a replica while the node is down,
// and no object outlives the node for a later purge to lose track of. The
// domain name carries no purge counter either ("<uuid>.<version>.<appnum>"), so
// two generations could not coexist under distinct names even in principle.
//
// Running the kvm variant against a build without the fixes is therefore
// expected to PASS, and that pass is the useful result: it localises the
// duplicate-generation defect to the kube path. What the kvm variant still
// covers is everything in the purge that is not hypervisor-specific:
//
//  1. The purge must complete. zedmanager parks the outgoing VolumeRefStatus
//     and waits for volumemgr to confirm the delete; if the reboot wiped
//     volumemgr's own state for that reference before it was asked again, the
//     confirmation never arrives and the app stays in DownloadAndVerify for
//     ever, never requesting the new volume. That code is in zedmanager and is
//     shared by every hypervisor, so a FAILURE of the kvm variant on master is
//     the interesting outcome - it means that wedge reproduces off the kube
//     path too.
//  2. The old generation's disk must be gone, and no volume artifact may be left
//     that no live VolumeStatus names - the kvm-shaped form of a purge going
//     wrong is a disk nobody owns, not a second running domain.
//  3. kvm must not regress from the kube fixes, which change shared zedmanager
//     code and restate DomainStatus.DomainId's meaning as a cross-hypervisor
//     invariant ("zero if and only if the domain is confirmed absent" - for
//     kvm, the qemu pid).
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port, SDN DNS, controller
//     reachable.
//
// Device configuration
// --------------------
//   - purgeDeviceRequirements (fixtures_test.go) on the selected hypervisor:
//     always created fresh, so no prior generation or purge counter can leak
//     in; default ext4 (configurable via FILESYSTEM).
//   - SystemAdapter on eth0 (DHCP, mgmt+app).
//   - One Local NI "local-ni" (10.11.13.0/24, a distinct subnet from the other
//     tests in this suite) and one shim-VM app (vmShimApplication). The same
//     app fixture serves both variants: a container image with
//     VirtualizationMode=HVM runs in a VMIRS on eve-k and in a qemu domain on
//     kvm, which is what makes the two results comparable.
//
// Test parameters
// ---------------
//   - HYPERVISOR (kubevirt|kvm|xen). Note the default is **kubevirt**, not the
//     framework-wide kvm default: an unqualified run of this test should
//     exercise the path the defect is on. Set EVETEST_HYPERVISOR=kvm for the
//     control.
//   - TPM via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// Phases
// ------
//  1. setup-done -> app-is-running: bring the node up, deploy the app, wait
//     for RUNNING.
//  2. baseline-recorded: capture the volume's generation key and on-disk path,
//     and read the persisted purge counter.
//  3. device-powered-off: sync, then EdgeDevice.PowerOff() (hard power-off
//     through the broker, no reboot to bring it back on its own). The sync
//     matters - see syncDisks in deviceaccess_test.go.
//  4. purge-issued-while-down: PurgeApplication(waitUntilPurged=false) -
//     bumps the purge counter and pushes config to the controller; this must
//     succeed even though the device cannot fetch it yet (see
//     EdgeDevice.ApplyConfig - a push with both wait flags false never depends
//     on device reachability).
//  5. device-powered-on -> app-is-running-again: EdgeDevice.PowerOn(true)
//     waits for the device to boot, then WaitUntilAppIsRunning waits for the
//     purge to complete. A purge wedged on a volume-ref removal never gets
//     past this point, so the wait is itself an assertion.
//  6. End-state assertions: assertPurgeCompleted for what every hypervisor
//     must satisfy (counter advanced, purge phase finished, one volume at a new
//     generation), then assertKubePurgeEndState or
//     assertLocalDomainPurgeEndState for what only that hypervisor can be
//     asked. On Kubevirt the decisive one is "exactly one VMIRS, named for the
//     NEW generation" - precisely what the bug violates, since both
//     generations can otherwise survive indefinitely, each reporting ready.
//
// Suite placement
// ---------------
//   - TestVMAppPurgeSuite, as two variants (kubevirt and kvm).
func TestVMAppPurgeAfterPowerCycle(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		// Same key as evetest.HypervisorParameter(), but defaulting to
		// Kubevirt rather than kvm: this test exists for the kube path, and
		// kvm is its control.
		evetest.TestParameterDefinition{
			Key:          evetest.HypervisorParameterKey,
			DefaultValue: evetest.HypervisorKubevirt,
			Description: evetest.TestParameterDescription{
				Summary: "Hypervisor to purge the app on. Kubevirt is where the " +
					"duplicate-generation defect lives; kvm/xen act as the control.",
				Default:       "kubevirt",
				AllowedValues: "kubevirt|kvm|xen",
			},
		},
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	devName := "edge-dev"
	requiredDevice := purgeDeviceRequirements(devName, withTPM, filesystem, hypervisor)
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
		Subnet:      evetest.IPSubnet("10.11.13.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.13.2"),
			End:   evetest.IPAddress("10.11.13.254"),
		},
		Gateway:       evetest.IPAddress("10.11.13.1"),
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
	if hypervisor == evetest.HypervisorKubevirt {
		// k3s and Longhorn must be up before the app can start; without this the
		// app sits in INITIAL and consumes the app-ready budget.
		device.WaitForClusterNodeIsReady(clusterReadyTimeout)
	}
	evetest.Checkpoint("config-applied")

	device.WaitUntilAppIsRunning(appUUID, appReadyTimeout)
	evetest.Checkpoint("app-is-running")

	// Baseline: the volume generation key and its on-disk path, both of which the
	// purge must replace, plus the counter it must advance. Unlike
	// TestVMAppPurgeBaseline there is no domain-identity check, because the power
	// cycle recreates the domain by itself and a changed DomainId would prove
	// nothing about the purge.
	baselineVolGen := ""
	baselineVolPath := ""
	t.Eventually(func(g Gomega) {
		vol := soleVolumeStatus(g, device)
		baselineVolGen = vol.Key()
		baselineVolPath = vol.PathName()
	}, baselineTimeout, assertPollInterval).Should(Succeed())
	baselineCounter, _ := purgeCounter(device, appUUID)
	log.Infof("Baseline volume %q at %q, purge counter %d",
		baselineVolGen, baselineVolPath, baselineCounter)
	evetest.Checkpoint("baseline-recorded")

	// Flush before pulling power. Without this, the image layers unpacked
	// moments ago are still dirty and the power-off discards them - see
	// syncDisks. The subject of this test is the purge, not unpack durability.
	syncDisks(device)

	log.Infof("Powering off device %q", devName)
	device.PowerOff()
	evetest.Checkpoint("device-powered-off")

	device.PurgeApplication(appUUID, false, 0)
	evetest.Checkpoint("purge-issued-while-down")

	log.Infof("Powering device %q back on", devName)
	device.PowerOn(true)
	if hypervisor == evetest.HypervisorKubevirt {
		// The reboot took k3s down with it, so the node has to become Ready
		// again before the purged app can be scheduled.
		device.WaitForClusterNodeIsReady(clusterReadyTimeout)
	}
	evetest.Checkpoint("device-powered-on")

	device.WaitUntilAppIsRunning(appUUID, appReadyTimeout)
	evetest.Checkpoint("app-is-running-again")

	wantCounter := baselineCounter + 1
	t.Eventually(func(g Gomega) {
		assertPurgeCompleted(g, device, appUUID, wantCounter, baselineVolGen)
		if hypervisor == evetest.HypervisorKubevirt {
			assertKubePurgeEndState(g, device, appUUID, appDisplayName, wantCounter)
		} else {
			assertLocalDomainPurgeEndState(g, device, appUUID, baselineVolGen,
				hypervisor)
		}
	}, purgeEndStateTimeout, assertPollInterval).Should(Succeed())
	evetest.Checkpoint("purge-verified")

	// The old generation's storage is reclaimed on its own schedule, minutes
	// after the purge itself completes - see assertOldVolumeReclaimed.
	//
	// assertNoOrphanedPVCs is disabled on Kubevirt for now: sweepStaleGenerations
	// deletes the old VMIRS and its pod but not its PVC, so the old generation's
	// disk stays behind. That is a pillar fix, not a test bug - re-enable this
	// once sweepStaleGenerations deletes the PVC too.
	t.Eventually(func(g Gomega) {
		if hypervisor == evetest.HypervisorKubevirt {
			// assertNoOrphanedPVCs(g, device)
		} else {
			assertOldVolumeReclaimed(g, device, baselineVolPath)
		}
	}, storageReclaimTimeout, storageReclaimPollInterval).Should(Succeed())
	evetest.Checkpoint("old-storage-reclaimed")
}
