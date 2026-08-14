// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

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
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	powerCutMethodParamKey = "POWER_CUT_METHOD"

	// powerCutPowerCycle takes the node down by pulling its (virtual) power, so
	// EVE gets no chance to act on anything still in flight.
	powerCutPowerCycle = "power-cycle"
	// powerCutControllerReboot takes the node down with a reboot command from
	// the controller. zedagent stops parsing a configuration as soon as it sees
	// a new reboot counter, so a purge submitted after that command is not
	// looked at until the device comes back - the same deferral a power cut
	// produces, reached without cutting power.
	powerCutControllerReboot = "controller-reboot"
)

// TestVMAppPurgeAfterPowerCycle exercises a purge issued while the device is
// powered off, on the hypervisor selected by the HYPERVISOR parameter. The
// sequence is identical for every hypervisor; only the end-state assertions
// differ, because what a "generation" of a workload is differs.
//
// Kubevirt (HYPERVISOR=kubevirt - the default for this test)
// ----------------------------------------------------------
// This is the path on which a purge can lose track of the generation it is
// replacing, and the sequence below is what makes that possible. /run is
// tmpfs, so a reboot drops DomainConfig/DomainStatus while the VMIRS survives
// in etcd and re-creates its own replica. zedmanager re-detects the purge from
// the persisted counter, but a teardown check that consults only /run finds
// nothing, concludes "no domain to halt" and advances the counter, which leaves
// the old generation's VMIRS in the cluster beside the new one. Both then
// survive indefinitely, each reporting ready. The test drives that sequence
// deterministically rather than through the narrow same-node replica-restart
// race, so it holds as a guard rather than reproducing only sometimes.
//
// kvm/xen (the control, HYPERVISOR=kvm)
// -------------------------------------
// A duplicate generation cannot occur here. A domain is a local qemu process:
// the power-off destroys it, nothing re-creates a replica while the node is
// down, and no object outlives the node for a later purge to lose track of. The
// domain name carries no purge counter either ("<uuid>.<version>.<appnum>"), so
// two generations could not coexist under distinct names even in principle.
//
// The kvm variant is therefore expected to pass even where the kube path is
// broken, and that asymmetry is the point: it localises a surviving generation
// to the kube path instead of to code both share. What the kvm variant does
// cover is everything in a purge that is not hypervisor-specific:
//
//  1. The purge must complete. zedmanager parks the outgoing VolumeRefStatus
//     and waits for volumemgr to confirm the delete; if the reboot wiped
//     volumemgr's own state for that reference before it was asked again, the
//     confirmation never arrives and the app stays in DownloadAndVerify for
//     ever, never requesting the new volume. That code is in zedmanager and is
//     shared by every hypervisor, so a kvm failure here says the wedge is not
//     specific to the kube path.
//  2. The old generation's disk must be gone, and no volume artifact may be left
//     that no live VolumeStatus names - the kvm-shaped form of a purge going
//     wrong is a disk nobody owns, not a second running domain.
//  3. kvm must not regress when the kube path changes, because the two share
//     zedmanager code, and because DomainStatus.DomainId carries the same
//     meaning on every hypervisor: zero if and only if the domain is confirmed
//     absent, and for kvm the qemu pid otherwise.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- one mgmt+app port, SDN DNS, controller
//     reachable.
//
// Device configuration
// --------------------
//   - purgeDeviceRequirements (purge_helpers_test.go) on the selected hypervisor:
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
//   - HYPERVISOR (kubevirt|kvm|xen), read from the suite: this test runs
//     wherever the suite runs, and both hypervisors are worth running - see
//     above for what each one can and cannot show.
//   - TPM via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//   - POWER_CUT_METHOD (power-cycle|controller-reboot, defaults to
//     power-cycle): how the node is taken down while the purge is submitted.
//     Both leave the purge to be discovered on the next boot; the
//     controller-reboot form reaches that window through zedagent's config
//     parsing rather than by pulling the power, so it also covers a purge
//     deferred by an orderly reboot.
//
// Phases
// ------
//  1. setup-done -> app-is-running: bring the node up, deploy the app, wait
//     for RUNNING.
//  2. baseline-recorded: capture the volume's generation key and on-disk path,
//     and read the persisted purge counter.
//  3. device-powered-off: EdgeDevice.SyncDisks(), then the node goes down by
//     the selected POWER_CUT_METHOD - PowerOff() (hard power-off through the
//     broker, no reboot to bring it back on its own) or RequestReboot(false).
//     The sync matters - see EdgeDevice.SyncDisks.
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
//     NEW generation": nothing else notices an old generation that stays in
//     the cluster, since both would survive indefinitely, each reporting ready.
//  7. purge-survived-reboot: reboot the node once more, after the purge has
//     already settled, and re-run the phase-6 assertions unchanged. The field
//     report this test comes from had a further reboot adding another copy of
//     the volume without removing the first, so reaching the right end state
//     once is not the same as holding it across a boot. Reusing the phase-6
//     assertions is deliberate: the decisive kube check ("exactly one VMIRS,
//     named for the NEW generation") is exactly what a resurrected generation
//     would break.
//
// Suite placement
// ---------------
//   - TestAppsSuite, last, with no variants of its own: the suite is run once
//     per hypervisor, so declaring variants here would run each one twice.
func TestVMAppPurgeAfterPowerCycle(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
		evetest.TestParameterDefinition{
			Key:          powerCutMethodParamKey,
			DefaultValue: powerCutPowerCycle,
			Description: evetest.TestParameterDescription{
				Summary:       "How to take the node down while the purge is submitted",
				Default:       powerCutPowerCycle,
				AllowedValues: powerCutPowerCycle + "|" + powerCutControllerReboot,
			},
		},
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()
	powerCutMethod := evetest.GetTestParameter[string](powerCutMethodParamKey)
	if powerCutMethod != powerCutPowerCycle &&
		powerCutMethod != powerCutControllerReboot {
		evetestT.Fatalf("Unsupported %s value %q (expected %s or %s)",
			powerCutMethodParamKey, powerCutMethod,
			powerCutPowerCycle, powerCutControllerReboot)
	}

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
	// TestVMAppPurgeReplacesVMIRS there is no domain-identity check, because
	// the power cycle recreates the domain by itself and a changed DomainId
	// would prove nothing about the purge.
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

	// The layers unpacked moments ago are still dirty, and this test is about
	// the purge, not about what a power cut does to them - see SyncDisks.
	device.SyncDisks()

	// Subscribe before the node goes down, so the first post-boot info message
	// cannot be missed while the controller-reboot variant waits for it.
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()

	switch powerCutMethod {
	case powerCutPowerCycle:
		log.Infof("Powering off device %q", devName)
		device.PowerOff()
		evetest.Checkpoint("device-powered-off")

		device.PurgeApplication(appUUID, false, 0)
		evetest.Checkpoint("purge-issued-while-down")

		log.Infof("Powering device %q back on", devName)
		device.PowerOn(true)

	case powerCutControllerReboot:
		rebootRequestedAt := time.Now()
		log.Infof("Rebooting device %q from the controller", devName)
		device.RequestReboot(false)
		evetest.Checkpoint("device-rebooting")

		device.PurgeApplication(appUUID, false, 0)
		evetest.Checkpoint("purge-issued-while-down")

		// The device brings itself back, so the only thing left to wait for is
		// evidence that the reboot happened at all. Without it the assertions
		// below could run against the pre-reboot state and pass while the purge
		// has not been looked at yet.
		t.Eventually(devUpdates, deviceRebootTimeout).Should(Receive(
			matchers.SatisfyPredicate("device has rebooted",
				func(dinfo *eveinfo.ZInfoDevice) bool {
					ts := dinfo.GetLastRebootTime()
					return ts != nil && ts.AsTime().After(rebootRequestedAt)
				})))
	}
	if hypervisor == evetest.HypervisorKubevirt {
		// The node went down and took k3s with it, so it has to become Ready
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
	// after the purge itself completes - see assertOldVolumeReclaimed. On
	// Kubevirt the reclaim is volumemgr's periodic GC pass rather than the
	// purge: sweepStaleGenerations deletes the old VMIRS and its pod, and the
	// PVC outlives both until that pass collects it.
	t.Eventually(func(g Gomega) {
		if hypervisor == evetest.HypervisorKubevirt {
			assertNoOrphanedPVCs(g, device)
		} else {
			assertOldVolumeReclaimed(g, device, baselineVolPath)
		}
	}, storageReclaimTimeout, storageReclaimPollInterval).Should(Succeed())
	evetest.Checkpoint("old-storage-reclaimed")

	// The end state has to survive a boot, not merely be reached once: the
	// field report had a further reboot adding another copy of the volume
	// without removing the first.
	log.Infof("Rebooting device %q now that the purge has settled", devName)
	device.SoftReboot(true)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(clusterReadyTimeout)
	}
	device.WaitUntilAppIsRunning(appUUID, appReadyTimeout)

	// Deliberately the phase-6 assertions verbatim: a generation resurrected by
	// the reboot is exactly what "exactly one VMIRS, named for the NEW
	// generation" rules out, and the counter must not have moved either.
	t.Eventually(func(g Gomega) {
		assertPurgeCompleted(g, device, appUUID, wantCounter, baselineVolGen)
		if hypervisor == evetest.HypervisorKubevirt {
			assertKubePurgeEndState(g, device, appUUID, appDisplayName, wantCounter)
		} else {
			assertLocalDomainPurgeEndState(g, device, appUUID, baselineVolGen,
				hypervisor)
		}
	}, purgeEndStateTimeout, assertPollInterval).Should(Succeed())
	evetest.Checkpoint("purge-survived-reboot")
}
