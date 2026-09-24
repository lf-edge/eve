// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

const (
	// The vault content whose fate through the cut is what this test asserts on.
	powerCutMarkerPath = "/persist/vault/evetest-powercut-marker"
	powerCutMarkerText = "KONVERT-ZFS-VAULT-POWERCUT-4e81b60a-survives-an-interrupted-swap"
)

// TestKvmToKZFSVaultPowerCutMidSwap cuts power to a ZFS device in the middle of
// the kvm→EVE-K vault migration's rename swap, and follows the vault contents
// from there to a committed EVE-K device.
//
// The swap renames the carried-over filesystem vault aside and then renames the
// staging zvol into its place. Between those two renames the vault path does not
// exist, and only a real interruption says what ZFS's rename and the swap
// record's fsync do when the machine disappears there.
//
// The boot that follows the cut is EVE-kvm: the EVE-K partition is not committed
// yet, so the device falls back. EVE-kvm cannot mount a zvol vault, so the
// completed copy is no use to it and recovery renames the parked pre-migration
// vault back into place, discards the copy, and clears the swap record. That
// leaves a device that boots with its contents and a migration for the next
// EVE-K boot to redo from the start.
//
// What each phase asserts is the contents themselves, read out of the vault the
// device is running on -- the datasets holding them are worth nothing to an
// operator whose vault comes up empty.
//
// Phases:
//  1. Baseline: /persist moved onto the extra disk and up as ZFS, the vault
//     settled on a local TPM unlock, a marker written into it, and the fault
//     point armed.
//  2. Push the kvm→k update and wait for the device to park inside the swap.
//  3. Cut power there and bring it back.
//  4. EVE-kvm restored the vault: it holds the marker, and neither leftover nor
//     swap record remains.
//  5. Disarm the fault and boot the installed EVE-K partition: the migration is
//     redone and the vault is a zvol still holding the marker.
//  6. Commit the running partition, which is where recovery is free to reclaim
//     pool space; the migrated vault must survive it intact.
//
// Requires an image built with FAULT_INJECTION=y: the fault point that parks the
// migration in that window is compiled in only under that tag, and without it
// this test arms a marker nothing reads, the migration completes normally, and
// the power cut lands somewhere uninteresting. Arming asserts the device honoured
// the marker rather than letting that pass silently.
//
// The device is fixed rather than parameterized: a TPM, ZFS /persist, and the
// same second disk holding the pool as TestKvmToKZFSVaultMigration, which needs
// the broker's disk-edit capability.
func TestKvmToKZFSVaultPowerCutMidSwap(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	defineSharedParameters()
	p := resolveDeviceParams(t)
	p = raiseFloorsForCarriedVolume(t, p)
	// As in TestKvmToKZFSVaultMigration: the build under test, so the flavor
	// change reaches the vault migration with no repartition in the way.
	p.initialVersion = ""
	p.initialRepo = ""
	p.initialHypervisor = evetest.HypervisorKVM
	p.withTPM = true
	p = twodiskParams(p)

	device := setupDevice(t, p, evetest.FilesystemZFS,
		[]uint64{twodiskExtraDiskBytes},
		evetest.CreateFromScratchWithLiveImage,
		evetest.RequireCapabilities{
			Capabilities: []api.Capability{
				api.Capability_CAPABILITY_EDIT_DEVICE_DISK,
			},
		})
	log := evetest.Logger()

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	applyMgmtNetwork(device, devConfig)

	// The pool belongs on a disk of its own, as in eden's twodisk-zfs leg: the
	// swap this test cuts into copies the vault within that pool.
	movePersistToExtraDisk(t, device, devConfig)

	// Phase 1.
	log.Infof("baseline: /persist must be ZFS")
	assertPersistType(t, device, "zfs")
	log.Infof("settling the vault on a local TPM unlock")
	settleVaultLocal(t, device)
	log.Infof("writing a marker into the vault at %s", powerCutMarkerPath)
	writeMarkerFile(t, device, powerCutMarkerPath, powerCutMarkerText)
	evetest.Checkpoint("vault-settled")

	log.Infof("arming the migration fault at step %q", faultStepBeforePromote)
	armVaultMigrationFault(t, device)

	// Phase 2. Not waiting for the upgrade: the device is going to park
	// mid-migration and then lose power, so it never reports the new version the
	// wait expects.
	log.Infof("pushing the kvm→k update; the migration will park mid-swap")
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKubevirt,
		evetest.BaseOSDatastoreHTTP, false, false, conversionUpgradeTimeout)

	log.Infof("waiting for the device to reach the swap window")
	reached := waitForFaultWindow(t, device, 40*time.Minute)
	log.Infof("device parked in the swap window: %s", reached)
	evetest.Checkpoint("parked-mid-swap")

	// Phase 3. PowerOff bypasses ACPI, so nothing in the guest gets to flush on
	// the way down -- which is the point.
	log.Infof("cutting power with the swap half-done")
	device.PowerOff()
	// PowerOn's wait relies on a reboot-time republish that a true power cycle
	// does not produce (see its doc comment), so come back without it and
	// confirm recovery from the device state instead.
	device.PowerOn(false)
	device.DisableRebootAccounting(
		"a hard power-cycle, then a cross-flavor fallback that reboots a " +
			"variable number of times as EVE-K comes up and gives way")
	evetest.Checkpoint("powered-back-on")

	log.Infof("waiting for the device to come back")
	waitForVaultRecovered(t, device, 40*time.Minute)

	// Phase 4. Until the vault is unlocked its mountpoint is an empty directory
	// on the parent dataset, so the contents read as destroyed rather than as not
	// yet available -- including in the state dump the assertions below quote.
	waitVaultUnlocked(t, device)
	state := describeVaultState(device, powerCutMarkerPath)
	log.Infof("post-cut device state:\n%s", state)

	log.Infof("asserting EVE-kvm came back on the restored vault, with its contents")
	t.Expect(zfsProperty(t, device, "type", vaultDataset)).To(Equal("filesystem"),
		"the vault EVE-kvm came back on is not the restored pre-migration one:\n%s", state)
	marker, err := runEVE(device, "eve exec pillar cat "+powerCutMarkerPath)
	t.Expect(err).NotTo(HaveOccurred(),
		"the vault contents are not readable after the cut:\n%s", state)
	t.Expect(strings.TrimSpace(marker)).To(Equal(powerCutMarkerText),
		"the vault does not hold the contents written before the cut:\n%s", state)

	datasets := listPersistDatasets(t, device)
	t.Expect(datasets).NotTo(ContainElement(vaultBackupDataset),
		"the pre-migration vault was not renamed back into place:\n%s", state)
	t.Expect(datasets).NotTo(ContainElement(vaultStagingDataset),
		"the abandoned copy outlived the recovery that rejected it:\n%s", state)
	t.Expect(readSwapMarker(t, device)).To(Equal("NONE"),
		"the swap record outlived the swap it describes:\n%s", state)
	evetest.Checkpoint("contents-restored-on-kvm")

	// Phase 5. The copy was discarded, so the migration has to be redone from the
	// restored vault. Disarming first is what lets it finish: the fault marker is
	// on /persist and would park this boot in the same window.
	log.Infof("disarming the fault and booting the installed EVE-K partition")
	disarmVaultMigrationFault(t, device)
	bootOtherPartition(t, device)
	waitForVaultMigrated(t, device, powerCutMarkerPath, powerCutMarkerText, 45*time.Minute)

	afterState := describeVaultState(device, powerCutMarkerPath)
	log.Infof("state after the redone migration:\n%s", afterState)
	afterDatasets := listPersistDatasets(t, device)
	t.Expect(afterDatasets).NotTo(ContainElement(vaultBackupDataset),
		"the redone migration left its pre-migration vault behind:\n%s", afterState)
	t.Expect(afterDatasets).NotTo(ContainElement(vaultStagingDataset),
		"the redone migration left its staging zvol behind:\n%s", afterState)
	t.Expect(readSwapMarker(t, device)).To(Equal("NONE"),
		"a swap record outlived the swap it describes:\n%s", afterState)
	evetest.Checkpoint("migration-redone-on-evek")

	// Phase 6. A committed partition is what lets recovery reclaim pool space
	// rather than hold it for a revert, so it is also where a healthy migrated
	// vault could be taken for debris.
	log.Infof("committing the running partition; the migrated vault must survive it")
	commitCurrentPartition(t, device)
	waitForVaultMigrated(t, device, powerCutMarkerPath, powerCutMarkerText, 30*time.Minute)

	finalState := describeVaultState(device, powerCutMarkerPath)
	log.Infof("state after committing the partition:\n%s", finalState)
	finalDatasets := listPersistDatasets(t, device)
	t.Expect(finalDatasets).NotTo(ContainElement(vaultBackupDataset),
		"the commit left a pre-migration vault behind:\n%s", finalState)
	t.Expect(finalDatasets).NotTo(ContainElement(vaultStagingDataset),
		"the commit left a staging zvol behind:\n%s", finalState)
	evetest.Checkpoint("migrated-vault-survives-commit")
}
