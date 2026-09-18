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
	// The vault content whose fate after the cut is what this test reports on.
	powerCutMarkerPath = "/persist/vault/evetest-powercut-marker"
	powerCutMarkerText = "KONVERT-ZFS-VAULT-POWERCUT-4e81b60a-survives-an-interrupted-swap"
)

// TestKvmToKZFSVaultPowerCutMidSwap cuts power to a ZFS device in the middle of
// the kvm→EVE-K vault migration's rename swap, and asserts the contents are
// never destroyed by what happens next.
//
// The swap renames the carried-over filesystem vault aside and then renames the
// staging zvol into its place. Between those two renames the vault path does not
// exist, and only a real interruption says what ZFS's rename and the swap
// record's fsync do when the machine disappears there.
//
// Measured behaviour in that window: the device does not come back on EVE-K. It
// falls back to EVE-kvm, which carries no migration code, finds no vault, and
// creates a fresh empty one -- so the contents survive only in the two datasets
// the swap left, and the running vault is not one of them.
//
// The assertions are therefore the guarantee the code makes rather than the one
// an operator wants: both datasets survive the cut, the swap record survives to
// say the swap never completed, and -- the part that needs a device -- they also
// survive an EVE-K boot passing over them, where recovery and the migration each
// get a chance to mistake them for debris and destroy them. That the running
// vault is empty is logged, not asserted: closing that gap means deferring the
// migration until the EVE-K partition is committed, which is a design decision
// open on lf-edge/eve#6036, and asserting it here would only hold the suite red.
//
// Phases:
//  1. Baseline: /persist moved onto the extra disk and up as ZFS, the vault
//     settled on a local TPM unlock, a marker written into it, and the fault
//     point armed.
//  2. Push the kvm→k update and wait for the device to park inside the swap.
//  3. Cut power there and bring it back.
//  4. Assert both datasets and the swap record survived.
//  5. Boot the installed EVE-K partition so a boot actually passes over them,
//     and assert they survive that too.
//  6. Commit the running partition; the kept datasets must then be dropped.
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

	// Phase 4. What the code guarantees today: the contents are never destroyed.
	// The swap parks the pre-migration vault under one dataset and the completed
	// copy under the other, and both must survive whatever boots next.
	state := describeVaultState(device, powerCutMarkerPath)
	log.Infof("post-cut device state:\n%s", state)
	log.Infof("asserting the vault contents survived the cut somewhere")
	datasets := listPersistDatasets(t, device)
	t.Expect(datasets).To(ContainElement(vaultBackupDataset),
		"the pre-migration vault was destroyed after the cut:\n%s", state)
	t.Expect(datasets).To(ContainElement(vaultStagingDataset),
		"the completed migration copy was destroyed after the cut:\n%s", state)
	t.Expect(readSwapMarker(t, device)).To(Equal(vaultStagingDataset),
		"the swap record was lost, and with it the only statement that the swap "+
			"never completed:\n%s", state)
	evetest.Checkpoint("contents-preserved")

	// The gap, recorded rather than asserted: a device that falls back to EVE-kvm
	// inside the swap window comes up on a vault that is not the migrated one and
	// does not hold the contents. EVE-kvm carries no migration code, so nothing
	// on that boot can put them back.
	vaultType := zfsProperty(t, device, "type", vaultDataset)
	marker, markerErr := runEVE(device, "eve exec pillar cat "+powerCutMarkerPath)
	if vaultType != "volume" || markerErr != nil ||
		strings.TrimSpace(marker) != powerCutMarkerText {
		log.Warnf("KNOWN GAP: the running vault is %s and does not hold the pre-cut "+
			"contents; they are in %s and %s. See lf-edge/eve#6036 on deferring the "+
			"migration until the EVE-K partition is committed.",
			vaultType, vaultBackupDataset, vaultStagingDataset)
	}

	// Phase 5. Make an EVE-K boot actually run over the leftovers. Recovery and
	// the migration both get a look at them on that boot and both must leave them
	// alone; this is the only way to exercise that from outside, since EVE-kvm
	// never runs either path.
	log.Infof("booting the installed EVE-K partition so a boot passes over the leftovers")
	bootOtherPartition(t, device)
	waitForEVEKPassOverLeftovers(t, device, 45*time.Minute)

	afterState := describeVaultState(device, powerCutMarkerPath)
	log.Infof("state after an EVE-K pass over the leftovers:\n%s", afterState)
	afterDatasets := listPersistDatasets(t, device)
	t.Expect(afterDatasets).To(ContainElement(vaultBackupDataset),
		"an EVE-K pass destroyed the pre-migration vault:\n%s", afterState)
	t.Expect(afterDatasets).To(ContainElement(vaultStagingDataset),
		"an EVE-K pass destroyed the completed migration copy:\n%s", afterState)
	evetest.Checkpoint("contents-survive-an-evek-pass")

	// Phase 6. Committing the partition ends the fallback's purpose, because the
	// device is no longer going to revert to the other flavor. Both datasets
	// should then go, rather than holding pool space for the life of the device.
	log.Infof("committing the running partition; the kept datasets should be dropped")
	commitCurrentPartition(t, device)
	waitForLeftoversDropped(t, device, 20*time.Minute)

	finalState := describeVaultState(device, powerCutMarkerPath)
	log.Infof("state after committing the partition:\n%s", finalState)
	finalDatasets := listPersistDatasets(t, device)
	t.Expect(finalDatasets).NotTo(ContainElement(vaultBackupDataset),
		"the pre-migration vault outlived the commit:\n%s", finalState)
	t.Expect(finalDatasets).NotTo(ContainElement(vaultStagingDataset),
		"the migration copy outlived the commit:\n%s", finalState)
	t.Expect(readSwapMarker(t, device)).To(Equal("NONE"),
		"the swap record outlived the datasets it names:\n%s", finalState)
	evetest.Checkpoint("fallback-dropped-after-commit")
}
