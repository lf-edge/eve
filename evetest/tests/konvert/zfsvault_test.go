// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"strings"
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

const (
	// The vault content that must survive an abandoned migration untouched.
	zfsVaultMarkerPath = "/persist/vault/evetest-vault-marker"
	zfsVaultMarkerText = "KONVERT-ZFS-VAULT-MARKER-7b1e4c02-survives-a-declined-migration"

	// availRecoveryMarginBytes is how far below its pre-fill value the pool's
	// available space may sit once the filler is gone. It absorbs ordinary churn
	// (logs, newlog, a baseos image in flight) while staying far below the tens
	// of GiB a leaked staging zvol would hold.
	availRecoveryMarginBytes = int64(3) << 30
)

// TestKvmToKZFSVaultMigration drives a kvm→EVE-K update on a device whose
// /persist is ZFS, with the pool deliberately too tight for the vault
// migration, and asserts that the abandoned migration leaves nothing behind.
//
// This is the vault half of the conversion, not the boot-disk half: the device
// starts on the current EVE-kvm build, whose geometry already fits an EVE-K
// rootfs, so no repartition is involved. What the flavor change does trigger is
// the vault migration, which copies the carried-over filesystem vault into a
// staging zvol sized to the pool's free space and swaps it into place.
//
// The interesting case is the one that does not complete. The migration declines
// up front when the free space cannot hold a second copy of the vault, and this
// test creates exactly that condition -- by growing the vault rather than by
// filling the pool, so the pool keeps roughly half its capacity free and the
// device never approaches the low-disk maintenance threshold. It then asserts
// what the device is left with: no staging zvol, no parked backup, no etcd
// volume, no swap record, the vault still a filesystem dataset with its content
// readable, and the pool's free space back where it started. A leaked staging
// zvol is what makes this matter -- it holds whatever was copied into it, up to
// all the space the pool had free, and the EVE-kvm the device falls back to has
// no migration code that would ever reclaim it.
//
// Negative control: against a build without lf-edge/eve#6530 the etcd-volume
// assertion fails, because the etcd zvol was created before the free-space check
// rather than after it.
//
// Phases:
//  1. Baseline: /persist is moved onto the extra disk and must come up ZFS, the
//     vault settled on a local TPM unlock, and a marker written into it.
//  2. Grow the vault until the pool cannot hold a second copy of it.
//  3. Push the kvm→k update, which must revert.
//  4. Assert on the device log that the migration is what declined.
//  5. Assert nothing the migration would have created is on the device.
//  6. Remove the filler; the pool's free space must come back.
//
// The device is fixed rather than parameterized: a TPM (the migration stages the
// unlock key for the encrypted zvol), ZFS /persist, and a second disk that
// /persist is moved onto, which needs the broker's disk-edit capability. The
// pool on a disk of its own is the topology the eden leg this is ported from
// uses, and it decides what the migration can attempt.
//
// Not covered: retrying the update after freeing the space. baseosmgr only
// reconsiders a FAILED baseos once its retry counter is bumped or the image is
// removed and re-added, and the framework exposes neither, so the successful
// migration stays with the conversion's happy path.
func TestKvmToKZFSVaultMigration(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	defineSharedParameters()
	p := resolveDeviceParams(t)
	p = raiseFloorsForCarriedVolume(t, p)
	// The build under test, not a release: this needs a device whose geometry
	// already fits an EVE-K rootfs, so that the flavor change reaches the vault
	// migration without a repartition in the way.
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
	// migration sizes its staging zvol from the pool's free space, so where the
	// pool lives and how big it is are what this test varies.
	movePersistToExtraDisk(t, device, devConfig)

	// Phase 1. The whole test is about ZFS-specific dataset layout, so prove the
	// substrate first: on ext4 every assertion below would pass for the wrong
	// reason.
	log.Infof("baseline: /persist must be ZFS")
	assertPersistType(t, device, "zfs")

	// A new rootfs moves the PCRs, so the first boot unlocks via the controller
	// key; the migration path under test is the one a locally sealed vault
	// takes, so settle there first.
	log.Infof("settling the vault on a local TPM unlock")
	settleVaultLocal(t, device)

	log.Infof("writing a marker into the vault at %s", zfsVaultMarkerPath)
	writeMarkerFile(t, device, zfsVaultMarkerPath, zfsVaultMarkerText)
	availBefore := zfsNumber(t, device, "available", "persist")
	log.Infof("baseline: persist available=%d vault used=%d", availBefore,
		zfsNumber(t, device, vaultUsedProperty, vaultDataset))
	evetest.Checkpoint("vault-settled")

	// Phase 2.
	log.Infof("filling the vault until the pool cannot hold a second copy of it")
	fillVaultUntilNoSpace(t, device)
	availFilled := zfsNumber(t, device, "available", "persist")
	usedFilled := zfsNumber(t, device, vaultUsedProperty, vaultDataset)
	log.Infof("after fill: persist available=%d vault used=%d", availFilled, usedFilled)
	t.Expect(availFilled).To(BeNumerically("<=", usedFilled),
		"the fill did not reach the decline condition (available %d must be <= vault "+
			"used %d); the migration would have proceeded and this run would prove nothing",
		availFilled, usedFilled)
	evetest.Checkpoint("vault-too-big-to-migrate")

	// Phase 3. The flavor change triggers the migration, which declines; EVE
	// marks the EVE-K baseos FAILED and the device returns on the kvm partition.
	declineOK := false
	defer func() {
		if !declineOK {
			dumpVaultState(device)
		}
	}()
	log.Infof("kvm→k update: the vault migration must decline and the update revert")
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKubevirt,
		evetest.BaseOSDatastoreHTTP, true, true, conversionUpgradeTimeout)
	evetest.Checkpoint("update-reverted")

	// Phase 4. Without this the run could revert for an unrelated reason and
	// every assertion below would still hold.
	log.Infof("the device log must show the migration declining for space")
	assertVaultMigrationDeclined(t, device)

	// Phase 5.
	log.Infof("the abandoned migration must have left no datasets behind")
	datasets := listPersistDatasets(t, device)
	t.Expect(datasets).NotTo(ContainElement(vaultStagingDataset),
		"the staging zvol survived an abandoned migration:\n%s", strings.Join(datasets, "\n"))
	t.Expect(datasets).NotTo(ContainElement(vaultBackupDataset),
		"the parked pre-migration vault survived an abandoned migration:\n%s",
		strings.Join(datasets, "\n"))
	t.Expect(datasets).NotTo(ContainElement(etcdZvolDataset),
		"a declined migration created the etcd volume:\n%s", strings.Join(datasets, "\n"))
	t.Expect(datasets).To(ContainElement(vaultDataset), "the vault itself is gone")

	log.Infof("the vault must still be an unmigrated filesystem dataset, with its content")
	t.Expect(zfsProperty(t, device, "type", vaultDataset)).To(Equal("filesystem"),
		"the vault is no longer a filesystem dataset after a declined migration")
	waitVaultUnlocked(t, device)
	assertMarkerFile(t, device, zfsVaultMarkerPath, zfsVaultMarkerText)
	t.Expect(readSwapMarker(t, device)).To(Equal("NONE"),
		"a swap record survived an abandoned migration")
	declineOK = true
	evetest.Checkpoint("no-leftovers-after-decline")

	// Phase 6. This is the operator-visible form of the same property: a leaked
	// staging zvol would still be holding the space the fallback boot needs.
	log.Infof("removing the filler; the pool's free space must come back")
	removeVaultFill(t, device)
	availAfter := zfsNumber(t, device, "available", "persist")
	log.Infof("after cleanup: persist available=%d (baseline %d)", availAfter, availBefore)
	t.Expect(availAfter).To(BeNumerically(">", availBefore-availRecoveryMarginBytes),
		"the pool did not get its free space back (available %d vs baseline %d); "+
			"something the migration created is still holding it", availAfter, availBefore)
	evetest.Checkpoint("free-space-recovered")
}
