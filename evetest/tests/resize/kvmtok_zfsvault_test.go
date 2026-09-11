// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package resize_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const (
	// The datasets a ZFS vault migration works with. persist/vault is the vault
	// itself, persist/vault2 the zvol the contents are copied into, and
	// persist/vault.old the pre-migration vault parked while the two are
	// swapped. persist/etcd-storage is the EVE-k etcd volume the migration
	// creates alongside them.
	vaultDataset        = "persist/vault"
	vaultStagingDataset = "persist/vault2"
	vaultBackupDataset  = "persist/vault.old"
	etcdZvolDataset     = "persist/etcd-storage"

	// vaultSwapMarkerPath is where the migration records that its staging zvol
	// holds a complete copy and may be promoted.
	vaultSwapMarkerPath = "/persist/status/vault-migration-swap"

	// The vault content that must survive an abandoned migration untouched.
	vaultMarkerPath = "/persist/vault/evetest-vault-marker"
	vaultMarkerText = "KVMTOK-ZFS-VAULT-MARKER-7b1e4c02-survives-a-declined-migration"

	// vaultFillDir holds the incompressible filler this test writes INTO the
	// vault to drive the migration's free-space check below its threshold.
	vaultFillDir = "/persist/vault/evetest-nospace"

	// availRecoveryMarginBytes is how far below its pre-fill value the pool's
	// available space may sit once the filler is gone. It absorbs ordinary
	// churn (logs, newlog, a baseos image in flight) while staying far below
	// the tens of GiB a leaked staging zvol would hold.
	availRecoveryMarginBytes = int64(3) << 30
)

// TestKvmToKZFSVaultMigration drives a kvm→EVE-k update on a device whose
// /persist is ZFS, with the pool deliberately too tight for the vault
// migration, and asserts that the abandoned migration leaves nothing behind.
//
// This is the vault half of the conversion, not the boot-disk half: the device
// starts on the current EVE-kvm build, whose geometry already fits an EVE-k
// rootfs, so no repartition is involved. What the flavor change does trigger is
// migrateVaultFsToZvol, which copies the carried-over filesystem vault into a
// staging zvol sized to the pool's free space and swaps it into place.
//
// The interesting case is the one that does not complete. The migration
// declines up front when the free space cannot hold a second copy of the
// vault, and this test creates exactly that condition — by growing the vault
// rather than by filling the pool, so the pool keeps roughly half its capacity
// free and the device never approaches the low-disk maintenance threshold. It
// then asserts what the device is left with: no staging zvol, no parked backup,
// no etcd volume, no swap record, the vault still a filesystem dataset with its
// content readable, and the pool's free space back where it started. A leaked
// staging zvol is what makes this matter — it holds whatever was copied into
// it, up to all the space the pool had free, and the EVE-kvm the device falls
// back to has no migration code that would ever reclaim it.
//
// Negative control: run this against a build without lf-edge/eve#6530 and the
// etcd-volume assertion fails, because the etcd zvol was created before the
// free-space check rather than after it.
//
// Parameters: EVE_VERSION / DISK_SIZE_MB / RAM_SIZE_MB / CPUS. The device needs
// a TPM (the migration stages the unlock key for the encrypted zvol) and is set
// up with ZFS /persist, neither of which is a parameter here.
//
// Not covered: retrying the update after freeing the space. baseosmgr only
// reconsiders a FAILED baseos once its retry counter is bumped or the image is
// removed and re-added, and the framework exposes neither, so the successful
// migration stays with the conversion's happy path.
func TestKvmToKZFSVaultMigration(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.EVEVersionParameter(),
		evetest.DiskSizeMiBParameter(),
		evetest.RAMSizeMiBParameter(),
		evetest.CPUsParameter(),
	)

	eveVersion := evetest.GetEVEVersionParameterValue()
	diskSizeMiB := evetest.GetDiskSizeMiBParameterValue()
	effectiveRAMMiB := evetest.GetRAMSizeMiBParameterValue()
	if effectiveRAMMiB == 0 {
		effectiveRAMMiB = minDeviceRAMInMiB
	}
	effectiveCPUs := evetest.GetCPUsParameterValue()
	if effectiveCPUs == 0 {
		effectiveCPUs = minDeviceCPUs
	}

	const devName = "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:             devName,
			WithEVEVersion:   eveVersion,
			WithHypervisor:   evetest.HypervisorKVM,
			WithTPM:          true,
			WithFilesystem:   evetest.FilesystemZFS,
			MinDiskSizeInMiB: diskSizeMiB,
			MinRAMInMiB:      effectiveRAMMiB,
			MinCPUs:          effectiveCPUs,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	log := evetest.Logger()

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	networkUUID := devConfig.AddNetwork(evetest.DHCPNetworkConfig{NetworkType: evecommon.NetworkType_V4})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "eth0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   networkUUID,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, false, false)

	// The EVE-k attempt boots, fails to bring the vault up and is reverted;
	// that is several reboots and runs close to the default upgrade budget.
	device.SetUpgradeTimeout(45 * time.Minute)

	// The whole test is about ZFS-specific dataset layout, so prove the
	// substrate before anything else: on ext4 every assertion below would pass
	// for the wrong reason.
	log.Infof("baseline: /persist must be ZFS")
	assertPersistIsZFS(t, device)

	// A new rootfs moves the PCRs, so the first boot unlocks via the controller
	// key; the migration path under test is the one a locally sealed vault
	// takes, so settle there first.
	log.Infof("settling vault to a local TPM unlock")
	settleVaultLocal(t, device)
	evetest.Checkpoint("vault-settled")

	log.Infof("writing a marker into the vault at %s", vaultMarkerPath)
	writeVaultMarker(t, device)
	availBefore := zfsNumber(t, device, "available", "persist")
	usedBefore := zfsNumber(t, device, "used", vaultDataset)
	log.Infof("baseline: persist available=%d vault used=%d", availBefore, usedBefore)

	// Grow the vault until it no longer fits twice in the pool, which is the
	// condition migrateVaultFsToZvol declines on.
	log.Infof("filling the vault until the pool cannot hold a second copy of it")
	fillVaultUntilNoSpace(t, device)
	availFilled := zfsNumber(t, device, "available", "persist")
	usedFilled := zfsNumber(t, device, vaultUsedProperty, vaultDataset)
	log.Infof("after fill: persist available=%d vault used=%d", availFilled, usedFilled)
	t.Expect(availFilled).To(BeNumerically("<=", usedFilled),
		"the fill did not reach the decline condition (available %d must be <= vault used %d); "+
			"the migration would have proceeded and this run would prove nothing",
		availFilled, usedFilled)
	evetest.Checkpoint("vault-too-big-to-migrate")

	// The flavor change triggers the migration, which declines; EVE marks the
	// EVE-k baseos FAILED and the device returns on the kvm partition.
	log.Infof("kvm→k update: the vault migration must decline and the update revert")
	device.UpgradeEVE(eveVersion, evetest.HypervisorKubevirt, evetest.BaseOSDatastoreHTTP, true, true)
	evetest.Checkpoint("update-reverted")

	// Positive control on the mechanism: without this line the run could revert
	// for an unrelated reason and every assertion below would still hold.
	log.Infof("the device log must show the migration declining for space")
	assertVaultMigrationDeclined(t, device)

	log.Infof("the abandoned migration must have left no datasets behind")
	datasets := listPersistDatasets(t, device)
	t.Expect(datasets).NotTo(ContainElement(vaultStagingDataset),
		"the staging zvol survived an abandoned migration:\n%s", strings.Join(datasets, "\n"))
	t.Expect(datasets).NotTo(ContainElement(vaultBackupDataset),
		"the parked pre-migration vault survived an abandoned migration:\n%s", strings.Join(datasets, "\n"))
	t.Expect(datasets).NotTo(ContainElement(etcdZvolDataset),
		"a declined migration created the etcd volume:\n%s", strings.Join(datasets, "\n"))
	t.Expect(datasets).To(ContainElement(vaultDataset), "the vault itself is gone")

	log.Infof("the vault must still be an unmigrated filesystem dataset, with its content")
	t.Expect(zfsProperty(t, device, "type", vaultDataset)).To(Equal("filesystem"),
		"the vault is no longer a filesystem dataset after a declined migration")
	assertVaultMarker(t, device)
	t.Expect(readSwapMarker(t, device)).To(Equal("NONE"),
		"a swap record survived an abandoned migration")
	evetest.Checkpoint("no-leftovers-after-decline")

	// With the filler gone the pool must be as free as it was. This is the
	// operator-visible form of the same property: a leaked staging zvol would
	// still be holding the space the fallback boot needs.
	log.Infof("removing the filler; the pool's free space must come back")
	removeVaultFill(t, device)
	availAfter := zfsNumber(t, device, "available", "persist")
	log.Infof("after cleanup: persist available=%d (baseline %d)", availAfter, availBefore)
	t.Expect(availAfter).To(BeNumerically(">", availBefore-availRecoveryMarginBytes),
		"the pool did not get its free space back (available %d vs baseline %d); "+
			"something the migration created is still holding it", availAfter, availBefore)
	evetest.Checkpoint("free-space-recovered")
}

// vaultUsedProperty is the ZFS property migrateVaultFsToZvol compares the
// pool's free space against.
const vaultUsedProperty = "used"

// assertPersistIsZFS fails the run unless /persist is ZFS, reading the type
// storage-init recorded at boot.
func assertPersistIsZFS(t Gomega, device *evetest.EdgeDevice) {
	out, err := runEVE(device, "eve exec pillar cat /run/eve.persist_type")
	t.Expect(err).NotTo(HaveOccurred())
	t.Expect(strings.TrimSpace(out)).To(Equal("zfs"),
		"this test needs a ZFS /persist; got %q", strings.TrimSpace(out))
}

// zfsProperty reads one ZFS property of one dataset.
func zfsProperty(t Gomega, device *evetest.EdgeDevice, property, dataset string) string {
	out, err := runEVE(device,
		"eve exec pillar zfs get -Hp -o value "+property+" "+dataset)
	t.Expect(err).NotTo(HaveOccurred(), "reading %s of %s failed", property, dataset)
	return strings.TrimSpace(out)
}

// zfsNumber reads a numeric ZFS property (bytes) of one dataset.
func zfsNumber(t Gomega, device *evetest.EdgeDevice, property, dataset string) int64 {
	value := zfsProperty(t, device, property, dataset)
	n, err := strconv.ParseInt(value, 10, 64)
	t.Expect(err).NotTo(HaveOccurred(), "%s of %s is not a number: %q", property, dataset, value)
	return n
}

// listPersistDatasets returns every dataset under the persist pool, so a test
// can assert both presence and absence from one snapshot.
func listPersistDatasets(t Gomega, device *evetest.EdgeDevice) []string {
	out, err := runEVE(device, "eve exec pillar zfs list -H -o name -r persist")
	t.Expect(err).NotTo(HaveOccurred())
	var datasets []string
	for _, line := range strings.Split(out, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			datasets = append(datasets, name)
		}
	}
	t.Expect(datasets).NotTo(BeEmpty(), "zfs list returned nothing")
	return datasets
}

// readSwapMarker returns the migration's swap record, or "NONE" when there is
// none.
func readSwapMarker(t Gomega, device *evetest.EdgeDevice) string {
	out, err := runEVE(device,
		`eve exec pillar sh -c 'cat `+vaultSwapMarkerPath+` 2>/dev/null || echo NONE'`)
	t.Expect(err).NotTo(HaveOccurred())
	return strings.TrimSpace(out)
}

// writeVaultMarker puts a known string inside the vault, to be read back after
// the migration has been abandoned.
func writeVaultMarker(t Gomega, device *evetest.EdgeDevice) {
	out, err := runEVE(device,
		`eve exec pillar sh -c 'printf %s `+vaultMarkerText+` > `+vaultMarkerPath+`; sync'`)
	t.Expect(err).NotTo(HaveOccurred(), "writing the vault marker failed:\n%s", out)
	assertVaultMarker(t, device)
}

// assertVaultMarker fails the run unless the vault still holds the marker.
func assertVaultMarker(t Gomega, device *evetest.EdgeDevice) {
	out, err := runEVE(device, "eve exec pillar cat "+vaultMarkerPath)
	t.Expect(err).NotTo(HaveOccurred(), "reading the vault marker failed")
	t.Expect(strings.TrimSpace(out)).To(Equal(vaultMarkerText),
		"the vault content did not survive")
}

// fillVaultUntilNoSpace writes incompressible files INTO the vault until the
// pool's free space is no longer enough to hold a second copy of it, which is
// what migrateVaultFsToZvol declines on.
//
// Growing the vault, rather than filling the pool, is what keeps this safe to
// run: the condition is a comparison between the two, so it is met with the
// pool still roughly half free, well clear of the threshold at which EVE puts
// the device into low-disk maintenance mode. The bytes must be incompressible
// or ZFS stores them in nearly nothing and the loop never converges.
func fillVaultUntilNoSpace(t Gomega, device *evetest.EdgeDevice) {
	const script = `set -u
DIR=` + vaultFillDir + `
rm -rf "$DIR"; mkdir -p "$DIR"
n=0
while :; do
  avail=$(zfs get -Hp -o value available persist)
  used=$(zfs get -Hp -o value used ` + vaultDataset + `)
  [ "$avail" -le "$used" ] && break
  f=$(printf "%s/%06d" "$DIR" "$n")
  dd if=/dev/urandom of="$f" bs=1M count=512 2>/dev/null || break
  n=$((n + 1))
  sync
done
sync
echo "VAULTFILLED files=$n avail=$(zfs get -Hp -o value available persist) used=$(zfs get -Hp -o value used ` + vaultDataset + `)"`
	out, err := runOnEVEScript(device, script, 40*time.Minute)
	t.Expect(err).NotTo(HaveOccurred(), "filling the vault failed:\n%s", out)
	t.Expect(out).To(ContainSubstring("VAULTFILLED"), "the fill did not report completion:\n%s", out)
	evetest.Logger().Infof("vault fill: %s", strings.TrimSpace(out))
}

// removeVaultFill deletes the filler and waits for ZFS to account for it, so
// the pool's free space can be compared against its pre-fill value.
func removeVaultFill(t Gomega, device *evetest.EdgeDevice) {
	out, err := runEVE(device,
		`eve exec pillar sh -c 'rm -rf `+vaultFillDir+`; sync'`)
	t.Expect(err).NotTo(HaveOccurred(), "removing the vault filler failed:\n%s", out)
	// ZFS frees the blocks asynchronously, so let the accounting catch up
	// rather than reading it once and calling the space lost.
	t.Eventually(func(g Gomega) {
		used, err := runEVE(device,
			"eve exec pillar zfs get -Hp -o value used "+vaultDataset)
		g.Expect(err).NotTo(HaveOccurred())
		usedBytes, err := strconv.ParseInt(strings.TrimSpace(used), 10, 64)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(usedBytes).To(BeNumerically("<", int64(4)<<30),
			"the vault is still holding the filler (%d bytes used)", usedBytes)
	}, 5*time.Minute, 15*time.Second).Should(Succeed())
}

// assertVaultMigrationDeclined fails the run unless the device log shows the
// migration declining for lack of space. Without it a revert for an unrelated
// reason would satisfy every other assertion in this test.
func assertVaultMigrationDeclined(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device,
			newlogProbe(`grep -a "insufficient free space to migrate vault" | tail -5`))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring("insufficient free space to migrate vault"),
			"the vault migration never declined for space; the update reverted for another reason")
	}, 5*time.Minute, 15*time.Second).Should(Succeed())
}
