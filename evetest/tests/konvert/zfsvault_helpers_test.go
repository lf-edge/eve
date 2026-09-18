// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"strconv"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// The datasets a ZFS vault migration works with. persist/vault is the vault
// itself, persist/vault2 the zvol its contents are copied into, and
// persist/vault.old the pre-migration vault parked while the two are swapped.
// persist/etcd-storage is the EVE-K etcd volume the migration creates alongside
// them.
const (
	vaultDataset        = "persist/vault"
	vaultStagingDataset = "persist/vault2"
	vaultBackupDataset  = "persist/vault.old"
	etcdZvolDataset     = "persist/etcd-storage"

	// vaultSwapMarkerPath is where the migration records that its staging zvol
	// holds a complete copy and may be promoted.
	vaultSwapMarkerPath = "/persist/status/vault-migration-swap"

	// vaultUsedProperty is the ZFS property the migration compares the pool's
	// free space against when deciding whether a second copy fits.
	vaultUsedProperty = "used"

	// vaultFillDir holds the incompressible filler written INTO the vault to
	// drive that comparison past its threshold.
	vaultFillDir = "/persist/vault/evetest-nospace"
)

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
	return readOptionalFile(t, device, vaultSwapMarkerPath)
}

// fillVaultUntilNoSpace writes incompressible files INTO the vault until the
// pool's free space is no longer enough to hold a second copy of it, which is
// the condition the migration declines on.
//
// Growing the vault, rather than filling the pool, is what keeps this safe to
// run: the condition is a comparison between the two, so it is met with the pool
// still roughly half free, well clear of the threshold at which EVE puts the
// device into low-disk maintenance mode. The bytes must be incompressible or ZFS
// stores them in nearly nothing and the loop never converges.
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
	out, err := runEVEScript(device, script, 40*time.Minute)
	t.Expect(err).NotTo(HaveOccurred(), "filling the vault failed:\n%s", out)
	t.Expect(out).To(ContainSubstring("VAULTFILLED"),
		"the fill did not report completion:\n%s", out)
	evetest.Logger().Infof("vault fill: %s", strings.TrimSpace(out))
}

// removeVaultFill deletes the filler and waits for ZFS to account for it, so the
// pool's free space can be compared against its pre-fill value.
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
// reason would satisfy every other assertion the caller makes.
func assertVaultMigrationDeclined(t Gomega, device *evetest.EdgeDevice) {
	const declined = "insufficient free space to migrate vault"
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, newlogProbe(`grep -a "`+declined+`" | tail -5`))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring(declined),
			"the vault migration never declined for space; the update reverted for another reason")
	}, 5*time.Minute, 15*time.Second).Should(Succeed())
}
