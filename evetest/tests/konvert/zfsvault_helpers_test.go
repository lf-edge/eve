// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"fmt"
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

// The fault point compiled into a FAULT_INJECTION=y image: writing the step name
// arms it, and the device records reaching that step in the second file before
// parking there. Both live on /persist because the migration runs on the first
// EVE-K boot, which /tmp does not survive.
const (
	vaultFaultFile        = "/persist/status/vault-migration-fault"
	vaultFaultReachedFile = "/persist/status/vault-migration-fault-reached"

	// faultStepBeforePromote parks the migration after the pre-migration vault
	// has been renamed aside and before the staging zvol takes its place -- the
	// window in which the vault path does not exist.
	faultStepBeforePromote = "before-promote"
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

// armVaultMigrationFault arms the fault point and fails the run if the image
// does not carry it, rather than letting a test pass having cut power at an
// arbitrary moment.
func armVaultMigrationFault(t Gomega, device *evetest.EdgeDevice) {
	out, err := runEVE(device,
		`eve exec pillar sh -c 'rm -f `+vaultFaultReachedFile+
			`; printf %s `+faultStepBeforePromote+` > `+vaultFaultFile+`; sync'`)
	t.Expect(err).NotTo(HaveOccurred(), "arming the migration fault failed:\n%s", out)
	assertMarkerFile(t, device, vaultFaultFile, faultStepBeforePromote)
}

// waitForFaultWindow polls for the device recording that the migration reached
// the swap window, and returns what it recorded.
func waitForFaultWindow(t Gomega, device *evetest.EdgeDevice, timeout time.Duration) string {
	var reached string
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device,
			`eve exec pillar sh -c 'cat `+vaultFaultReachedFile+` 2>/dev/null || echo PENDING'`)
		// SSH comes and goes across the update's reboots; only the content matters.
		if err != nil {
			g.Expect(err).NotTo(HaveOccurred())
			return
		}
		reached = strings.TrimSpace(out)
		g.Expect(reached).NotTo(Equal("PENDING"),
			"the migration has not reached the swap window yet")
		g.Expect(reached).NotTo(BeEmpty())
	}, timeout, 15*time.Second).Should(Succeed(),
		"the device never reached the swap window -- is this a FAULT_INJECTION=y image?")
	return reached
}

// waitForVaultRecovered waits for the rebooted device to be reachable again with
// its vault dataset back in place, which is what recovery produces.
func waitForVaultRecovered(t Gomega, device *evetest.EdgeDevice, timeout time.Duration) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, "eve exec pillar zfs list -H -o name -r persist")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring(vaultDataset),
			"the vault dataset has not come back")
	}, timeout, 20*time.Second).Should(Succeed())
}

// disarmVaultMigrationFault removes the fault point, so that a later EVE-K boot
// runs the migration through instead of parking in the same window. The marker
// lives on /persist and outlives every boot until it is taken away.
func disarmVaultMigrationFault(t Gomega, device *evetest.EdgeDevice) {
	out, err := runEVE(device,
		`eve exec pillar sh -c 'rm -f `+vaultFaultFile+` `+vaultFaultReachedFile+`; sync'`)
	t.Expect(err).NotTo(HaveOccurred(), "disarming the migration fault failed:\n%s", out)
	t.Expect(readOptionalFile(t, device, vaultFaultFile)).To(Equal("NONE"),
		"the migration fault is still armed")
}

// waitForVaultMigrated waits for the vault to be the EVE-K zvol with markerText
// readable out of it, which together are what a completed migration produces.
//
// Both halves are needed: the dataset becomes a zvol at the swap's second
// rename, a moment before the migration mounts it, so a type check alone can
// return while the contents are still unreachable. The wait spans a whole boot,
// because the flavor change moves the measurements the seal is bound to -- the
// local unseal fails, the vault opens on a key from the controller, and only
// then does the migration run. Every read is allowed to fail: ssh comes and goes
// across the boot, and the vault path is absent between the two renames.
func waitForVaultMigrated(t Gomega, device *evetest.EdgeDevice,
	markerPath, markerText string, timeout time.Duration) {
	t.Eventually(func(g Gomega) {
		datasetType, err := runEVE(device,
			"eve exec pillar zfs get -Hp -o value type "+vaultDataset)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(datasetType)).To(Equal("volume"),
			"the vault is not the migrated zvol")
		marker, err := runEVE(device, "eve exec pillar cat "+markerPath)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(marker)).To(Equal(markerText),
			"the migrated vault is not mounted with its contents")
	}, timeout, 30*time.Second).Should(Succeed())
}

// describeVaultState collects everything needed to tell the outcomes of an
// interrupted migration apart: which flavor booted (EVE-kvm has no migration
// code and would create a fresh vault), the datasets, the vault's type, whether
// the content survived, and whether a swap record is still on disk.
//
// Returned rather than logged, because it goes into the failure message of the
// assertions that follow it: which of those outcomes a run landed in is the
// first thing to know and the state is gone by the time the log is read.
// Best-effort -- a probe that cannot run reports why instead of failing, since
// this is called precisely when the device may be in a bad way.
func describeVaultState(device *evetest.EdgeDevice, markerPath string) string {
	probes := []probe{
		{"eve version", "eve exec pillar /bin/eve version 2>/dev/null || eve version"},
		{"persist type", "eve exec pillar cat " + persistTypeFile},
		{"partitions", "eve exec pillar sh -c 'echo cur=$(zboot curpart) IMGA=$(zboot partstate IMGA) IMGB=$(zboot partstate IMGB)'"},
		{"datasets", "eve exec pillar zfs list -H -o name,type,used -r persist"},
		{"vault type", "eve exec pillar zfs get -Hp -o value type " + vaultDataset},
		{"vault marker", "eve exec pillar sh -c 'cat " + markerPath + " 2>/dev/null || echo ABSENT'"},
		{"vault contents", "eve exec pillar sh -c 'ls -A /persist/vault 2>/dev/null | head -20 || echo UNREADABLE'"},
		{"swap record", "eve exec pillar sh -c 'cat " + vaultSwapMarkerPath + " 2>/dev/null || echo NONE'"},
		{"fault reached", "eve exec pillar sh -c 'cat " + vaultFaultReachedFile + " 2>/dev/null || echo NONE'"},
	}
	var b strings.Builder
	for _, p := range probes {
		out, err := runEVE(device, p.script)
		if err != nil {
			fmt.Fprintf(&b, "  %-14s <unreadable: %v>\n", p.what+":", err)
			continue
		}
		fmt.Fprintf(&b, "  %-14s %s\n", p.what+":",
			strings.ReplaceAll(strings.TrimSpace(out), "\n", "\n                 "))
	}
	return b.String()
}
