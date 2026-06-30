// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// TestVaultZvolTrimReclaimsBlocks verifies that fstrim on /persist/vault
// returns ghost blocks to ZFS, reducing logicalused on the persist/vault
// dataset on an EVE-k ZFS node.
//
// Ghost blocks accumulate when ext4 frees blocks (e.g. from Longhorn replica
// churn) that the underlying ZFS zvol never receives DISCARD for. Without
// periodic fstrim these blocks inflate logicalused, which inflates usedByDom0,
// which shrinks allowedDeviceDiskSize and can trigger false maintenance mode.
//
// The test writes 256 MiB of incompressible data (/dev/urandom bypasses ZFS
// zstd compression), deletes it to create ghost blocks, then verifies that
// fstrim causes logicalused to drop. Skipped on non-kubevirt or non-ZFS nodes.
func TestVaultZvolTrimReclaimsBlocks(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	devName := "edge-dev"
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    evetest.HypervisorKubevirt,
			WithFilesystem:    evetest.FilesystemZFS,
			DeviceReusePolicy: evetest.UseAsIs,
		},
	)
	device := evetest.GetEdgeDevice(devName)

	// evetest.Setup returns once the device is onboarded and has fetched its
	// config; it does NOT wait for the vault to be unlocked/mounted. Gate the
	// test on vault readiness before touching /persist/vault, otherwise the
	// write lands on the parent persist dataset's mountpoint directory (the
	// ext4-on-zvol is not mounted yet) and logicalused on the zvol never moves.

	// Wait for vaultmgr to report the default vault ConversionComplete. Read
	// the VaultStatus pubsub JSON on-device via a shell (not ReadPublication):
	// ReadPublication/ReadFile Fatalf on a not-yet-published file, and the
	// pubsub key "Application Data Store" contains spaces that break scp's
	// remote path. A failed cat just fails the poll and we retry.
	vaultStatusPath := `/run/vaultmgr/VaultStatus/` + pillartypes.DefaultVaultName + `.json`
	t.Eventually(func() bool {
		out, _, err := device.RunShellScript(
			`eve exec pillar cat "`+vaultStatusPath+`"`, 15*time.Second, 0)
		if err != nil {
			return false // status not published yet
		}
		return strings.Contains(strings.ReplaceAll(out, " ", ""),
			`"ConversionComplete":true`)
	}, 5*time.Minute, 5*time.Second).Should(BeTrue(),
		"vaultmgr must report the default vault ConversionComplete before writing")

	// The ext4-on-zvol must actually be mounted at /persist/vault; this is the
	// decisive guard for where the write lands.
	t.Eventually(func() error {
		_, _, err := device.RunShellScript(
			"eve exec pillar mountpoint -q /persist/vault", 15*time.Second, 0)
		return err
	}, 2*time.Minute, 5*time.Second).Should(Succeed(),
		"/persist/vault ext4-on-zvol must be mounted before writing test data")

	const mib = 1024 * 1024

	// Reclaim any pre-existing ghost blocks first so the baseline is
	// deterministic and the write below inflates logicalused by the full
	// amount — a write that merely reuses untrimmed ext4 free space would not.
	// zfs/fstrim and the /persist/vault mount live in the pillar container,
	// not the host SSH shell, so run everything via "eve exec pillar".
	_, _, err := device.RunShellScript(
		"eve exec pillar fstrim /persist/vault", 120*time.Second, 0)
	t.Expect(err).To(BeNil(), "baseline cleanup fstrim failed")
	_, _, err = device.RunShellScript("eve exec pillar sync", 30*time.Second, 0)
	t.Expect(err).To(BeNil(), "sync after cleanup fstrim failed")

	baseline, err := vaultLogicalUsed(device)
	t.Expect(err).To(BeNil(), "failed to read baseline logicalused")

	// Write 256 MiB of incompressible data. /dev/zero compresses to near-zero
	// under zstd; /dev/urandom forces real ZFS block allocation.
	_, _, err = device.RunShellScript(
		`eve exec pillar dd if=/dev/urandom of=/persist/vault/trim_test `+
			`bs=1M count=256 conv=fsync`,
		120*time.Second, 0)
	t.Expect(err).To(BeNil(), "failed to write trim_test file")
	_, _, err = device.RunShellScript("eve exec pillar sync", 30*time.Second, 0)
	t.Expect(err).To(BeNil(), "sync after write failed")

	// ZFS accounts zvol space per transaction group, so logicalused lags the
	// write by a few seconds — poll until it reflects the 256 MiB.
	t.Eventually(func() (int64, error) {
		return vaultLogicalUsed(device)
	}, 60*time.Second, 3*time.Second).Should(BeNumerically(">", baseline+200*mib),
		"logicalused should rise ~256 MiB after the write (baseline=%d)", baseline)

	// Delete the file. ext4 frees the blocks but the underlying zvol never
	// receives DISCARD, so they linger as ghost blocks (logicalused stays high).
	_, _, err = device.RunShellScript(
		"eve exec pillar rm /persist/vault/trim_test", 30*time.Second, 0)
	t.Expect(err).To(BeNil(), "failed to remove trim_test file")
	_, _, err = device.RunShellScript("eve exec pillar sync", 30*time.Second, 0)
	t.Expect(err).To(BeNil(), "sync after rm failed")

	// fstrim issues DISCARD for the freed blocks; the zvol reclaims them.
	// -v logs the trimmed byte count to aid diagnosis on failure.
	trimOut, _, err := device.RunShellScript(
		"eve exec pillar fstrim -v /persist/vault", 120*time.Second, 0)
	t.Expect(err).To(BeNil(), "fstrim /persist/vault failed")
	test.Logf("fstrim: %s", strings.TrimSpace(trimOut))
	_, _, err = device.RunShellScript("eve exec pillar sync", 30*time.Second, 0)
	t.Expect(err).To(BeNil(), "sync after fstrim failed")

	// Poll until the reclaim is reflected: logicalused must fall back near
	// baseline, proving fstrim returned the ghost blocks to ZFS.
	t.Eventually(func() (int64, error) {
		return vaultLogicalUsed(device)
	}, 60*time.Second, 3*time.Second).Should(BeNumerically("<", baseline+64*mib),
		"fstrim must reclaim ghost blocks; logicalused should return near baseline=%d",
		baseline)
}

// vaultLogicalUsed returns the current logicalused value for persist/vault in
// bytes, as reported by `zfs get -Hp logicalused`. zfs lives in the pillar
// container, so the command is run via "eve exec pillar".
func vaultLogicalUsed(device *evetest.EdgeDevice) (int64, error) {
	stdout, _, err := device.RunShellScript(
		"eve exec pillar zfs get -Hp logicalused persist/vault",
		30*time.Second, 0)
	if err != nil {
		return 0, err
	}
	// Output: "persist/vault\tlogicalused\t<bytes>\t-\n"
	fields := strings.Fields(strings.TrimSpace(stdout))
	if len(fields) < 3 {
		return 0, fmt.Errorf("unexpected zfs get output: %q", stdout)
	}
	return strconv.ParseInt(fields[2], 10, 64)
}
