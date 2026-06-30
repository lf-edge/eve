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

	// Write 256 MiB of incompressible data then delete it to create ghost
	// blocks. /dev/zero compresses to near-zero under zstd and produces no
	// ghost blocks; /dev/urandom forces real ZFS block allocation.
	_, _, err := device.RunShellScript(
		"dd if=/dev/urandom of=/persist/vault/trim_test bs=1M count=256 conv=fsync"+
			" && rm /persist/vault/trim_test",
		120*time.Second, 0)
	t.Expect(err).To(BeNil(), "failed to create and delete trim_test file")

	before, err := vaultLogicalUsed(device)
	t.Expect(err).To(BeNil(), "failed to read logicalused before fstrim")

	_, _, err = device.RunShellScript("fstrim /persist/vault", 120*time.Second, 0)
	t.Expect(err).To(BeNil(), "fstrim /persist/vault failed")

	after, err := vaultLogicalUsed(device)
	t.Expect(err).To(BeNil(), "failed to read logicalused after fstrim")

	t.Expect(after).To(BeNumerically("<", before),
		"fstrim must reduce persist/vault logicalused (before=%d after=%d)",
		before, after)
}

// vaultLogicalUsed returns the current logicalused value for persist/vault in
// bytes, as reported by `zfs get -Hp logicalused`.
func vaultLogicalUsed(device *evetest.EdgeDevice) (int64, error) {
	stdout, _, err := device.RunShellScript(
		"zfs get -Hp logicalused persist/vault",
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
