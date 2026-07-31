// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestStorageSuite drives storage-layer regression tests.
//
// Subtests
// --------
//   - TestZVolProvisionedSizeReported -- regression test for a volumemgr bug
//     where a ZFS zvol-backed volume always reported a provisioned size of 0.
//   - TestVaultZvolTrimReclaimsBlocks -- verifies fstrim on /persist/vault
//     reclaims ghost blocks on a ZFS node.
func TestStorageSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestZVolProvisionedSizeReported,
		},
		evetest.TestCase{
			Test: TestVaultZvolTrimReclaimsBlocks,
		},
	)
}
