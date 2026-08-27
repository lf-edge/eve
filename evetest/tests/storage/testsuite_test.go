// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestStorageSuite drives storage-layer regression tests.
func TestStorageSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		// Non-ZFS tests first, grouped together so the device can be reused
		// across all of them.
		evetest.TestCase{
			Test: TestVolumes,
		},
		evetest.TestCase{
			Test: TestMountedVolumes,
		},
		evetest.TestCase{
			Test: TestExtraDiskAttach,
		},
		// TestVolumeSizeAlignment cannot share the default-size device the other
		// non-ZFS tests above reuse: it needs 16 GiB / 8 CPUs for the EVE-k
		// k3s/KubeVirt/Longhorn/CDI cluster, so it gets its own larger device.
		evetest.TestCase{
			Test: TestVolumeSizeAlignment,
		},
		// ZFS tests next, grouped together for the same reason.
		evetest.TestCase{
			Test: TestZVolProvisionedSizeReported,
		},
		evetest.TestCase{
			Test: TestVaultZvolTrimReclaimsBlocks,
		},
		// Last: needs its own freshly created device with extra disks, so
		// placement relative to the other tests does not matter for reuse.
		evetest.TestCase{
			Test: TestZFSDiskLayout,
		},
	)
}
