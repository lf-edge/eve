// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package konvert_test covers the EVE-kvm ↔ EVE-K conversion: the cross-flavor
// base-OS upgrade, and the in-field boot-disk repartition (small → large GPT
// geometry) that the cross-flavor seam arms.
//
// It is a suite of its own rather than part of TestUpgradeSuite because a
// conversion leg is not a single upgrade. Reaching the repartition takes a
// released small-geometry kvm image, a kvm→kvm hop to land the conversion code
// without moving the geometry, and only then the kvm→k hop -- with an offline
// resize and several reboots in between. Folding that into the upgrade suite
// would make a suite worth gating on as expensive as the scenario it is not
// about.
//
// Test files are named for the stage of the conversion they cover:
//
//   - upgrade_test.go     -- the flavor switch itself
//   - repartition_test.go -- the boot-disk conversion, both routes to the space
//   - repartition_refused_test.go  -- the repartition declined, both reasons
//   - repartition_geometry_test.go -- the resulting partition layout, on its own
//   - volmig_test.go      -- an app volume carried across the conversion
//   - firstboot_test.go   -- a volume asked for before EVE-K storage exists
//   - restore_test.go     -- /persist lost or corrupted, recovered offline
//
// Helper files are named for the state they observe:
//
//   - device_helpers_test.go  -- shared parameters, device setup, disk sizing
//   - shell_helpers_test.go   -- running a command on EVE
//   - geometry_helpers_test.go -- partition table, storage-resizer decisions
//   - vault_helpers_test.go   -- vault unlock method and the TPM seal
//   - restore_helpers_test.go -- identity backup, controller isolation
//   - cluster_helpers_test.go -- EVE-K bring-up: k3s, volumemgr, Longhorn
//   - app_helpers_test.go     -- app deployment, SSH, volume markers, blob reuse
//   - download_helpers_test.go -- what the downloader pulled, for blob reuse
//   - diag_helpers_test.go    -- best-effort captures taken when an assertion
//     is about to fail
//
// Every test here needs an EVE that carries the conversion work (lf-edge/eve#6036
// and #6063). On a stock build baseosmgr refuses a kvm↔k base-OS update outright
// (handlebaseos.go, "Upgrade to EVE-k ... is not supported"), so the cross-flavor
// hop fails before any of this is exercised.
//
// Device sizing matches the eden escripts these are ported from
// (lf-edge/eden#1209): 4 vCPUs and 8 GiB of RAM, eden's own defaults, which
// those escripts never override. Raising it makes EVE-K and Longhorn converge
// more easily and stops the tests covering the envelope the escripts cover, so
// the floors stay where eden put them and move only through RAM_SIZE_MB / CPUS.
package konvert_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// Parameters shared by every test in the package. The conversion has two
// version axes (where the device starts, and the build under test) and two
// hypervisor axes (the flavor it starts on, and the flavor it converts to), and
// each test selects points on them rather than carrying its own copy.
const (
	// initialEVEVersionParamKey names the image the device boots first. For the
	// repartition tests it must be a SMALL-geometry release, or the conversion
	// is a no-op that proves nothing; for the flavor-switch tests it defaults to
	// the build under test.
	initialEVEVersionParamKey = "INITIAL_EVE_VERSION"
	// initialEVERepoParamKey overrides the repo the initial image comes from.
	initialEVERepoParamKey = "INITIAL_EVE_REPO"
	// initialHypervisorParamKey is the flavor the device starts on.
	initialHypervisorParamKey = "INITIAL_HYPERVISOR"
	// altEVEVersionParamKey names the version of the *other* flavor, for the
	// tests that switch flavor without repartitioning.
	altEVEVersionParamKey = "ALT_EVE_VERSION"
	// expectDecisionParamKey selects which way the repartition must free the
	// space the EVE-K layout needs.
	expectDecisionParamKey = "EXPECT_DECISION"
	// fillPersistGiBParamKey sizes the pre-conversion fill that gives a shrink
	// real blocks to relocate.
	fillPersistGiBParamKey = "FILL_PERSIST_GIB"
	// refuseReasonParamKey selects why the conversion must be refused.
	refuseReasonParamKey = "REFUSE_REASON"
)

// Defaults shared across the package, reproducing the eden escripts' own, so
// that a run with nothing set matches what eden runs.
const (
	// defaultInitialEVEVersion is the release the device is brought up on
	// before the conversion. It has to land inside assertSmallGeometry's window
	// -- ESP under 256 MiB, IMGA and IMGB under 1 GiB, no ESP-B -- or a run
	// fails at the baseline assert rather than converting anything.
	//
	// Releases do not all lay the boot disk out the same way. In
	// mkimage-raw-efi's make-raw the rootfs partition is a fixed 300 MiB up to
	// 10.1.0 and a fixed 512 MiB at 10.2.0; 12.1.0 turned it into a floor the
	// actual rootfs may exceed, and 14.5 raises that floor to 1 GiB. 10.1.0 is
	// the smallest layout inside the window, and its size is fixed rather than
	// a floor, so the baseline geometry cannot drift with rootfs content.
	defaultInitialEVEVersion = "10.1.0"

	// bootDiskMiB is the single-boot-disk size the escripts use, and the size
	// EVE-K plus Longhorn needs (prep-kvm-to-k-topology.sh BOOT_DISK_MB).
	bootDiskMiB = 65536
	// splitBootDiskMiB is the boot disk the grow route starts on; the rest of
	// bootDiskMiB is added afterwards as a free tail
	// (prep-kvm-to-k-topology.sh EVE_DISK_MB).
	splitBootDiskMiB = 32768
	// defaultFillPersistGiB matches the escripts' FILL_PERSIST_GIB. It must stay
	// below the post-shrink size of /persist, or the shrink cannot fit what the
	// fill put there.
	defaultFillPersistGiB = 33
	// deviceRAMMiB and deviceCPUs are eden's defaults
	// (pkg/defaults/defaults.go DefaultMemory / DefaultCpus), which the
	// escripts do not override.
	deviceRAMMiB = 8192
	deviceCPUs   = 4
)

// TestKonvertSuite runs the conversion tests in an order that lets the
// framework reuse a device where it can: the flavor-switch tests need no
// repartition, so they share one device.
func TestKonvertSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.RAMSizeMiBParameter(),
		evetest.CPUsParameter(),
	)

	evetest.RunTestSuite(
		// Grouped by what each test needs of its device, so the framework can
		// reuse one where the requirements match: the flavor-switch ext4 tests
		// first, then the ones that need a different disk or filesystem.
		evetest.TestCase{Test: TestKvmToKUpgrade},
		evetest.TestCase{Test: TestKvmToKContentTree},
		evetest.TestCase{Test: TestKvmToKAppRecreate},
	)
}
