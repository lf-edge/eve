// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package upgrade_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// Package layout
// --------------
//   - upgrade_test.go / snapshotter_upgrade_test.go: one test each.
//   - snapshotter_helpers_test.go: helpers observing the containerd
//     snapshotter stores and the /persist free space they compete for, plus
//     the shared k3sNodeIsReady predicate and the app/NI fixtures.
//
// TestUpgradeSuite runs TestEVEUpgrade across multiple hypervisor combinations
// and disk sizes, then TestSnapshotterUpgrade across the two eve-k app modes,
// the reclaim/rollback path, and the out-of-space path.
// IMPORTANT: In this test suite, it is assumed that the tested EVE version
// (selected by the variable EVETEST_EVE_VERSION) is at least 17.0.0
// and therefore uses the 2 * 10GB partition layout.
func TestUpgradeSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	const (
		// 16.0.0-lts has small enough partitions to boot on smallDiskSizeMiB.
		// The target EVE version (>= 17.0.0) requires larger partitions, so the
		// upgrade fails and EVE reverts -- which is what the *WithSmallDisk variants
		// are designed to test.
		initialEVEVersionForKVM = "16.0.0-lts"

		// EVE-K (k3s/kubevirt-based EVE) is officially supported starting from 17.0.0.
		initialEVEVersionForKubevirt = "17.0.0-lts"

		// The OCI-datastore variant points EVE at evetest's own embedded OCI
		// registry (see PushDockerImageToLocalRegistry), which is fronted by
		// the harness's self-signed CA. Resolving an OCI tag against a
		// custom-CA registry only started honoring the datastore's trusted
		// certificates in pillar commit 90fb8664 ("downloader: ds custom
		// certs when resolving OCI"); before that, tag resolution opened the
		// registry without them and failed TLS verification even though the
		// certs were (and still are) applied correctly for the subsequent
		// download. That fix is included in 17.0.0-lts (but not in 16.0.0-lts).
		initialEVEVersionForOCIDatastore = "17.0.0-lts"

		// Enough for the pre-10GB partition layout, but not enough for EVE 17.0.0+,
		// which is why *WithSmallDisk variants expect revert.
		smallDiskSizeMiB = uint32(20480) // 20 GiB

		// initialEVEVersionForSnapshotter is the pre-erofs base for the
		// TestSnapshotterUpgrade variants. It has to be a build whose
		// pkg/kube/config-k3s.toml still sets snapshotter = "overlayfs", so
		// that the upgrade has something to convert.
		//
		// A master snapshot rather than a release, for two reasons: master is
		// what devices actually run immediately before this change, and
		// 17.0.0-lts-k is unusable as a base -- its TPM path cannot sign the
		// TLS handshake to the controller ("signing data using TPM failed:
		// handle 1 ... not correct for the use", so onboarding never
		// completes), and with TPM disabled its app deploy still times out in
		// INITIAL.
		//
		// Pinned by commit because upstream publishes no floating eve-k
		// snapshot tag (snapshot-k-amd64 is 404; only 16.0-stable-k-amd64
		// floats). Docker Hub prunes old snapshots, so re-pin this to a
		// current master build when the tag disappears.
		initialEVEVersionForSnapshotter = "0.0.0-master-5786db09"
	)

	// Define configurable parameters available for the test suite.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestEVEUpgrade,
			// Target EVE version is common to all variants: set via EVETEST_EVE_VERSION.
			Variants: []evetest.TestVariant{
				{
					Name: "TestEVEUpgradeKVMtoKVM",
					Parameters: []evetest.TestParameterValue{
						// Initial
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForKVM},
						{Key: initialHypervisorParamKey, Value: evetest.HypervisorKVM},
						// Target
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKVM},
					},
				},
				{
					Name: "TestEVEUpgradeKVMtoKVMWithOCIDatastore",
					Parameters: []evetest.TestParameterValue{
						// Initial
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForOCIDatastore},
						{Key: initialHypervisorParamKey, Value: evetest.HypervisorKVM},
						// Target
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKVM},
						// Have EVE pull the target rootfs directly from its OCI registry
						// instead of the default evetest-hosted HTTP datastore.
						{Key: datastoreTypeParamKey, Value: evetest.BaseOSDatastoreOCI},
					},
				},
				{
					Name: "TestEVEUpgradeKubevirtToKubevirt",
					Parameters: []evetest.TestParameterValue{
						// Initial
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForKubevirt},
						{Key: initialHypervisorParamKey, Value: evetest.HypervisorKubevirt},
						// Target
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKubevirt},
					},
				},
				{
					Name: "TestEVEUpgradeKVMtoKubevirt",
					Parameters: []evetest.TestParameterValue{
						// Initial
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForKVM},
						{Key: initialHypervisorParamKey, Value: evetest.HypervisorKVM},
						// Target
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKubevirt},
					},
				},
				{
					Name: "TestEVEUpgradeKVMtoKVMWithSmallDisk",
					Parameters: []evetest.TestParameterValue{
						// Initial
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForKVM},
						{Key: initialHypervisorParamKey, Value: evetest.HypervisorKVM},
						// Target
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKVM},
						// Extra params
						{Key: evetest.DiskSizeMiBParameterKey, Value: smallDiskSizeMiB},
						// Expect upgrade to fail
						{Key: expectRevertParamKey, Value: true},
					},
				},
				{
					Name: "TestEVEUpgradeKVMtoKubevirtWithSmallDisk",
					Parameters: []evetest.TestParameterValue{
						// Initial
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForKVM},
						{Key: initialHypervisorParamKey, Value: evetest.HypervisorKVM},
						// Target
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKubevirt},
						// Extra params
						{Key: evetest.DiskSizeMiBParameterKey, Value: smallDiskSizeMiB},
						// Expect upgrade to fail
						{Key: expectRevertParamKey, Value: true},
					},
				},
			},
		},
		evetest.TestCase{
			Test: TestSnapshotterUpgrade,
			Variants: []evetest.TestVariant{
				{
					// The path the overlayfs->erofs switch actually changes:
					// a plain k8s pod whose image CRI must re-unpack.
					//
					// TPM is off for every variant here: an eve-k device cannot
					// sign the TLS handshake to the controller with the emulated
					// TPM ("signing data using TPM failed: handle 1 ... not
					// correct for the use"), so onboarding never completes.
					// Reproduced on both 17.0.0-lts-k and master-k, so it is an
					// eve-k/swtpm problem rather than a property of the base
					// version -- revisit once that is fixed.
					Name: "TestSnapshotterUpgradeNativeContainer",
					Parameters: []evetest.TestParameterValue{
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForSnapshotter},
						{Key: evetest.TPMParameterKey, Value: false},
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKubevirt},
						{Key: appVirtModeParamKey, Value: appVirtModeNoHyper},
					},
				},
				{
					// Control: a VMIRS-backed app off a PVC, which never
					// reaches the CRI snapshotter.
					Name: "TestSnapshotterUpgradeVMBackedApp",
					Parameters: []evetest.TestParameterValue{
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForSnapshotter},
						{Key: evetest.TPMParameterKey, Value: false},
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKubevirt},
						{Key: appVirtModeParamKey, Value: appVirtModeHVM},
					},
				},
				{
					// Once kube-init has reclaimed the superseded overlayfs
					// snapshots, an operator-forced rollback must still land
					// on a working app.
					Name: "TestSnapshotterUpgradeForcedRollback",
					Parameters: []evetest.TestParameterValue{
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForSnapshotter},
						{Key: evetest.TPMParameterKey, Value: false},
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKubevirt},
						{Key: appVirtModeParamKey, Value: appVirtModeNoHyper},
						{Key: verifyRollbackParamKey, Value: true},
					},
				},
				{
					// The conversion is forced with /persist below kubelet's
					// eviction floor, then the space is returned.
					Name: "TestSnapshotterUpgradeOutOfSpace",
					Parameters: []evetest.TestParameterValue{
						{Key: initialEVEVersionParamKey, Value: initialEVEVersionForSnapshotter},
						{Key: evetest.TPMParameterKey, Value: false},
						{Key: evetest.HypervisorParameterKey, Value: evetest.HypervisorKubevirt},
						{Key: appVirtModeParamKey, Value: appVirtModeNoHyper},
						{Key: constrainPersistParamKey, Value: true},
					},
				},
			},
		},
	)
}
