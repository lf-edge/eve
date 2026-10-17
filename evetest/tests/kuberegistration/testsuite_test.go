// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package kuberegistration_test covers controller registration of an EVE-K
// cluster with native Kubernetes orchestration (informally "base mode"): a
// CLUSTER_TYPE_REPLICATED_STORAGE cluster with EnableNativeK8SOrchestration,
// the opt-in that replaced CLUSTER_TYPE_K3S_BASE. EVE then serves
// EVE-API-scheduled and natively-applied workloads side by side, and the
// controller registers the cluster through a manifest EVE hands to k3s.
//
// These tests are staged, not independent: the first forms the cluster and
// the others build on the one it leaves running, which travels between them
// in kubeRegCluster (helpers_test.go). Before adding a test here:
//
//   - Every test must declare the same devices and network model, or the
//     harness tears the VMs down between tests and takes the cluster with
//     them. kubeRegRequirements is the single source of both.
//   - Only the first test may use a reuse policy other than UseAsIs;
//     ResetDeviceConfig strips every cipher block from the retained config,
//     the join token included.
//
// Layout: helpers_test.go holds the shared environment, the Kubernetes
// readers and the cluster handed between tests; clustersetup_test.go,
// addnode_test.go and longhorndisks_test.go hold one test each, in suite
// order.
package kuberegistration_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestKubeRegistrationSuite is the entry point for the native-K8s cluster
// tests. It reuses the harness (Adam, SDN, broker) and the EVE devices across
// its subtests, which is what lets the cluster survive between them.
//
// Order is load-bearing here: each subtest starts from the cluster the
// previous one left. Running one on its own fails with an explanation (see
// requireKubeRegCluster), and EVETEST_RESTART_ONLY_FAILED cannot be used for
// the same reason -- skipping the setup test leaves nothing to run against.
//
// Test parameters
// ---------------
//   - TPM (bool) via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// The same values go to every subtest, which they must: a device is reused
// only when the new test's requirements match it field for field.
func TestKubeRegistrationSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	// Define configurable parameters available for the test suite.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestKubeRegistrationClusterSetup,
		},
		evetest.TestCase{
			Test: TestKubeRegistrationAddNode,
		},
		evetest.TestCase{
			Test: TestKubeRegistrationLonghornDisks,
		},
	)
}
