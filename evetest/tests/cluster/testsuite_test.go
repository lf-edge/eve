// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestNodeClusterSuite is the top-level entry point for the functional cluster
// tests. It reuses the evetest harness (Adam controller, SDN, broker) across
// the subtests for efficiency. All subtests pin the device to the Kubevirt
// hypervisor (aka eve-k). Tests that inject faults or stress failure
// handling live in TestNodeClusterResilienceSuite.
//
// The single-node subtests run before the three-node ones. The three-node
// subtests that share device requirements and network model run back to back
// so that evetest can reuse the provisioned devices; TestClusterVMApp needs
// its own device requirements (no vCPU caps) and therefore runs last.
//
// Test parameters
// ---------------
//   - TPM (bool) via evetest.TPMParameter(). The suite passes the same
//     TPM choice to all subtests.
func TestNodeClusterSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	// Define configurable parameters available for the test suite.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestSingleNodeCluster,
		},
		evetest.TestCase{
			// Device requirements and network model match TestSingleNodeCluster's
			// exactly, so the framework reuses its device instead of creating a
			// new one.
			Test: TestNativeKubeAppNetworking,
		},
		evetest.TestCase{
			Test: TestAppInstancePurge,
		},
		evetest.TestCase{
			Test: TestThreeNodesCluster,
		},
		evetest.TestCase{
			// Runs right after TestThreeNodesCluster, whose devices it reuses.
			Test: TestThreeNodesPortScan,
		},
		evetest.TestCase{
			// Its default NUM_NODES=3 device requirements and network model
			// match TestThreeNodesCluster's exactly, letting evetest reuse the
			// same already-provisioned devices.
			Test: TestMgmtProxy,
		},
		evetest.TestCase{
			Test: TestTieBreakerCluster,
		},
		evetest.TestCase{
			Test: TestClusterToSingleConversion,
		},
		evetest.TestCase{
			Test: TestClusterVMApp,
		},
	)
}

// TestNodeClusterResilienceSuite is the entry point for the cluster tests that
// inject faults or stress failure handling, as opposed to the functional tests
// in TestNodeClusterSuite. It reuses the evetest harness (Adam controller,
// SDN, broker) across the subtests for efficiency. All subtests pin the device
// to the Kubevirt hypervisor (aka eve-k).
//
// The single-node subtest runs first, then the three-node ones from the least
// to the most disruptive. TestVMAppPurgeDuringFailover builds its cluster from
// scratch rather than resetting the device config, and TestClusterPVCRedownload
// power-cycles every node and cuts off the datastore, so they go last.
//
// Test parameters
// ---------------
//   - TPM (bool) via evetest.TPMParameter(). The suite passes the same
//     TPM choice to all subtests.
func TestNodeClusterResilienceSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	// Define configurable parameters available for the test suite.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestVMIRSStrandedReplicasRecovery,
		},
		evetest.TestCase{
			Test: TestDNIDandBackupDNID,
		},
		evetest.TestCase{
			Test: TestVMAppPurgeDuringFailover,
		},
		evetest.TestCase{
			Test: TestClusterPVCRedownload,
		},
	)
}
