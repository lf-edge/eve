// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestNodeClusterSuite is the top-level entry point for cluster tests.
// It runs TestSingleNodeCluster followed by TestThreeNodesCluster,
// reusing the evetest harness (Adam controller, SDN, broker) across both
// subtests for efficiency. Both subtests pin the device to the Kubevirt
// hypervisor (cluster tests are the only ones that use Kubevirt).
//
// Test parameters
// ---------------
//   - TPM (bool) via evetest.TPMParameter(). The suite passes the same
//     TPM choice to both subtests.
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
			Test: TestThreeNodesCluster,
		},
	)
}
