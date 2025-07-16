// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package lps_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestLPSSuite is the entry point for Local Profile Server (LPS) tests.
// Currently it contains only TestNetworkLocalChanges. The TODO above
// indicates we will enable HypervisorParameter once the suite grows to
// include app-related LPS scenarios that depend on hypervisor choice;
// for now the single subtest hardcodes its own hypervisor.
func TestLPSSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	/* TODO: re-enable if there are any app-related LPS tests
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	*/

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestNetworkLocalChanges,
		},
	)
}
