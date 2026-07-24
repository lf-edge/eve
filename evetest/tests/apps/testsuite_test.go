// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestApplicationLifecycleSuite drives application life-cycle scenarios:
// controller-requested operations that take an already deployed application
// instance through halt/boot cycles without redeploying it. All subtests
// deploy an application and therefore share the HYPERVISOR parameter -- the
// suite declares evetest.HypervisorParameter() once and every subtest reads
// it via evetest.GetHypervisorParameterValue(). Each subtest also calls
// evetest.SkipIfHypervisorKubevirt() right after reading the value: Kubevirt
// is reserved for cluster tests under evetest/tests/cluster.
//
// Subtests
// --------
//   - TestAppRestart -- controller-requested application restart (restart
//     counter bump, i.e. a domain restart without purge), repeated several
//     times in a row.
func TestApplicationLifecycleSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	// Define parameters for the entire test suite.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestAppRestart,
		},
	)
}
