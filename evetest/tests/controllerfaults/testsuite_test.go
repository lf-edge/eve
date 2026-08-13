// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllerfaults_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestControllerFaultsSuite covers how EVE behaves when the controller fails
// the requests through which a device reports itself. The controller runs
// behind a proxy which the subtests tell to answer, reject or drop selected
// device requests; every subtest arms its own faults and clears them again.
//
// The subtests share one device and one network model so that the framework
// reuses a single VM across the suite, and all of them hardcode the hypervisor
// parameter's default, as the other non-application suites do.
//
// Subtests
// --------
//   - TestInfoRetriedAfterServerError -- a state change reported while the
//     controller answers 503 still reaches it afterwards.
//   - TestInfoRetriedAfterLostController -- the same when the controller cannot
//     be reached at all.
//   - TestInfoDroppedOnRejectionKeepsDeviceReporting -- a message the
//     controller rejects outright is given up on, and later changes are still
//     reported.
func TestControllerFaultsSuite(test *testing.T) {
	// The controller is started while the harness comes up, so it has to be
	// told to run behind the fault injecting proxy before Init.
	evetest.EnableControllerFaults()

	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestInfoRetriedAfterServerError,
		},
		evetest.TestCase{
			Test: TestInfoRetriedAfterLostController,
		},
		evetest.TestCase{
			Test: TestInfoDroppedOnRejectionKeepsDeviceReporting,
		},
	)
}
