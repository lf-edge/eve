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
// The suite and each of its tests ask Init for the fault proxy themselves.
// Only an explicit EVETEST_CONTROLLER_FAULTS=false turns it off, in which case
// the devices reach the controller directly and these tests skip.
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
//
// TestInfoDroppedOnRejectionKeepsDeviceReporting runs last, and has to: it is
// the one subtest which finishes without waiting for the application state it
// changed to reach the controller, so it hands the shared device on with an
// application the controller still believes is running and may still be
// shutting down. Resetting the device for a following subtest then waits for
// that application to be reported gone, and runs out of its budget.
func TestControllerFaultsSuite(test *testing.T) {
	evetest.Init(test, evetest.WithControllerFaults())
	defer evetest.Close()
	if !evetest.ControllerFaultsEnabled() {
		test.Skip("controller fault injection was turned off; " +
			"unset EVETEST_CONTROLLER_FAULTS to run this test")
	}

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
