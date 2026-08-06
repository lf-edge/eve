// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestTelemetrySuite drives the three channels through which EVE reports
// itself to the controller: info messages, metric messages and logs. None of
// the subtests deploys an application -- they exercise the EVE control plane
// only -- and therefore none parameterizes the hypervisor; all hardcode
// HypervisorKVM, as the other non-application suites do.
//
// Every subtest declares the TPM parameter and passes it to
// RequireEdgeDevice, so all three state identical device requirements and the
// framework reuses a single VM across the suite. Only TestDeviceInfo actually
// asserts on the TPM (via HSMStatus); for the other two the parameter merely
// selects which device flavor the suite runs on.
//
// Subtests
// --------
//   - TestDeviceInfo -- ZInfoDevice reports the applied port configuration,
//     a plausible hardware inventory and the HSM state.
//   - TestDeviceMetrics -- DeviceMetric reports moving per-port network
//     counters plus memory, CPU and controller-connectivity counters.
//   - TestDeviceLogs -- logs produced by EVE services reach the controller.
func TestTelemetrySuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	// Define parameters for the entire test suite.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestDeviceInfo,
		},
		evetest.TestCase{
			Test: TestDeviceMetrics,
		},
		evetest.TestCase{
			Test: TestDeviceLogs,
		},
	)
}
