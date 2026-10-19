// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestTelemetrySuite drives the channels through which EVE reports itself to the
// controller - info messages, metric messages and logs - and the configuration
// of the on-device pipeline that produces the logs. That pipeline is newlogd,
// which collects events from memlogd and the kernel and uploads them to the
// controller in gzip batches.
//
// Every subtest declares the HYPERVISOR and TPM parameters and passes both to
// setupTelemetryTestDevice, which states the device requirements in one place.
// That is what lets the framework reuse a single VM across the suite: it
// compares the requirements field by field, so any divergence silently costs a
// full device recreation. TestDeviceInfo asserts on the
// TPM (via HSMStatus); for the others both parameters
// merely select the device flavor. None of the subtests deploys an application,
// but the hypervisor is a parameter regardless, even though nothing here is
// hypervisor-specific.
//
// The subtests are grouped by subject - what EVE reports, then how the log
// pipeline is configured - and the two that reboot the device go last so that
// the others do not pay for a reboot. Nothing beyond that is load-bearing: the
// framework resets the device configuration between subtests, and each subtest
// establishes the state it needs before it asserts anything, so the order can be
// changed freely.
//
// Subtests
// --------
//   - TestDeviceInfo -- ZInfoDevice reports the applied port configuration,
//     a plausible hardware inventory and the HSM state.
//   - TestDeviceMetrics -- DeviceMetric reports moving per-port network
//     counters plus memory, CPU and controller-connectivity counters.
//   - TestDeviceLogs -- logs produced by EVE services and by the kernel reach
//     the controller.
//   - TestRemoteLogLevelNone -- remote log levels set to "none" stop log upload
//     without stopping the device or its local log collection.
func TestTelemetrySuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	// Define parameters for the entire test suite.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
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
		evetest.TestCase{
			Test: TestRemoteLogLevelNone,
		},
	)
}
