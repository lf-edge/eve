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
// which collects events from memlogd and the kernel, routes them through Vector
// (EVE's log-processing engine, configured with the vector.config global config
// item) and uploads them to the controller in gzip batches.
//
// Every subtest declares the HYPERVISOR and TPM parameters and passes both to
// setupTelemetryTestDevice, which states the device requirements in one place.
// That is what lets the framework reuse a single VM across the suite: it
// compares the requirements field by field, so any divergence silently costs a
// full device recreation. Only TestDeviceInfo asserts on the TPM (via
// HSMStatus); for the others both parameters merely select the device flavor.
// None of the subtests deploys an application, but the hypervisor is a parameter
// regardless, so that the suite can be run against eve-k - where the log
// pipeline and the reporting paths are worth covering even though nothing here
// is hypervisor-specific. It has so far only been run under KVM.
//
// The subtests are grouped by subject - what EVE reports, then how the log
// pipeline is configured - and TestRemoteLogLevelNone goes last because it is
// the only one that reboots, which the others would otherwise pay for. Nothing
// beyond that is load-bearing: the framework resets the device configuration
// between subtests, and each subtest establishes the state it needs before it
// asserts anything, so the order can be changed freely.
//
// Subtests
// --------
//   - TestDeviceInfo -- ZInfoDevice reports the applied port configuration,
//     a plausible hardware inventory and the HSM state.
//   - TestDeviceMetrics -- DeviceMetric reports moving per-port network
//     counters plus memory, CPU and controller-connectivity counters.
//   - TestDeviceLogs -- logs produced by EVE services and by the kernel reach
//     the controller.
//   - TestWorkingConfig -- a valid custom Vector config is promoted and
//     actively transforms the upload stream.
//   - TestFaultyConfig -- a Vector config that fails validation is never
//     promoted and the running pipeline keeps uploading.
//   - TestEmptyConfig -- clearing vector.config restores the Vector config
//     built into the image.
//   - TestInvalidBase64Config -- a vector.config value that is not base64 is
//     rejected by pillar and never reaches Vector.
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
			Test: TestWorkingConfig,
		},
		evetest.TestCase{
			Test: TestFaultyConfig,
		},
		evetest.TestCase{
			Test: TestEmptyConfig,
		},
		evetest.TestCase{
			Test: TestInvalidBase64Config,
		},
		evetest.TestCase{
			Test: TestRemoteLogLevelNone,
		},
	)
}
