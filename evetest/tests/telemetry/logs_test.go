// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test the device logs that EVE collects and uploads to the controller.

package telemetry_test

import (
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// TestDeviceLogs verifies that EVE collects logs and uploads them to the
// controller: a message emitted on the device in response to an externally
// triggered event must become visible to the controller, and the log stream
// of EVE's own microservices must be flowing as well.
//
// The trigger is a kernel log probe (see emitKernelLogProbe) rather than
// something logged by a third-party daemon, which makes it deterministic and
// the assertion immune to third-party log wording.
//
// Two ingestion paths are covered:
//   - /dev/kmsg -> getKernelMsg -> newlogd (source "kernel"), driven by the
//     test, and
//   - the pillar agents' memlog path (source = agent name), which is EVE
//     logging on its own.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- log upload only needs working
//     controller connectivity over a single mgmt port.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), logical label "ethernet0".
//   - debug.kernel.loglevel and debug.kernel.remote.loglevel set to "info".
//     Both already default to "info" (types.SyslogKernelDefaultLogLevel) and
//     a userspace write to /dev/kmsg lands at that priority, but the kernel
//     path is gated by its own knobs -- separate from the debug.default.*
//     ones the framework sets -- so the test states its dependency instead of
//     inheriting it.
//   - The framework defaults already enable newlog.allow.fastupload.
//
// Phases / assertions
// -------------------
//  1. setup-done -> config-applied.
//  2. kernel-log-received: a kernel log probe reaches the controller,
//     attributed to Source="kernel" and with Severity populated, i.e. a
//     well-formed log record rather than merely a matching string.
//  3. The pillar agents' log stream is flowing too: entries with
//     Source="zedagent" have been uploaded (base/logobjecttypes.go sets the
//     "source" field to the agent name).
//
// Timing note: logs are batched into gzip bundles before upload, so the wait
// in phase 2 is generous even with fast upload enabled.
//
// Test params
// -----------
//   - HYPERVISOR, TPM. Neither is asserted on here; both are declared so that
//     every test in the suite states the same device requirements and the
//     framework can reuse one VM.
//
// Suite placement
// ---------------
//   - TestTelemetrySuite.
func TestDeviceLogs(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.TPMParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()
	useTPM := evetest.GetTPMParameterValue()

	// Set up the test harness and specify the test prerequisites.
	device := setupTelemetryTestDevice(hypervisor, useTPM)
	evetest.Checkpoint("setup-done")

	// Build and apply the device configuration. The kernel log path has its
	// own level knobs, independent of the framework-wide debug.default.*.
	devConfig := singleMgmtPortConfig()
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueString(pillartypes.KernelLogLevel, "info")
	cfgProps.SetGlobalValueString(pillartypes.KernelRemoteLogLevel, "info")
	devConfig.SetConfigProperties(cfgProps)
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(clusterNodeReadyTimeout)
	}

	// Phase 2: a kernel log probe reaches the controller.
	expectKernelLogProbe(t, device, "device-logs")
	evetest.Checkpoint("kernel-log-received")

	// Phase 3: EVE's own microservices are logging to the controller as well.
	agentLogs := device.GetLogs(evetest.LogMsgMatch{Source: "zedagent"})
	t.Expect(agentLogs).ToNot(BeEmpty(),
		"no zedagent log messages were uploaded to the controller")
}
