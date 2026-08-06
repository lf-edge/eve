// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test the device logs that EVE collects and uploads to the controller.

package telemetry_test

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// Prefix of the marker written to /dev/kmsg. A per-run nonce is appended so
// the assertion cannot be satisfied by a log entry from an earlier run.
const kmsgMarkerPrefix = "evetest-device-log-marker"

// TestDeviceLogs verifies that EVE collects logs and uploads them to the
// controller: a message emitted on the device in response to an externally
// triggered event must become visible to the controller, and the log stream
// of EVE's own microservices must be flowing as well.
//
// The trigger is a marker written to /dev/kmsg rather than something logged by
// a third-party daemon. Driving SSH sessions and matching on sshd's
// "Disconnected from" was tried first and does not work: the sessions are
// established (so sshd definitely handled them), but no matching entry ever
// reaches the controller within 10 minutes. /dev/kmsg is an ingestion path EVE
// documents and relies on itself -- ssh-service.sh writes there with the
// comment "this is picked up by newlogd" -- which makes the trigger
// deterministic and the assertion immune to third-party log wording.
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
//  2. Subscribe to device logs matching a per-run marker string *before*
//     emitting it, then write the marker to /dev/kmsg over SSH.
//  3. kernel-log-received: the marker reaches the controller. Assert
//     Source="kernel" (the entry was attributed to the right ingestion
//     path), Severity is populated, and the timestamp is not in the future --
//     i.e. a well-formed log record, not merely a matching string.
//  4. The pillar agents' log stream is flowing too: entries with
//     Source="zedagent" have been uploaded (base/logobjecttypes.go sets the
//     "source" field to the agent name).
//
// Timing note: logs are batched into gzip bundles before upload, so the wait
// in phase 3 is generous even with fast upload enabled.
//
// Test params
// -----------
//   - TPM. Declared only so that every test in the suite states the same
//     device requirements and the framework can reuse one VM; nothing here
//     depends on the TPM.
//
// Suite placement
// ---------------
//   - TestTelemetrySuite. No application is deployed, so the hypervisor is
//     hardcoded to KVM like the other non-app suites.
func TestDeviceLogs(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.TPMParameter(),
	)

	// Get parameter values set for this test execution.
	useTPM := evetest.GetTPMParameterValue()

	// Set up the test harness and specify the test prerequisites.
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    evetest.HypervisorKVM,
			WithTPM:           useTPM,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
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

	// Phase 2: subscribe first, then emit the marker.
	marker := fmt.Sprintf("%s-%d", kmsgMarkerPrefix, time.Now().UnixNano())
	logs, stopLogWatch := device.WatchLogs(evetest.LogMsgMatch{
		MsgHasSubstring: marker,
	})
	defer stopLogWatch()

	const (
		sshTimeout = 30 * time.Second
		logTimeout = 10 * time.Minute
	)
	_, _, err := device.RunShellScript(
		fmt.Sprintf("echo %q > /dev/kmsg", marker), sshTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	evetest.Logger().Infof(
		"Emitted marker %q on the device, waiting for it to reach the controller...",
		marker)

	// Phase 3: the message reaches the controller.
	var logMsg evetest.LogMsg
	t.Eventually(logs, logTimeout).Should(Receive(&logMsg),
		"device log marker was not uploaded to the controller")
	t.Expect(logMsg.Message).To(ContainSubstring(marker))
	t.Expect(logMsg.Source).To(Equal("kernel"))
	t.Expect(logMsg.Severity).ToNot(BeEmpty())
	t.Expect(logMsg.Timestamp).To(BeTemporally("<", time.Now()))
	evetest.Checkpoint("kernel-log-received")

	// Phase 4: EVE's own microservices are logging to the controller as well.
	agentLogs := device.GetLogs(evetest.LogMsgMatch{Source: "zedagent"})
	t.Expect(agentLogs).ToNot(BeEmpty(),
		"no zedagent log messages were uploaded to the controller")
}
