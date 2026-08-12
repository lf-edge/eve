// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test how the configured log levels govern which device logs EVE forwards to
// the controller.

package telemetry_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	evemetrics "github.com/lf-edge/eve-api/go/metrics"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// Every source stays verbose locally while nothing is forwarded, so that what
	// the test observes is attributable to the remote setting alone.
	mutedLocalLogLevel  = "debug"
	mutedRemoteLogLevel = "none"

	// The kernel path has its own knobs, separate from the debug.default.* ones
	// the framework sets. "info" is also EVE's default for them.
	unmutedKernelLogLevel = "info"

	// The one entry class a remote level of "none" still uploads.
	panicSeverity = "panic"
)

// TestRemoteLogLevelNone verifies the controller-observable contract of setting
// every remote log level to "none": log upload stops, the device stays alive and
// keeps reporting throughout, and clearing the setting starts upload again.
//
// The central claim is negative ("no logs arrive"), which a broken test satisfies
// as well as a working EVE. Three things keep it honest: a positive control
// before the mute, liveness during the silence, and a positive control after
// unmuting.
//
// Deliberate gap: nothing here verifies that EVE keeps collecting logs locally
// while muted. That is not controller-observable by construction, so a
// regression in which local filtering followed the *remote* level would leave
// every assertion green. Covering it belongs in a pkg/newlog unit test, not in
// an E2E test coupled to newlogd's on-disk layout.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- log upload only needs controller
//     connectivity over a single mgmt port.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps). The base config object is built
//     once and only its ConfigItems are replaced: rebuilding it would mint a
//     fresh network UUID and churn EVE through a new DPC.
//   - Unmuted: the two kernel knobs at "info". Muted: all three local levels at
//     "debug", all three remote levels at "none".
//   - The framework default newlog.allow.fastupload is what makes the negative
//     assertion's window practical (10s file close, 3s upload poll).
//
// Phases / assertions
// -------------------
//  1. unmuted-config-applied.
//  2. logs-arrive-unmuted: a /dev/kmsg probe reaches the controller with
//     Source="kernel". Positive control.
//  3. logging-muted.
//  4. device-rebooted: produces a fresh set of logs (kernel boot messages plus
//     every agent starting up) under the muted config. This is what exercises
//     newlogd's on-disk log level cache, which handles logs produced before
//     zedagent publishes the live config. The phase *depends* on that cache, so
//     do not clear it mid-test; it also sets the EVE floor -- present from
//     17.0.0-rc2 (including 17.0.0-lts) and on master, absent from 17.0.0 and
//     17.0.0-rc1.
//  5. Anchor at ZInfoDevice.BootTime of the post-reboot message, minus 2s for
//     its +-1s jitter. LastRebootTime only identifies the message: with no
//     recorded reboot reason it is stamped during nodeagent startup, well into
//     the boot, so anchoring on it would exclude the boot logs.
//  6. A fresh probe, so the negative assertion has an entry that provably
//     postdates the mute.
//  7. device-alive-while-muted: a metric message still arrives, which is the
//     assertion -- the silence cannot be blamed on a dead or disconnected
//     device. Its failedToSend flag is a weak extra: newlogd refreshes those
//     values only every 90-300s and nothing in the message dates them, so read
//     it as "the uploader was not already broken going in". Phases 2 and 9 are
//     the real bracketing; an upload wedge that begins and heals inside the
//     muted window stays uncovered.
//  8. no-logs-while-muted: for two minutes neither a post-anchor entry nor the
//     probe is present. Polls are 30s apart because each re-reads the device's
//     entire log history from Adam, and the claim covers the whole period since
//     the anchor regardless of poll count. A panic-level entry fails this phase
//     deliberately, with its own message: "none" still uploads those by design,
//     so it is a finding about the agent.
//  9. logs-arrive-again: a third probe arrives while the muted one stays absent,
//     showing suppressed entries never entered the upload queue.
//
// Expect three to four minutes after setup; the ~35 minute ceiling is almost all
// in the two 10-minute probe-upload limits, which normally complete in seconds.
//
// Test params
// -----------
//   - HYPERVISOR, TPM. Neither is asserted on here; both are declared so that
//     every test in the suite states the same device requirements and the
//     framework can reuse one VM.
//
// Suite placement
// ---------------
//   - TestTelemetrySuite, last: it is the only subtest that reboots, and the
//     others would otherwise pay for it.
func TestRemoteLogLevelNone(test *testing.T) {
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

	// Phase 1: start from a configuration that forwards logs to the controller.
	devConfig := singleMgmtPortConfig()
	setUnmutedLogLevels(devConfig)
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("unmuted-config-applied")
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(clusterNodeReadyTimeout)
	}

	// Phase 2: positive control.
	expectKernelLogProbe(t, device, "unmuted")
	evetest.Checkpoint("logs-arrive-unmuted")

	// Phase 3: mute every log source. Unmute on the way out even on failure:
	// teardown builds the device log artifact by reading the controller, so
	// leaving the device muted would blank the artifact needed to diagnose the
	// failure. It cannot affect any assertion - suppressed entries never enter
	// the upload queue, so unmuting cannot bring them back.
	muted := false
	defer func() {
		if muted {
			setUnmutedLogLevels(devConfig)
			device.ApplyConfig(devConfig, false, false)
		}
	}()
	setMutedLogLevels(devConfig)
	device.ApplyConfig(devConfig, true, true)
	muted = true
	evetest.Checkpoint("logging-muted")

	// Phase 4: reboot to generate fresh logs under the muted config.
	prevRebootTime := device.GetDeviceInfo().GetLastRebootTime().AsTime()
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	device.SoftReboot(true)
	evetest.Checkpoint("device-rebooted")

	// Phase 5: anchor at the boot time reported by the post-reboot info message.
	var rebootAnchor time.Time
	t.Eventually(devUpdates, 3*time.Minute).Should(Receive(matchers.SatisfyPredicate(
		"Device reports the reboot triggered by the test",
		func(info *eveinfo.ZInfoDevice) bool {
			rebootTime := info.GetLastRebootTime()
			bootTime := info.GetBootTime()
			if rebootTime == nil || bootTime == nil ||
				!rebootTime.AsTime().After(prevRebootTime) {
				return false
			}
			rebootAnchor = bootTime.AsTime().Add(-2 * time.Second)
			return true
		})))
	evetest.Logger().Infof(
		"Anchoring the assertion at the device-reported boot time %s", rebootAnchor)

	// Phase 6: emit the probe. Subscribe to metrics first, so the message the
	// liveness assertion waits for is one published while muted.
	metricUpdates, stopMetricWatch := device.WatchDeviceMetrics()
	defer stopMetricWatch()
	probeMarker := newLogProbeMarker("muted")
	emitKernelLogProbe(t, device, probeMarker)

	// Phase 7: the device is still talking to the controller.
	var metric *evemetrics.DeviceMetric
	t.Eventually(metricUpdates, 90*time.Second).Should(Receive(&metric),
		"the device stopped reporting metrics to the controller while muted")
	t.Expect(metric.GetNewlog().GetFailedToSend()).To(BeFalse(),
		"EVE reports its log uploader as failing to send, so an absence of "+
			"uploaded logs would not be attributable to the remote log levels")
	evetest.Checkpoint("device-alive-while-muted")

	// Phase 8: Consistently rather than Eventually - the claim is that the
	// controller stays log-free, not that it becomes so.
	const (
		quietWindow   = 2 * time.Minute
		quietPollIntv = 30 * time.Second
	)
	t.Consistently(func(g Gomega) {
		var afterReboot, probes, panics []evetest.LogMsg
		for _, logMsg := range device.GetLogs(evetest.LogMsgMatch{}) {
			if strings.Contains(logMsg.Message, probeMarker) {
				probes = append(probes, logMsg)
			}
			if logMsg.Timestamp.Before(rebootAnchor) {
				continue
			}
			if logMsg.Severity == panicSeverity {
				panics = append(panics, logMsg)
				continue
			}
			afterReboot = append(afterReboot, logMsg)
		}
		g.Expect(len(panics)).To(BeZero(),
			"an EVE agent panicked during the muted window. A remote log level of "+
				"%q still uploads panic-level entries by design, so this is a "+
				"genuine finding about the agent, not a muting failure.\n%s",
			mutedRemoteLogLevel, summarizeLogMsgs(panics))
		g.Expect(len(afterReboot)).To(BeZero(),
			"EVE uploaded device logs generated after the reboot even though every "+
				"remote log level is set to %q.\n%s",
			mutedRemoteLogLevel, summarizeLogMsgs(afterReboot))
		g.Expect(len(probes)).To(BeZero(),
			"the kernel log probe emitted after the reboot reached the "+
				"controller.\n%s", summarizeLogMsgs(probes))
	}, quietWindow, quietPollIntv).Should(Succeed())
	evetest.Checkpoint("no-logs-while-muted")

	// Phase 9: unmute and confirm recovery. This confirmed apply doubles as the
	// cleanup: waiting for LastProcessedConfig means newlogd has rewritten its
	// on-disk log level cache with the unmuted levels.
	setUnmutedLogLevels(devConfig)
	device.ApplyConfig(devConfig, true, true)
	muted = false
	evetest.Checkpoint("logging-unmuted")
	expectKernelLogProbe(t, device, "unmuted-again")
	t.Expect(device.GetLogs(evetest.LogMsgMatch{MsgHasSubstring: probeMarker})).
		To(BeEmpty(), "the kernel log probe emitted while muted was uploaded "+
			"once remote logging was re-enabled")
	evetest.Checkpoint("logs-arrive-again")
}

// summarizeLogMsgs renders log messages for a failure message: per-source counts,
// busiest first, then the first few verbatim, so a failure answers "which source
// leaked?" without dumping thousands of lines.
func summarizeLogMsgs(logMsgs []evetest.LogMsg) string {
	if len(logMsgs) == 0 {
		return "no matching log messages"
	}
	perSource := make(map[string]int)
	for _, logMsg := range logMsgs {
		perSource[logMsg.Source]++
	}
	sources := make([]string, 0, len(perSource))
	for source := range perSource {
		sources = append(sources, source)
	}
	sort.Slice(sources, func(i, j int) bool {
		if perSource[sources[i]] != perSource[sources[j]] {
			return perSource[sources[i]] > perSource[sources[j]]
		}
		return sources[i] < sources[j]
	})

	var sb strings.Builder
	fmt.Fprintf(&sb, "%d log messages; by source:", len(logMsgs))
	for _, source := range sources {
		fmt.Fprintf(&sb, " %s=%d", source, perSource[source])
	}
	const (
		maxSamples    = 3
		maxSampleLen  = 200
		sampleElision = "..."
	)
	for i, logMsg := range logMsgs {
		if i == maxSamples {
			break
		}
		content := logMsg.Message
		if len(content) > maxSampleLen {
			content = content[:maxSampleLen] + sampleElision
		}
		fmt.Fprintf(&sb, "\n  %s [%s] %s: %s",
			logMsg.Timestamp.Format(time.RFC3339), logMsg.Severity, logMsg.Source,
			content)
	}
	return sb.String()
}

// setUnmutedLogLevels makes devConfig forward logs to the controller. Only the
// kernel knobs are stated; debug.default.* are left to the framework defaults.
func setUnmutedLogLevels(devConfig *evetest.EdgeDeviceConfig) {
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueString(pillartypes.KernelLogLevel, unmutedKernelLogLevel)
	cfgProps.SetGlobalValueString(pillartypes.KernelRemoteLogLevel, unmutedKernelLogLevel)
	replaceConfigProperties(devConfig, cfgProps)
}

// setMutedLogLevels makes devConfig log every source locally at "debug" while
// forwarding none of them. All six keys are stated explicitly; restating the
// framework's own debug.default.loglevel is safe because the framework skips its
// defaults for keys the test already set, so no key lands in ConfigItems twice.
func setMutedLogLevels(devConfig *evetest.EdgeDeviceConfig) {
	cfgProps := pillartypes.NewConfigItemValueMap()
	for _, key := range []pillartypes.GlobalSettingKey{
		pillartypes.DefaultLogLevel,
		pillartypes.SyslogLogLevel,
		pillartypes.KernelLogLevel,
	} {
		cfgProps.SetGlobalValueString(key, mutedLocalLogLevel)
	}
	for _, key := range []pillartypes.GlobalSettingKey{
		pillartypes.DefaultRemoteLogLevel,
		pillartypes.SyslogRemoteLogLevel,
		pillartypes.KernelRemoteLogLevel,
	} {
		cfgProps.SetGlobalValueString(key, mutedRemoteLogLevel)
	}
	replaceConfigProperties(devConfig, cfgProps)
}
