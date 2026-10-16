// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test that a kernel panic recorded in pstore is reported after the reboot.

package telemetry_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
)

const (
	// The device reboots panic=120 seconds after the panic, so this covers
	// that delay plus a full boot and reconnection to the controller.
	kernelPanicRebootTimeout = 15 * time.Minute

	// How long nodeagent may take, once the device is back, to have saved the
	// dump and erased its records, and newlogd to have uploaded the log lines.
	kernelPanicReportTimeout = 10 * time.Minute

	// The message panic() prints for "echo c > /proc/sysrq-trigger".
	sysrqPanicMessage = "Kernel panic - not syncing: sysrq triggered crash"

	// Where nodeagent reads pstore and saves the dumps, as seen from the
	// pillar container.
	pillarPstoreDir = "/hostfs/sys/fs/pstore"
	kcrashesGlob    = "/persist/kcrashes/pstore-*.log"
)

// TestKernelPanicReport verifies that a kernel panic reaches the controller and
// /persist when EVE runs without a crash kernel: the panicking kernel writes the
// tail of its log to pstore (efi-pstore under the OVMF firmware the framework
// boots the device with), and on the next boot nodeagent saves it, logs it as a
// kernel panic stack trace and turns it into the reboot reason.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- only controller connectivity is needed.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), logical label "ethernet0".
//   - The framework defaults set debug.default.remote.loglevel to "debug" and
//     enable newlog.allow.fastupload, so the Warn-level stack lines are uploaded.
//
// Phases / assertions
// -------------------
//  1. setup-done -> config-applied: the device is onboarded, its pstore holds
//     no records and its last boot reason is not BOOT_REASON_KERNEL, so
//     nothing below can be satisfied by an earlier boot.
//  2. kernel-panicked: "echo c > /proc/sysrq-trigger", with the reboot that
//     follows declared through ExpectReboots.
//  3. reboot-reported: ZInfoDevice reports lastBootReason BOOT_REASON_KERNEL,
//     lastRebootReason "kernel panic, pstore: <panic message>" and a
//     lastRebootStack that starts at the panic message and holds the
//     crashing frame, sysrq_handle_crash.
//  4. logs-reported: the controller receives the "Kernel panic stack trace
//     from pstore" header, a line of the kernel log on a kernel_panic_stacks
//     log object holding the panic message, and the end marker, and no
//     "[dmesg #N]" copy of the reboot stack.
//  5. persist-checked: the dump is in /persist/kcrashes and holds
//     lastRebootStack, the device's /persist/newlog holds the
//     kernel_panic_stacks lines, and pstore is empty.
//
// Test params
// -----------
//   - HYPERVISOR, TPM. Neither is asserted on here; both are declared so that
//     every test in the suite states the same device requirements and the
//     framework can reuse one VM.
//
// Suite placement
// ---------------
//   - TestTelemetrySuite, among the subtests that reboot the device.
func TestKernelPanicReport(test *testing.T) {
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

	devConfig := singleMgmtPortConfig()
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(clusterNodeReadyTimeout)
	}

	// Phase 1: nothing left over from an earlier boot.
	t.Expect(device.GetDeviceInfo().GetLastBootReason()).
		ToNot(Equal(info.BootReason_BOOT_REASON_KERNEL),
			"the device already reports a kernel panic before the test panics it")
	t.Expect(runInPillar(t, device, "ls -A "+pillarPstoreDir)).To(BeEmpty(),
		"pstore holds records before the test panics the device")
	backend := runInPillar(t, device,
		"cat /hostfs/sys/module/pstore/parameters/backend 2>&1 || true")
	evetest.Logger().Infof("pstore backend: %q", strings.TrimSpace(backend))

	// Every watch is opened before the panic: they deliver only what arrives
	// after subscribing, so nothing they deliver can predate the panic.
	devUpdates, stopDevWatch := device.WatchDeviceInfo()
	defer stopDevWatch()
	headerLogs, stopHeaderWatch := device.WatchLogs(evetest.LogMsgMatch{
		MsgHasSubstring: "Kernel panic stack trace from pstore",
	})
	defer stopHeaderWatch()
	stackLogs, stopStackWatch := device.WatchLogs(evetest.LogMsgMatch{
		MsgHasSubstring: "kernel_panic_stacks",
	})
	defer stopStackWatch()
	endLogs, stopEndWatch := device.WatchLogs(evetest.LogMsgMatch{
		MsgHasSubstring: "Kernel panic stack trace: end of stack",
	})
	defer stopEndWatch()

	// Phase 2: panic. The SSH session dies with the kernel, so its error is
	// expected and not checked.
	device.ExpectReboots(1)
	panickedAt := time.Now()
	_, _, _ = device.RunShellScript(
		"sync; echo c > /proc/sysrq-trigger", probeSSHTimeout, 0)
	evetest.Logger().Infof("Triggered a kernel panic at %s", panickedAt)
	evetest.Checkpoint("kernel-panicked")

	// Phase 3: the controller sees the panic as the reboot reason.
	var devInfo *info.ZInfoDevice
	t.Eventually(devUpdates, kernelPanicRebootTimeout).Should(Receive(&devInfo,
		WithTransform(func(m *info.ZInfoDevice) info.BootReason {
			return m.GetLastBootReason()
		}, Equal(info.BootReason_BOOT_REASON_KERNEL))),
		"the device never reported BOOT_REASON_KERNEL after the panic")
	evetest.Logger().Infof("lastRebootReason: %q, lastRebootTime: %s",
		devInfo.GetLastRebootReason(), devInfo.GetLastRebootTime().AsTime())
	t.Expect(devInfo.GetLastRebootReason()).
		To(HavePrefix("kernel panic, pstore: " + sysrqPanicMessage))
	t.Expect(devInfo.GetLastRebootStack()).To(And(
		ContainSubstring(sysrqPanicMessage), ContainSubstring("sysrq_handle_crash")))
	t.Expect(strings.Index(devInfo.GetLastRebootStack(), sysrqPanicMessage)).
		To(BeNumerically("<", strings.Index(devInfo.GetLastRebootStack(), "\n")),
			"lastRebootStack does not start at the panic message")
	// The reboot time is the pstore record's mtime, which has one-second
	// resolution.
	t.Expect(devInfo.GetLastRebootTime().AsTime()).
		To(BeTemporally(">=", panickedAt.Truncate(time.Second)),
			"lastRebootTime is not the time of this test's panic")
	evetest.Checkpoint("reboot-reported")

	// Phase 4: the dump is logged as a kernel panic stack trace.
	t.Eventually(headerLogs, kernelPanicReportTimeout).Should(Receive(
		WithTransform(logMessage, ContainSubstring(sysrqPanicMessage))),
		"the kernel panic stack trace header was not uploaded")
	t.Eventually(stackLogs, kernelPanicReportTimeout).Should(Receive(
		WithTransform(logMessage, And(
			ContainSubstring("[kernel panic #"),
			ContainSubstring(sysrqPanicMessage)))),
		"no kernel_panic_stacks line holding the panic message was uploaded")
	t.Eventually(endLogs, kernelPanicReportTimeout).Should(Receive(),
		"the kernel panic stack trace end marker was not uploaded")
	t.Expect(device.GetLogs(evetest.LogMsgMatch{
		MsgHasSubstring: "[dmesg #",
		NotBefore:       panickedAt,
	})).To(BeEmpty(), "the reboot stack was logged a second time as [dmesg #N]")
	evetest.Checkpoint("logs-reported")

	// Phase 5: the copies on /persist, and the records erased.
	kcrashes := runInPillar(t, device,
		"grep -l \"sysrq triggered crash\" "+kcrashesGlob+" || true")
	evetest.Logger().Infof("dumps holding the panic: %q", kcrashes)
	t.Expect(kcrashes).ToNot(BeEmpty(), "no dump holding the panic in /persist/kcrashes")
	dump := runInPillar(t, device, "cat "+strings.Fields(kcrashes)[0])
	stack := strings.TrimSpace(strings.TrimSuffix(devInfo.GetLastRebootStack(), "..."))
	t.Expect(dump).To(ContainSubstring(stack),
		"lastRebootStack is not part of the dump saved in /persist/kcrashes")
	newlogLines := runInPillar(t, device,
		newlogCat+" | grep -c kernel_panic_stacks || true")
	evetest.Logger().Infof("kernel_panic_stacks lines in /persist/newlog: %s", newlogLines)
	t.Expect(strconv.Atoi(newlogLines)).To(BeNumerically(">", 0),
		"/persist/newlog holds no kernel_panic_stacks lines")
	t.Eventually(func() string {
		return runInPillar(t, device, "ls -A "+pillarPstoreDir)
	}, kernelPanicReportTimeout, 10*time.Second).Should(BeEmpty(),
		"the pstore records were not erased")
	evetest.Checkpoint("persist-checked")
}

// newlogCat writes every device log record kept in /persist/newlog to stdout.
// The records older than about five minutes are in gzipped chunks outside
// collect/, and the find form runs one zcat per file, which keeps -f safe on
// the plaintext chunks and avoids an argument list that overflows on a device
// with tens of thousands of chunks.
const newlogCat = `find /persist/newlog -name "dev.log.*" -exec zcat -f {} \; 2>/dev/null`

// runInPillar runs script in the pillar container, which sees the host's sysfs
// under /hostfs, and returns its trimmed stdout. script must not contain single
// quotes.
func runInPillar(t Gomega, device *evetest.EdgeDevice, script string) string {
	stdout, _, err := device.RunShellScript(
		"eve exec pillar sh -c '"+script+"'", probeSSHTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	return strings.TrimSpace(stdout)
}

// logMessage returns the content of a log message, for WithTransform.
func logMessage(m evetest.LogMsg) string {
	return m.Message
}
