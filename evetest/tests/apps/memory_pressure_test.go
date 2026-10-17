// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test of EVE's reactions to memory pressure in pillar's cgroup.

package apps_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const (
	// Logged by pillar's watcher each time it forces a GC on memory pressure.
	watcherPressureLog = "Received memory pressure event"
	// Logged by the watcher at start when it cannot arm a PSI trigger.
	watcherFallbackLog = "waking on memory.events instead"
	// Written by memory-monitor to its event log for a pressure event on pillar.
	monitorPressureEvent = "Pressure event for cgroup eve/services/pillar"
	monitorEventLog      = "/persist/memory-monitor/output/events.log"
	// Squeeze: memory.high at 90% of pillar's anonymous memory for 30 s. EVE
	// has no swap, so anon memory cannot be reclaimed and the limit sits below
	// the working set: every charge pillar makes is throttled (PSI memstall)
	// until the restore, whatever pillar allocates meanwhile.
	squeezePillar = `CG=/sys/fs/cgroup/eve/services/pillar
anon=$(awk '$1 == "anon" {print $2}' $CG/memory.stat)
echo $(( anon / 10 * 9 )) > $CG/memory.high
sleep 30
echo max > $CG/memory.high
echo "pressure=$(head -1 $CG/memory.pressure)"`
	restorePillar = `echo max > /sys/fs/cgroup/eve/services/pillar/memory.high`
)

// TestMemoryPressureEvents squeezes pillar's cgroup and verifies that both
// consumers of its memory pressure react: the watcher forces a Go GC (PSI
// trigger on memory.pressure, "some 150 ms in 1 s") and memory-monitor
// records a pressure event ("some 150 ms in 1 s").
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP; the device only needs to be managed.
//
// Device configuration
// --------------------
//   - eth0 as a DHCP mgmt+apps port. No application.
//
// Phases / assertions
// -------------------
//  1. Count memory-monitor's pillar pressure events and the watcher's
//     pressure log lines so far.
//  2. pillar-squeezed: set pillar's memory.high to 90% of its anonymous
//     memory (below its working set, so it is throttled) for 30 s, then
//     back to "max" (also on any failure, deferred).
//  3. watcher-gc-logged: a new watcher pressure log line reaches the
//     controller, and the watcher never logged that it fell back from PSI
//     to memory.events, so the GC came from the PSI trigger.
//  4. monitor-event-recorded: memory-monitor's event log has a new pressure
//     event for pillar.
//
// Test params
// -----------
//   - HYPERVISOR.
//
// Suite placement
// ---------------
//   - TestAppsSuite, after TestCgroupTree (same network model and device).
func TestMemoryPressureEvents(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	addMgmtPort(devConfig)
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")

	monitorBefore := monitorPressureEvents(t, device)
	watcherBefore := len(device.GetLogs(evetest.LogMsgMatch{MsgHasSubstring: watcherPressureLog}))

	defer func() {
		if _, _, err := device.RunShellScript(restorePillar, time.Minute, 0); err != nil {
			evetestT.Logf("restoring pillar's memory.high: %v", err)
		}
	}()
	f := deviceFacts(t, device, squeezePillar)
	evetest.Checkpoint("pillar-squeezed")
	evetestT.Logf("pillar memory.pressure after the squeeze: %s", f["pressure"])

	t.Eventually(func() int {
		return len(device.GetLogs(evetest.LogMsgMatch{MsgHasSubstring: watcherPressureLog}))
	}, 5*time.Minute, 10*time.Second).Should(BeNumerically(">", watcherBefore),
		"the watcher did not force a GC on pillar's memory pressure")
	t.Expect(device.GetLogs(evetest.LogMsgMatch{MsgHasSubstring: watcherFallbackLog})).To(BeEmpty(),
		"the watcher armed no PSI trigger and woke on memory.events")
	evetest.Checkpoint("watcher-gc-logged")

	t.Eventually(func() int {
		return monitorPressureEvents(t, device)
	}, 2*time.Minute, 10*time.Second).Should(BeNumerically(">", monitorBefore),
		"memory-monitor recorded no pressure event for pillar")
	evetest.Checkpoint("monitor-event-recorded")
}

// monitorPressureEvents counts memory-monitor's pressure events for pillar.
func monitorPressureEvents(t *WithT, device *evetest.EdgeDevice) int {
	out, stderr, err := device.RunShellScript(
		"grep -c '"+monitorPressureEvent+"' "+monitorEventLog+" 2>/dev/null || true", time.Minute, 0)
	t.Expect(err).ToNot(HaveOccurred(), stderr)
	n, _ := strconv.Atoi(strings.TrimSpace(out))
	return n
}
