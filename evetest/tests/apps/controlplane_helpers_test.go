// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Observers of EVE's own control plane under load: the two log signatures
// EVE emits on its way to a watchdog reset -- an agent reporting that its
// main loop fell behind, and watchdog(8) reporting a service that has not
// touched its /run/<service>.touch file for longer than the configured
// limit -- and a sampler of the budget the eve cgroup confines EVE's
// services to, as the kernel sees it. The sampler reads EVE-specific cgroup
// paths, so it is diagnostic output only; assertions are built on the log
// watches, which observe the device through the controller like any other
// test.

package apps_test

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve/evetest"
)

// watchdogStallRE matches watchdog(8)'s report that a watched touch file has
// been stale for longer than the configured change interval ("file
// /run/newlogd.touch was not changed in 529 seconds (more than 500)"). One
// such line means the service stopped kicking the watchdog for the whole
// interval, and the device is one retry window away from a reset.
var watchdogStallRE = regexp.MustCompile(
	`file /run/([A-Za-z0-9_.-]+)\.touch was not changed in (\d+) seconds`)

// slowAgentRE matches pubsub's warning that an agent's main loop
// ("StillRunning(newlogd) took a long time (longer than the warning
// threshold): 103") or one of its handlers ("DeferredEvent handler in
// zedagent took a long time ...") took longer than the watchdog warning
// threshold to come back around; the trailing number is the delay in
// seconds. Pillar's lines reach the controller as raw JSON, so the agent is
// named by one of the two forms rather than by the message prefix.
var slowAgentRE = regexp.MustCompile(
	`(?:StillRunning\(([^)]+)\)|handler in (\S+)) took a long time ` +
		`\(longer than the (?:warning|error) threshold\): (\d+)`)

// watchWatchdogStalls subscribes to the device logs for watchdog(8) stall
// reports. Call it before applying the configuration that may stall EVE's
// services, so the buffered channel keeps every report, including the ones
// newlogd only manages to upload once it has recovered itself.
func watchWatchdogStalls(device *evetest.EdgeDevice) (
	stalls <-chan evetest.LogMsg, stop func()) {
	return device.WatchLogs(evetest.LogMsgMatch{MsgMatchesRegexp: *watchdogStallRE})
}

// watchSlowAgents subscribes to the device logs for pubsub's slow-agent
// warnings.
func watchSlowAgents(device *evetest.EdgeDevice) (
	warnings <-chan evetest.LogMsg, stop func()) {
	return device.WatchLogs(evetest.LogMsgMatch{MsgMatchesRegexp: *slowAgentRE})
}

// drainLogs returns every message currently buffered in a log watch channel
// without blocking.
func drainLogs(ch <-chan evetest.LogMsg) []evetest.LogMsg {
	var msgs []evetest.LogMsg
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				return msgs
			}
			msgs = append(msgs, msg)
		default:
			return msgs
		}
	}
}

// describeLogs renders log messages one per line for assertion output.
func describeLogs(msgs []evetest.LogMsg) string {
	lines := make([]string, 0, len(msgs))
	for _, msg := range msgs {
		lines = append(lines, fmt.Sprintf("%s %s: %s",
			msg.Timestamp.UTC().Format(time.RFC3339), msg.Source, msg.Message))
	}
	return strings.Join(lines, "\n")
}

// summarizeSlowAgents reduces slow-agent warnings to the worst delay reported
// per agent, as "agent=seconds" pairs sorted by agent name.
func summarizeSlowAgents(msgs []evetest.LogMsg) string {
	worst := make(map[string]int)
	for _, msg := range msgs {
		m := slowAgentRE.FindStringSubmatch(msg.Message)
		if m == nil {
			continue
		}
		agent := m[1]
		if agent == "" {
			agent = m[2]
		}
		secs, err := strconv.Atoi(m[3])
		if err != nil {
			continue
		}
		if secs > worst[agent] {
			worst[agent] = secs
		}
	}
	if len(worst) == 0 {
		return "none"
	}
	agents := make([]string, 0, len(worst))
	for agent := range worst {
		agents = append(agents, agent)
	}
	sort.Strings(agents)
	parts := make([]string, 0, len(agents))
	for _, agent := range agents {
		parts = append(parts, fmt.Sprintf("%s=%ds", agent, worst[agent]))
	}
	return strings.Join(parts, " ")
}

// controlPlaneBudgetScript prints the budgets EVE's services run within --
// the CPUs pillar is confined to and the memory limit of the eve cgroup --
// next to the device's own CPU count and memory. The count asks for all
// CPUs because the shell this runs in is itself confined to pillar's
// cpuset. Files missing on a cgroup v2 device print as empty fields.
const controlPlaneBudgetScript = `
printf 'cpus=%s pillar_cpuset=%s eve_mem_limit=%s mem_total_kb=%s\n' \
  "$(nproc --all)" \
  "$(cat /sys/fs/cgroup/cpuset/eve/services/pillar/cpuset.cpus 2>/dev/null)" \
  "$(cat /sys/fs/cgroup/memory/eve/memory.limit_in_bytes 2>/dev/null)" \
  "$(awk '/^MemTotal/{print $2}' /proc/meminfo)"
`

// controlPlaneSampleScript prints the eve cgroup's memory consumption against
// its limit and how much of it is kernel memory, how often the kernel refused
// a charge against the eve cgroup and against each of its budgeted children
// (failcnt; a child at its own limit leaves the parent's counter at zero),
// the system-wide count of file pages evicted while still in use (the
// signature of thrashing), the load average and the number of QEMU
// processes. Files missing on a cgroup v2 device print as empty fields.
const controlPlaneSampleScript = `
cg=/sys/fs/cgroup/memory/eve
rd() { cat "$1" 2>/dev/null; }
printf 'load=%s eve_mem=%s/%s kmem=%s failcnt=eve:%s,services:%s,pillar:%s,ctrd:%s refault_file=%s qemu=%s\n' \
  "$(cut -d' ' -f1-3 /proc/loadavg)" \
  "$(rd $cg/memory.usage_in_bytes)" "$(rd $cg/memory.limit_in_bytes)" \
  "$(rd $cg/memory.kmem.usage_in_bytes)" \
  "$(rd $cg/memory.failcnt)" "$(rd $cg/services/memory.failcnt)" \
  "$(rd $cg/services/pillar/memory.failcnt)" "$(rd $cg/containerd/memory.failcnt)" \
  "$(awk '/^workingset_refault_file/{print $2}' /proc/vmstat)" \
  "$(pgrep -c qemu-system)"
`

// logControlPlaneBudget logs the CPU and memory budgets EVE's services run
// within on this device.
func logControlPlaneBudget(device *evetest.EdgeDevice) {
	log := evetest.Logger()
	stdout, _, err := device.RunShellScript(controlPlaneBudgetScript,
		20*time.Second, 0)
	if err != nil {
		log.Warnf("control plane budget could not be read: %v", err)
		return
	}
	log.Infof("control plane budget: %s", strings.TrimSpace(stdout))
}

// startControlPlaneSampler logs a control-plane sample every interval until
// the returned stop function is called (safe to call more than once). A
// sample that cannot be taken is logged as such and is itself a symptom: on
// a device whose services are starved, the SSH session a sample needs is
// among the first casualties.
func startControlPlaneSampler(device *evetest.EdgeDevice,
	interval time.Duration) (stop func()) {
	log := evetest.Logger()
	done := make(chan struct{})
	finished := make(chan struct{})
	sample := func() {
		stdout, _, err := device.RunShellScript(controlPlaneSampleScript,
			20*time.Second, 0)
		if err != nil {
			log.Warnf("control plane sample failed: %v", err)
			return
		}
		log.Infof("control plane: %s", strings.TrimSpace(stdout))
	}
	go func() {
		defer close(finished)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		sample()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				sample()
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			<-finished
		})
	}
}
