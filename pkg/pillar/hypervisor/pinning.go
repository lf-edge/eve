// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// setThreadAffinity pins a single OS thread (tid) to the given CPU set.
func setThreadAffinity(tid int, cpus []uint32) error {
	var set unix.CPUSet
	set.Zero()
	for _, c := range cpus {
		set.Set(int(c))
	}
	return unix.SchedSetaffinity(tid, &set)
}

func qemuPid(domainName string) (int, error) {
	data, err := os.ReadFile(kvmStateDir + domainName + "/pid")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// pinDomainThreads pins the domain's guest vCPU threads 1:1 (guest vCPU i ->
// ordered[i]) and, when emulator is non-empty (io_placement=housekeeping),
// pins every other QEMU thread to the emulator set.
//
// It is called from Start() at the one correct point in the containerd task
// lifecycle: after task Start has launched QEMU (paused via -S, so the vCPU
// threads exist and QMP is up) and BEFORE the QMP cont — i.e. after containerd
// has already written the cgroup cpuset, so our per-thread affinity is applied
// last and is not reset by the cpuset. ordered/emulator come straight from the
// domain's DomainStatus (bound into the Task via KvmContext.Task), so there is
// no ephemeral hand-off state and this is idempotent/safe to re-run on a boot
// retry.
//
// Every failure except a vanished thread is returned, so the caller keeps the
// guest paused instead of releasing it with a placement it does not have.
func (ctx KvmContext) pinDomainThreads(domainName, qmpFile string, ordered, emulator []uint32) error {
	if len(ordered) == 0 {
		return nil // not a topology-pinned domain
	}
	tids, err := QmpGetVcpuThreadIDs(qmpFile)
	if err != nil {
		return fmt.Errorf("query-cpus-fast: %w", err)
	}
	if len(tids) != len(ordered) {
		return fmt.Errorf("vcpu count mismatch: qemu=%d ordered=%d", len(tids), len(ordered))
	}
	vcpuTid := map[int]bool{}
	for i, tid := range tids {
		if tid <= 0 {
			return fmt.Errorf("refusing to pin vcpu %d: invalid thread-id %d", i, tid)
		}
		vcpuTid[tid] = true
		if err := setThreadAffinity(tid, []uint32{ordered[i]}); err != nil {
			return fmt.Errorf("pin vcpu %d (tid %d) -> cpu %d: %w", i, tid, ordered[i], err)
		}
	}
	// Log the full guest-vCPU -> thread -> host-CPU mapping, not just the CPU
	// list. QEMU does not name its vCPU threads unless it is started with
	// debug-threads=on, and the thread group also contains vhost_task helpers
	// that look no different from the outside, so this mapping cannot be
	// reconstructed from /proc afterwards -- QMP query-cpus-fast, which we just
	// called, is the only authoritative source of it. Recording it here is what
	// makes a pin verifiable after the fact, by a test or by a support engineer
	// reading /proc/<tid>/status.
	var mapping strings.Builder
	for i, tid := range tids {
		if i > 0 {
			mapping.WriteString(" ")
		}
		fmt.Fprintf(&mapping, "vcpu%d=tid%d@cpu%d", i, tid, ordered[i])
	}
	logrus.Infof("CPU pinning: domain %s pinned %d vCPUs 1:1 to host CPUs %v [%s]",
		domainName, len(tids), ordered, mapping.String())

	if len(emulator) == 0 {
		return nil // io_placement=dedicated: leave non-vCPU threads in the cgroup cpuset
	}
	pid, err := qemuPid(domainName)
	if err != nil {
		return fmt.Errorf("qemu pid: %w", err)
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return fmt.Errorf("read qemu task dir: %w", err)
	}
	var pinned, failed int
	var firstErr error
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil || vcpuTid[tid] {
			continue
		}
		if err := setThreadAffinity(tid, emulator); err != nil {
			// ESRCH is expected and harmless: QEMU has short-lived helper
			// threads, and one of them can exit between reading /proc and the
			// syscall. Every other errno is systemic rather than per-thread --
			// EINVAL means the mask holds no CPU inside the task's cgroup
			// cpuset, so no thread is pinned at all -- and must fail the pin
			// instead of leaving the emulator on the hot cores while the guest
			// is released and the placement reported as achieved.
			if errors.Is(err, unix.ESRCH) {
				continue
			}
			failed++
			if firstErr == nil {
				firstErr = fmt.Errorf("pin emulator thread %d -> cpus %v: %w", tid, emulator, err)
			}
			continue
		}
		pinned++
	}
	if firstErr != nil {
		return fmt.Errorf("%d of %d non-vCPU threads not pinned to %v: %w",
			failed, failed+pinned, emulator, firstErr)
	}
	logrus.Infof("CPU pinning: domain %s pinned %d emulator/IO threads to host CPUs %v",
		domainName, pinned, emulator)
	return nil
}
