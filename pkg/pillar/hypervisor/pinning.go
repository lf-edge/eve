// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	procutils "github.com/lf-edge/eve/pkg/pillar/utils/proc"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// kvmNXRecoveryComm is the comm (truncated to 15 bytes) of KVM's NX huge-page
// recovery thread on x86. Since Linux 6.13 (and in 6.12.y) it is a thread of
// the QEMU process, created by the first vCPU that enters KVM_RUN, i.e. after
// cont, with that vCPU's one-CPU affinity.
const kvmNXRecoveryComm = "kvm-nx-lpage-re"

// Vars so tests can point them at a fake /proc and sysfs.
var (
	procDir          = "/proc"
	kvmNXHugePages   = "/sys/module/kvm/parameters/nx_huge_pages"
	setAffinity      = setThreadAffinity
	nxRecoveryWait   = time.Second
	nxRecoveryPollAt = 10 * time.Millisecond
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
	return procutils.GetPidFromFile(filepath.Join(kvmStateDir, domainName, "pid"))
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
		return nil // not a pinned domain
	}
	tids, err := QmpGetVcpuThreadIDs(qmpFile)
	if err != nil {
		return fmt.Errorf("query-cpus-fast: %w", err)
	}
	if len(tids) != len(ordered) {
		return fmt.Errorf("vcpu count mismatch: qemu=%d ordered=%d", len(tids), len(ordered))
	}
	// The guest-vCPU -> thread -> host-CPU mapping is logged because nothing
	// else records it: QEMU does not name its vCPU threads unless started with
	// debug-threads=on, and query-cpus-fast is the only source of it.
	vcpuTid := map[int]bool{}
	var mapping []string
	for i, tid := range tids {
		if tid <= 0 {
			return fmt.Errorf("refusing to pin vcpu %d: invalid thread-id %d", i, tid)
		}
		vcpuTid[tid] = true
		if err := setAffinity(tid, []uint32{ordered[i]}); err != nil {
			return fmt.Errorf("pin vcpu %d (tid %d) -> cpu %d: %w", i, tid, ordered[i], err)
		}
		mapping = append(mapping, fmt.Sprintf("vcpu%d=tid%d@cpu%d", i, tid, ordered[i]))
	}
	logrus.Infof("CPU pinning: domain %s pinned %d vCPUs 1:1 to host CPUs %v [%s]",
		domainName, len(tids), ordered, strings.Join(mapping, " "))

	if len(emulator) == 0 {
		return nil // io_placement=dedicated: leave non-vCPU threads in the cgroup cpuset
	}
	pid, err := qemuPid(domainName)
	if err != nil {
		return fmt.Errorf("qemu pid: %w", err)
	}
	entries, err := os.ReadDir(filepath.Join(procDir, strconv.Itoa(pid), "task"))
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
		if err := setAffinity(tid, emulator); err != nil {
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

// placeLateThreads gives the QEMU threads that only appear once the guest runs
// the CPUs of the other non-vCPU threads: the emulator set under
// io_placement=housekeeping, otherwise the workload's own CPUs. Today that is
// KVM's NX huge-page recovery thread, which would otherwise stay on the CPU of
// whichever vCPU ran first: a kernel-isolated one for an isolated workload.
// It runs after cont, so a failure is logged rather than returned.
func (ctx KvmContext) placeLateThreads(domainName string, ordered, emulator []uint32) {
	cpus := lateThreadCPUs(ordered, emulator)
	if len(cpus) == 0 || !nxRecoveryThreadExpected() {
		return
	}
	pid, err := qemuPid(domainName)
	if err != nil {
		logrus.Warnf("CPU pinning: domain %s: qemu pid: %v", domainName, err)
		return
	}
	placeNXRecoveryThread(domainName, pid, cpus)
}

// lateThreadCPUs is where non-vCPU threads of a pinned workload belong; nil
// for a workload with no CPUs of its own.
func lateThreadCPUs(ordered, emulator []uint32) []uint32 {
	if len(ordered) == 0 {
		return nil
	}
	if len(emulator) > 0 {
		return emulator
	}
	return ordered
}

// nxRecoveryThreadExpected: x86 KVM starts the thread unless the mitigation is
// hard-disabled (nx_huge_pages=never); when merely off it starts and sleeps.
func nxRecoveryThreadExpected() bool {
	if runtime.GOARCH != "amd64" {
		return false
	}
	val, err := os.ReadFile(kvmNXHugePages)
	return err == nil && strings.TrimSpace(string(val)) != "never"
}

// placeNXRecoveryThread waits up to nxRecoveryWait for the first vCPU to have
// created the thread, then sets its affinity.
func placeNXRecoveryThread(domainName string, pid int, cpus []uint32) {
	deadline := time.Now().Add(nxRecoveryWait)
	for {
		if tid := threadByComm(pid, kvmNXRecoveryComm); tid > 0 {
			if err := setAffinity(tid, cpus); err != nil {
				logrus.Warnf("CPU pinning: domain %s: KVM NX recovery thread %d -> host CPUs %v: %v",
					domainName, tid, cpus, err)
				return
			}
			logrus.Infof("CPU pinning: domain %s pinned KVM NX recovery thread %d to host CPUs %v",
				domainName, tid, cpus)
			return
		}
		if time.Now().After(deadline) {
			logrus.Warnf("CPU pinning: domain %s: no KVM NX recovery thread within %v; it keeps the CPU of the vCPU that created it",
				domainName, nxRecoveryWait)
			return
		}
		time.Sleep(nxRecoveryPollAt)
	}
}

// threadByComm returns the tid of the process's first thread with that comm, or 0.
func threadByComm(pid int, comm string) int {
	dir := filepath.Join(procDir, strconv.Itoa(pid), "task")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		name, err := os.ReadFile(filepath.Join(dir, e.Name(), "comm"))
		if err != nil || strings.TrimSpace(string(name)) != comm {
			continue
		}
		if tid, err := strconv.Atoi(e.Name()); err == nil {
			return tid
		}
	}
	return 0
}
