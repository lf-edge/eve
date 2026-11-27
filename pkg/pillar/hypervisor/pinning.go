// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup"
	procutils "github.com/lf-edge/eve/pkg/pillar/utils/proc"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// kvmNXRecoveryComm is the comm (truncated to 15 bytes) of KVM's NX huge-page
// recovery thread on x86. Since Linux 6.13 (and in 6.12.y) it is a thread of
// the QEMU process, created by the first vCPU that enters KVM_RUN, i.e. after
// cont, in that vCPU's cgroup.
const kvmNXRecoveryComm = "kvm-nx-lpage-re"

// A domain's QEMU threads live in a threaded subtree of the task child of its
// cgroup, where runc runs the domain, as libvirt arranges them:
//
//	eve-user-apps/<domain>/  every CPU the domain uses; its memory limit
//	├── task/                QEMU, runc's cgroup: the task's memory and IO limits
//	│   ├── emulator/        every thread but the vCPUs': main loop, iothreads, vhost, IO workers
//	│   ├── vcpu0/           vCPU 0's thread
//	│   └── vcpuN/
//	└── helpers/             the domain's containerd shim and swtpm
//
// The groups cannot hang off the domain's cgroup itself, whose children task
// and helpers hold processes: the kernel turns no child of such a cgroup
// threaded.
//
// A thread starts in the group of the thread that created it, so one QEMU or
// the kernel starts later -- an io_uring or vhost worker -- is confined by the
// kernel, not by a pass that would have to find it. A group whose CPUs are the
// domain's leaves cpuset.cpus empty and follows the domain: both groups of an
// unpinned domain, and the emulator group of a pinned one whose IO stays on
// its own CPUs. The task child has no CPUs of its own either. The helpers
// child gets the emulator group's: the shim and the swtpm serve the domain as
// its emulator threads do, and under io_placement=housekeeping they too stay
// off the vCPUs' cores.
const (
	emulatorGroup   = "emulator"
	vcpuGroupPrefix = "vcpu"
)

// Vars so tests can stand in for QEMU, /proc and sysfs.
var (
	procDir          = "/proc"
	kvmNXHugePages   = "/sys/module/kvm/parameters/nx_huge_pages"
	vcpuThreadIDs    = QmpGetVcpuThreadIDs
	domainPid        = qemuPid
	addThread        = cgroup.AddThread
	nxRecoveryWait   = 30 * time.Second
	nxRecoveryPollAt = 10 * time.Millisecond
)

func qemuPid(domainName string) (int, error) {
	return procutils.GetPidFromFile(filepath.Join(kvmStateDir, domainName, "pid"))
}

// DomainCgroup is the cgroup of the domain named domainName, which carries the
// domain's CPUs.
func DomainCgroup(domainName string) string {
	return path.Join(containerd.GetServicesNamespace(), domainName)
}

// TaskCgroup is the child of the domain's cgroup that runc runs the domain
// named domainName in: QEMU's cgroup, and the root of its thread groups.
func TaskCgroup(domainName string) string {
	return path.Join(DomainCgroup(domainName), containerd.AppTaskCgroupName)
}

// helpersCgroup is the child of the domain's cgroup that its helpers, its
// containerd shim and its swtpm, run in.
func helpersCgroup(domainName string) string {
	return path.Join(DomainCgroup(domainName), containerd.AppHelpersCgroupName)
}

// setHelpersCPUs puts the domain's helpers on cpus, the IO CPUs of its emulator
// threads. A domain without a helpers child, whose shim and swtpm stayed where
// their services started them, has nothing to confine.
func setHelpersCPUs(domainName string, cpus []uint32) error {
	helpers := helpersCgroup(domainName)
	if _, err := os.Stat(cgroup.Path(helpers, "")); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := cgroup.WriteCPUs(helpers, cpus); err != nil {
		return fmt.Errorf("CPUs of %s: %w", helpers, err)
	}
	return nil
}

// arrangeDomainThreads puts the domain's threads in its thread groups: vCPU i's
// thread in vcpu<i>/, every other thread in emulator/. For a domain holding CPUs
// vcpu<i>/ holds a.CPUs[i] alone and emulator/, like the domain's helpers
// child, a.IOCPUs under io_placement=housekeeping; once every thread is in its
// group the domain's group gets all its CPUs (a.DomainCPUs()). It started where
// its non-vCPU threads run (DomainStatus.StartCPUs), so what QEMU set up while
// starting names no other CPU.
//
// It runs in Start, after QEMU is up and paused (-S) and before cont, and
// returns every failure but a thread that exited: the caller keeps the guest
// paused rather than release it with a placement it does not have. Running it
// again on a boot retry finds the groups made and moves the threads again.
func arrangeDomainThreads(domainName, qmpFile string, a types.CPUAssignment) error {
	tids, err := vcpuThreadIDs(qmpFile)
	if err != nil {
		return fmt.Errorf("query-cpus-fast: %w", err)
	}
	if a.Holds() && len(tids) != len(a.CPUs) {
		return fmt.Errorf("vcpu count mismatch: qemu=%d assigned=%d", len(tids), len(a.CPUs))
	}
	pid, err := domainPid(domainName)
	if err != nil {
		return fmt.Errorf("qemu pid: %w", err)
	}
	domain := DomainCgroup(domainName)
	task := TaskCgroup(domainName)
	emulator := path.Join(task, emulatorGroup)
	groups := []string{emulator}
	vcpuGroup := make(map[int]string, len(tids))
	for i, tid := range tids {
		vcpuGroup[tid] = path.Join(task, fmt.Sprintf("%s%d", vcpuGroupPrefix, i))
		groups = append(groups, vcpuGroup[tid])
	}
	for _, g := range groups {
		if err := cgroup.MakeThreaded(g); err != nil {
			return fmt.Errorf("thread group %s: %w", g, err)
		}
	}
	if err := cgroup.EnableControllers(task, "cpuset"); err != nil {
		return fmt.Errorf("cpuset for the thread groups of %s: %w", task, err)
	}
	// Each group gets its CPUs before any thread joins it, so none runs, even
	// briefly, where it does not belong.
	if len(a.IOCPUs) > 0 {
		if err := cgroup.WriteCPUs(emulator, a.IOCPUs); err != nil {
			return fmt.Errorf("CPUs of %s: %w", emulator, err)
		}
		if err := setHelpersCPUs(domainName, a.IOCPUs); err != nil {
			return err
		}
	}
	var mapping []string
	if a.Holds() {
		for i, tid := range tids {
			if err := cgroup.WriteCPUs(vcpuGroup[tid], []uint32{a.CPUs[i]}); err != nil {
				return fmt.Errorf("CPUs of %s: %w", vcpuGroup[tid], err)
			}
			mapping = append(mapping, fmt.Sprintf("vcpu%d=tid%d@cpu%d", i, tid, a.CPUs[i]))
		}
	}
	threads, err := os.ReadDir(filepath.Join(procDir, strconv.Itoa(pid), "task"))
	if err != nil {
		return fmt.Errorf("threads of qemu %d: %w", pid, err)
	}
	moved := 0
	for _, t := range threads {
		tid, err := strconv.Atoi(t.Name())
		if err != nil {
			continue
		}
		group, isVCPU := vcpuGroup[tid]
		if !isVCPU {
			group = emulator
		}
		switch err := addThread(group, tid); {
		case err == nil:
			moved++
		case errors.Is(err, unix.ESRCH):
			// A helper thread that exited after the listing.
		default:
			return fmt.Errorf("thread %d into %s: %w", tid, group, err)
		}
	}
	if a.Holds() {
		if err := cgroup.WriteCPUs(domain, a.DomainCPUs()); err != nil {
			return fmt.Errorf("CPUs of %s: %w", domain, err)
		}
		// The guest-vCPU -> thread -> host-CPU mapping is logged because
		// nothing else records it: QEMU does not name its vCPU threads unless
		// started with debug-threads=on, and query-cpus-fast is the only
		// source of it.
		logrus.Infof("CPU pinning: domain %s pinned %d vCPUs 1:1 to host CPUs %v [%s], "+
			"its other threads on %v", domainName, len(tids), a.CPUs,
			strings.Join(mapping, " "), a.EmulatorCPUs())
	}
	logrus.Infof("CPU pinning: domain %s: %d threads in %d thread groups", domainName,
		moved, len(groups))
	return nil
}

// SetIOCPUs moves a running domain's non-vCPU threads, and its helpers with
// them, onto a.IOCPUs, the housekeeping set they follow under
// io_placement=housekeeping. The domain's group is written first: a group runs
// on its own CPUs within its parent's, so a shrink reaches every thread at once
// and a growth only once the domain has the CPUs.
func SetIOCPUs(domainName string, a types.CPUAssignment) error {
	domain := DomainCgroup(domainName)
	if err := cgroup.WriteCPUs(domain, a.DomainCPUs()); err != nil {
		return fmt.Errorf("CPUs of %s: %w", domain, err)
	}
	emulator := path.Join(TaskCgroup(domainName), emulatorGroup)
	if err := cgroup.WriteCPUs(emulator, a.IOCPUs); err != nil {
		return fmt.Errorf("CPUs of %s: %w", emulator, err)
	}
	return setHelpersCPUs(domainName, a.IOCPUs)
}

// placeLateThreads moves the QEMU threads that only appear once the guest runs
// into emulator/: KVM's NX huge-page recovery thread, which the first vCPU
// creates in its own group, and so on its CPU: a kernel-isolated one for an
// isolated workload. It runs after cont and waits for the thread in the
// background, so a failure is logged rather than returned.
func placeLateThreads(domainName string) {
	if !nxRecoveryThreadExpected() {
		return
	}
	pid, err := domainPid(domainName)
	if err != nil {
		logrus.Warnf("CPU pinning: domain %s: qemu pid: %v", domainName, err)
		return
	}
	go placeNXRecoveryThread(domainName, pid, path.Join(TaskCgroup(domainName), emulatorGroup))
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
// created the thread, then moves it into group.
func placeNXRecoveryThread(domainName string, pid int, group string) {
	deadline := time.Now().Add(nxRecoveryWait)
	for {
		if tid := threadByComm(pid, kvmNXRecoveryComm); tid > 0 {
			if err := addThread(group, tid); err != nil {
				logrus.Warnf("CPU pinning: domain %s: KVM NX recovery thread %d into %s: %v",
					domainName, tid, group, err)
				return
			}
			logrus.Infof("CPU pinning: domain %s: KVM NX recovery thread %d in %s",
				domainName, tid, group)
			return
		}
		if time.Now().After(deadline) {
			logrus.Warnf("CPU pinning: domain %s: no KVM NX recovery thread within %v; "+
				"it stays in the group of the vCPU that created it", domainName, nxRecoveryWait)
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
