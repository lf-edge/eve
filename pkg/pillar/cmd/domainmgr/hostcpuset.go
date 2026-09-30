// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/containerd/cgroups"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// The host processes -- init, udevd, the getty, the system containerd and every
// containerd shim, of the services and of the workloads alike -- live in the
// root cpuset. That spans every CPU and cannot be narrowed: the kernel refuses
// writes to it, and every other cpuset, the workloads' included, may only use
// CPUs its parent has. Left there, the host processes run on CPUs dedicated to
// workloads.
//
// So they are moved into a cpuset of their own, beside /eve and /eve-user-apps,
// holding exactly the housekeeping CPUs and following them as workloads are
// placed and released. Processes they fork inherit it, and containerd still
// moves each workload's QEMU into the workload's own cpuset. Kernel threads are
// left where they are.

// hostCgroupRoot is the cgroup v1 hierarchy as pillar can write it: its own
// /sys/fs/cgroup is mounted read-only, the host's under /hostfs is not.
const hostCgroupRoot = "/hostfs/sys/fs/cgroup"

// hostCpusetName names the host processes' cpuset after the pool it holds.
const hostCpusetName = "housekeeping"

// pfKthread is PF_KTHREAD from include/linux/sched.h.
const pfKthread = 0x00200000

// hostCpuset keeps the host processes on the housekeeping CPUs. A nil
// *hostCpuset does nothing, which is what a node where EVE does not pin
// workloads has. Its caller serializes the updates.
type hostCpuset struct {
	hierarchy cgroups.Hierarchy // the cpuset hierarchy alone
	proc      string            // procfs
}

func newHostCpuset(cgroupRoot, proc string) *hostCpuset {
	cpuset := cgroups.NewCpuset(cgroupRoot)
	return &hostCpuset{
		hierarchy: func() ([]cgroups.Subsystem, error) {
			return []cgroups.Subsystem{cpuset}, nil
		},
		proc: proc,
	}
}

// update brings the host processes onto cpus, logging the outcome.
func (h *hostCpuset) update(cpus []uint32) {
	moved, err := h.apply(cpus)
	if err != nil {
		log.Errorf("host cpuset: %v", err)
	} else if moved > 0 {
		log.Noticef("host cpuset: moved %d host processes onto the housekeeping CPUs", moved)
	}
}

// apply sets the cpuset to cpus and moves into it every user-space process
// still in the root cpuset, returning how many it moved. The CPUs are written
// before any process is moved, so none runs, even briefly, on a CPU that has
// just been dedicated.
func (h *hostCpuset) apply(cpus []uint32) (int, error) {
	if h == nil {
		return 0, nil
	}
	if len(cpus) == 0 {
		return 0, errors.New("no housekeeping CPUs: an empty cpuset cannot hold a process")
	}
	// A new cpuset takes the root's memory nodes, without which cgroup v1
	// admits no process.
	housekeeping, err := cgroups.New(h.hierarchy, cgroups.StaticPath("/"+hostCpusetName),
		&specs.LinuxResources{CPU: &specs.LinuxCPU{Cpus: cpuList(cpus)}})
	if err != nil {
		return 0, err
	}
	root, err := cgroups.Load(h.hierarchy, cgroups.RootPath)
	if err != nil {
		return 0, err
	}
	procs, err := root.Processes(cgroups.Cpuset, false)
	if err != nil {
		return 0, err
	}
	moved := 0
	for _, p := range procs {
		if !h.isUserSpace(p.Pid) {
			continue
		}
		switch err := housekeeping.Add(cgroups.Process{Pid: p.Pid}); {
		case err == nil:
			moved++
		case errors.Is(err, syscall.ESRCH):
			// It exited after the listing.
		default:
			log.Warnf("host cpuset: cannot move pid %d: %v", p.Pid, err)
		}
	}
	return moved, nil
}

// isUserSpace reports whether pid is a live process that is not a kernel thread.
func (h *hostCpuset) isUserSpace(pid int) bool {
	stat, err := os.ReadFile(filepath.Join(h.proc, strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	// The command name may itself contain spaces and parentheses; the fields
	// after it start at the last ')': state, ppid, pgrp, session, tty_nr,
	// tpgid, flags.
	s := string(stat)
	fields := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	if len(fields) < 7 {
		return false
	}
	flags, err := strconv.ParseUint(fields[6], 10, 64)
	return err == nil && flags&pfKthread == 0
}
