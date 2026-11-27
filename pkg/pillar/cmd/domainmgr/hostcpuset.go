// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup"
)

// EVE's services run in /eve/services, on the CPUs reserved for EVE, its system
// containerd with the shims of EVE's own containers in /eve/containerd, and
// each workload, with its own shim and swtpm, in its own group under
// /eve-user-apps. The host processes left in the root cgroup -- init, udevd,
// the getty -- may use every CPU: the root's cpuset spans them all and cannot
// be narrowed. Left there, they run on CPUs dedicated to workloads.
//
// So they are moved into a group of their own, beside /eve and /eve-user-apps,
// holding exactly the housekeeping CPUs and following them as workloads are
// placed and released. Processes they fork inherit it. Kernel threads are left
// where they are. The user containerd, which runs under /eve-user-apps beside
// the workloads but is none of them, follows the housekeeping CPUs in its own
// group the same way.

// hostCpusetGroup names the host processes' group after the pool it holds.
const hostCpusetGroup = "housekeeping"

// pfKthread is PF_KTHREAD from include/linux/sched.h.
const pfKthread = 0x00200000

// hostCpuset keeps the host processes on the housekeeping CPUs. A nil
// *hostCpuset does nothing, which is what a node where EVE does not pin
// workloads has. Its caller serializes the updates.
type hostCpuset struct {
	proc string // procfs
}

// newHostCpuset returns the host cpuset, or an error when the root cgroup does
// not hand the cpuset controller to its children: a group of its own would then
// not confine the host processes.
func newHostCpuset(proc string) (*hostCpuset, error) {
	ctrls, err := cgroup.SubtreeControl("")
	if err != nil {
		return nil, err
	}
	if !slices.Contains(ctrls, "cpuset") {
		return nil, errors.New("the root cgroup does not enable the cpuset controller for its children")
	}
	return &hostCpuset{proc: proc}, nil
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

// apply sets the CPUs of the group, and of the user containerd's, to cpus and
// moves into the group every user-space process still in the root cgroup,
// returning how many it moved. The CPUs are written before any process is
// moved, so none runs, even briefly, on a CPU that has just been dedicated. A
// failure to confine the user containerd is returned once the host processes
// are moved.
func (h *hostCpuset) apply(cpus []uint32) (int, error) {
	if h == nil {
		return 0, nil
	}
	if len(cpus) == 0 {
		return 0, errors.New("no housekeeping CPUs: an empty cpuset cannot hold a process")
	}
	if err := os.MkdirAll(cgroup.Path(hostCpusetGroup, ""), 0755); err != nil {
		return 0, err
	}
	if err := cgroup.WriteCPUs(hostCpusetGroup, cpus); err != nil {
		return 0, err
	}
	ctrdErr := confineUserContainerd(cpus)
	pids, err := cgroup.Processes("")
	if err != nil {
		return 0, errors.Join(ctrdErr, err)
	}
	moved := 0
	for _, pid := range pids {
		if !h.isUserSpace(pid) {
			continue
		}
		switch err := cgroup.AddProcess(hostCpusetGroup, pid); {
		case err == nil:
			moved++
		case errors.Is(err, syscall.ESRCH):
			// It exited after the listing.
		default:
			log.Warnf("host cpuset: cannot move pid %d: %v", pid, err)
		}
	}
	return moved, ctrdErr
}

// confineUserContainerd puts the user containerd's group on cpus. The group is
// made if the daemon has not joined it yet -- domainmgr's first update comes
// before it starts the daemon -- so that the daemon finds the CPUs there.
func confineUserContainerd(cpus []uint32) error {
	group := containerd.UserContainerdCgroup()
	if err := os.MkdirAll(cgroup.Path(group, ""), 0755); err != nil {
		return fmt.Errorf("the user containerd's group: %w", err)
	}
	if err := cgroup.WriteCPUs(group, cpus); err != nil {
		return fmt.Errorf("the user containerd's group: %w", err)
	}
	return nil
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
