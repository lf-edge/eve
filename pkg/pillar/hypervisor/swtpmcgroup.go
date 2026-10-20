// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// joinSwtpmCgroup moves the swtpm vtpm launched for domain id, whose task is
// named task, to the helpers cgroup of that task, creating it if needed: like
// the domain's shim, the swtpm is per-domain overhead, but vtpm starts it in
// its own service cgroup, /eve/services/vtpm, whose memory is part of the
// fixed budget EVE's services share under /eve. In the helpers cgroup it
// counts against the domain's memory limit instead, in the memory hierarchy
// only, keeping vtpm's cpuset. memoryRoot is the cgroup v1 memory hierarchy,
// normally containerd.HostMemoryCgroupRoot; without one the error is
// containerd.ErrNoMemoryHierarchy. procRoot is the proc filesystem of the host
// pid namespace, which pillar shares: vtpm does not, so the pid it records for
// the swtpm is not usable here, and the swtpm is found by the pid file it was
// told to write, which names the domain.
func joinSwtpmCgroup(memoryRoot, procRoot string, id uuid.UUID, task string) error {
	cgroup, hostDir, err := containerd.AppHelpersCgroup(memoryRoot, task)
	if err != nil {
		return err
	}
	pid, err := findSwtpm(procRoot, id)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(hostDir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("cannot move swtpm pid %d to the %s cgroup: %w", pid, cgroup, err)
	}
	return nil
}

// findSwtpm returns the pid, in procRoot's pid namespace, of the swtpm started
// for domain id: the swtpm whose command line names the domain's pid file.
func findSwtpm(procRoot string, id uuid.UUID) (int, error) {
	pidFileArg := "file=" + fmt.Sprintf(types.SwtpmPidPath, id)
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return 0, fmt.Errorf("cannot list %s: %w", procRoot, err)
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(procRoot, entry.Name(), "cmdline"))
		if err != nil {
			continue // gone, or not ours to read
		}
		args := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		if len(args) < 2 || filepath.Base(args[0]) != "swtpm" {
			continue
		}
		for _, arg := range args[1:] {
			if arg == pidFileArg {
				return pid, nil
			}
		}
	}
	return 0, fmt.Errorf("no swtpm process for domain %s", id)
}
