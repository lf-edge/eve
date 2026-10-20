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

// joinSwtpmCgroup moves the swtpm of the domain id, which vtpm has started
// in its own service cgroup under /eve, to the helpers child of the domain's
// cgroup, /eve-user-apps/<task>/helpers, so that it counts against the
// domain's memory limit and runs on the domain's CPUs. root is the cgroup v2
// tree, normally cgroup.Root; without one the error is
// containerd.ErrNoCgroupTree. procRoot is the proc filesystem of the host
// pid namespace: vtpm runs in a pid namespace of its own, so the pid it
// records in its pid file is of no use here, and the swtpm is found by the
// pid file named on its command line.
func joinSwtpmCgroup(root, procRoot string, id uuid.UUID, task string) error {
	cgroup, hostDir, err := containerd.AppHelpersCgroup(root, task)
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
