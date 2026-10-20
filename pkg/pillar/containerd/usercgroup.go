// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ctrdConfiguredCgroup is the cgroup both containerd daemons join when they
// start: [cgroup] path in /etc/containerd/*.toml.
const ctrdConfiguredCgroup = "/eve/containerd"

// userContainerdCgroupName names the cgroup the user containerd daemon is
// charged to.
//
// That daemon is pillar's content store: it runs no task, but every image an
// app instance is made of is written into it and unpacked through it, and the
// pages it touches doing so are charged to the cgroup it runs in,
// /eve/containerd, part of the fixed memory budget EVE's services share under
// /eve. Most of them are page cache, which stays charged there until reclaim
// is forced, pressing on the services whose budget it is. Charged beside the
// domains instead, what the daemon caches for the apps costs the apps' side,
// and the daemon runs on the applications' CPUs rather than on the few EVE's
// services share.
const userContainerdCgroupName = "containerd"

// userContainerdCgroupTimeout bounds the wait for the daemon to join its
// configured cgroup, which it does while it initializes.
const userContainerdCgroupTimeout = 30 * time.Second

const cgroupPollInterval = 20 * time.Millisecond

// joinUserContainerdCgroup moves the user containerd daemon, pid, to the
// containerd cgroup under /eve-user-apps in the cgroup v2 tree root, normally
// cgroup.Root; without one the error is ErrNoCgroupTree. The daemon joins
// ctrdConfiguredCgroup on its own as it starts, which would undo an earlier
// move, so this waits, up to timeout, until <procRoot>/<pid>/cgroup shows it
// there.
func joinUserContainerdCgroup(root, procRoot string, pid int, timeout time.Duration) error {
	_, hostDir, err := UserAppsCgroup(root, userContainerdCgroupName)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		cgroup, err := cgroupOf(procRoot, pid)
		if err != nil {
			return err
		}
		if cgroup == ctrdConfiguredCgroup {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("user containerd pid %d is in the cgroup %s, not in %s", pid, cgroup, ctrdConfiguredCgroup)
		}
		time.Sleep(cgroupPollInterval)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("cannot move user containerd pid %d to the %s cgroup: %w", pid, userContainerdCgroupName, err)
	}
	return nil
}

// cgroupOf returns the cgroup of pid in the cgroup v2 tree, from
// <procRoot>/<pid>/cgroup, whose unified entry reads 0::<cgroup>.
func cgroupOf(procRoot string, pid int) (string, error) {
	path := filepath.Join(procRoot, strconv.Itoa(pid), "cgroup")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if cgroup, ok := strings.CutPrefix(line, "0::"); ok {
			return cgroup, nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 entry in %s", path)
}
