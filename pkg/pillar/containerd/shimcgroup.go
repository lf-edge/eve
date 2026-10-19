// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/types/runc/options"
	"github.com/sirupsen/logrus"
)

// HostMemoryCgroupRoot is the cgroup v1 memory hierarchy. Pillar's own
// cgroupfs mount is read-only, so the hierarchy is reached through hostfs.
const HostMemoryCgroupRoot = "/hostfs/sys/fs/cgroup/memory"

// ErrNoMemoryHierarchy is returned by the cgroup helpers when there is no
// cgroup v1 memory hierarchy to create the cgroup in, as under cgroup v2.
var ErrNoMemoryHierarchy = errors.New("no cgroup v1 memory hierarchy")

// appHelpersCgroupName names the child of a domain's cgroup that holds the
// helper processes EVE runs for the domain: its containerd shim and its swtpm.
//
// They are per-domain overhead, like the domain's qemu, but EVE's services,
// containerd and vtpm, start them in their own cgroups, whose memory limits
// are fixed and shared under /eve: fifty domains bring fifty shims and swtpms,
// enough to exhaust that budget and stall the services. Charged to a child of
// the domain's own cgroup instead, they count against the domain's memory
// limit, which runc sets on the parent when the task starts and which the
// admission check already pays for. The child exists in the memory hierarchy
// only, so the helpers keep the cpuset and cpu group of the service that
// started them.
//
// runc owns the domain's cgroup and destroys it with the task, children
// included, which fails while a helper still lives there; evictAppHelpers
// moves them out right before the task is deleted.
const appHelpersCgroupName = "helpers"

// UserAppsMemoryCgroup creates the cgroup /eve-user-apps/<name>, where the
// per-domain helper processes of EVE's services are charged beside the domains
// they belong to rather than to the service's budget under /eve. The cgroup
// exists in the memory hierarchy only, so that a process joining it keeps the
// cpuset of the service that started it. memoryRoot is the cgroup v1 memory
// hierarchy, normally HostMemoryCgroupRoot. It returns the cgroup's path in the
// hierarchy and its directory on the host, or ErrNoMemoryHierarchy when
// memoryRoot holds no such hierarchy.
func UserAppsMemoryCgroup(memoryRoot, name string) (string, string, error) {
	if _, err := os.Stat(filepath.Join(memoryRoot, "memory.usage_in_bytes")); err != nil {
		return "", "", ErrNoMemoryHierarchy
	}
	cgroup := "/" + ctrdServicesNamespace + "/" + name
	hostDir := filepath.Join(memoryRoot, cgroup)
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		return "", "", err
	}
	return cgroup, hostDir, nil
}

// AppHelpersCgroup creates the helpers cgroup of the domain whose task is
// named task, /eve-user-apps/<task>/helpers, in the memory hierarchy
// memoryRoot, normally HostMemoryCgroupRoot, and with it the domain's cgroup
// when the task does not exist yet: runc then finds that one and sets the
// domain's memory limit on it. It returns the cgroup's path in the hierarchy
// and its directory on the host, or ErrNoMemoryHierarchy when memoryRoot holds
// no cgroup v1 memory hierarchy.
func AppHelpersCgroup(memoryRoot, task string) (string, string, error) {
	return UserAppsMemoryCgroup(memoryRoot, task+"/"+appHelpersCgroupName)
}

// evictAppHelpers moves the helper processes of the domain whose task is named
// task out of the task's cgroup, to containerd's, so that runc can destroy the
// task's cgroup: the shim is still alive when its task is deleted. The pages
// they hold stay charged where they are, so this is done as late as possible.
// A task without a helpers cgroup needs nothing.
func evictAppHelpers(memoryRoot, task string) error {
	helpers := filepath.Join(memoryRoot, ctrdServicesNamespace, task, appHelpersCgroupName)
	procs, err := os.ReadFile(filepath.Join(helpers, "cgroup.procs"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	dest, err := os.OpenFile(filepath.Join(memoryRoot, ctrdConfiguredCgroup, "cgroup.procs"),
		os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer func() { _ = dest.Close() }()
	for _, pid := range strings.Fields(string(procs)) {
		// cgroupfs takes one pid per write; one that exited meanwhile is gone anyway
		if _, err := dest.WriteString(pid); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("cannot move pid %s of %s's helpers to %s: %w", pid, task, ctrdConfiguredCgroup, err)
		}
	}
	return nil
}

// shimCgroupOpt returns the container option that makes the shim of the
// container named task join the task's helpers cgroup as it starts, creating
// the cgroup if needed. The shim moves itself only once it runs, so the pages
// its start-up allocated in the cgroup it was born in, containerd's, stay
// charged there, about 2.5 MB per domain: cgroup v1 never migrates a charge.
// Without a cgroup v1 memory hierarchy at memoryRoot, or when the cgroup
// cannot be created, it returns nil and the shim stays in containerd's cgroup
// altogether.
func shimCgroupOpt(runtime, memoryRoot, task string) containerd.NewContainerOpts {
	cgroup, _, err := AppHelpersCgroup(memoryRoot, task)
	if errors.Is(err, ErrNoMemoryHierarchy) {
		logrus.Warnf("no cgroup v1 memory hierarchy at %s, shims stay in containerd's cgroup",
			memoryRoot)
		return nil
	}
	if err != nil {
		logrus.Errorf("cannot create the helpers cgroup of %s, its shim stays in containerd's cgroup: %v",
			task, err)
		return nil
	}
	return containerd.WithRuntime(runtime, &options.Options{ShimCgroup: cgroup})
}
