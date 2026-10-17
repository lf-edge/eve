// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/types/runc/options"
	"github.com/sirupsen/logrus"
)

// hostfsRoot is where pillar sees the host's root filesystem.
const hostfsRoot = "/hostfs"

// HostMemoryCgroupRoot is the cgroup v1 memory hierarchy. Pillar's own
// cgroupfs mount is read-only, so the hierarchy is reached through hostfs.
const HostMemoryCgroupRoot = hostfsRoot + "/sys/fs/cgroup/memory"

// ErrNoMemoryHierarchy is returned by UserAppsMemoryCgroup when there is no
// cgroup v1 memory hierarchy to create the cgroup in, as under cgroup v2.
var ErrNoMemoryHierarchy = errors.New("no cgroup v1 memory hierarchy")

// shimCgroupName names the cgroup every domain's containerd shim is started in.
//
// A shim is per-domain overhead, like the domain's qemu, but containerd starts
// it in its own cgroup, /eve/containerd, whose memory limit is fixed and shared
// with EVE's services under /eve. Fifty domains bring fifty shims, which is
// enough to exhaust that budget and stall the services, so the shim joins a
// cgroup beside the domains instead.
const shimCgroupName = "shims"

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

// shimWrapper is the program a domain's container names as its runtime, by
// the path the system containerd, a host process, sees pillar's rootfs at:
// pillar's eve-shim, which joins the shim cgroup and then executes the real
// shim, containerd-shim-runc-v2. The shim itself joins ShimCgroup only once
// it runs, after its runtime allocated its first pages in the cgroup it was
// born in, containerd's, and cgroup v1 leaves those pages charged there, a few
// MB per domain. Born in the shim cgroup, it leaves nothing behind.
const shimWrapper = "/containers/services/pillar/rootfs/opt/zededa/bin/eve-shim"

// shimCgroupOpt returns the container option that starts the container's shim
// in the shim cgroup, creating the cgroup if needed: through the shim wrapper
// when hostfs, the host's root as pillar sees it, holds it, and in any case
// with the runc option that makes the shim join the cgroup. Without a cgroup
// v1 memory hierarchy at memoryRoot, or when the cgroup cannot be created, it
// returns nil and the shim stays in containerd's cgroup.
func shimCgroupOpt(runtime, memoryRoot, hostfs string) containerd.NewContainerOpts {
	cgroup, _, err := UserAppsMemoryCgroup(memoryRoot, shimCgroupName)
	if errors.Is(err, ErrNoMemoryHierarchy) {
		logrus.Warnf("no cgroup v1 memory hierarchy at %s, shims stay in containerd's cgroup",
			memoryRoot)
		return nil
	}
	if err != nil {
		logrus.Errorf("cannot create the shim cgroup, shims stay in containerd's cgroup: %v", err)
		return nil
	}
	if _, err := os.Stat(filepath.Join(hostfs, shimWrapper)); err == nil {
		runtime = shimWrapper
	} else {
		logrus.Warnf("no shim wrapper at %s, the shims' first pages stay in containerd's cgroup: %v",
			shimWrapper, err)
	}
	return containerd.WithRuntime(runtime, &options.Options{ShimCgroup: cgroup})
}
