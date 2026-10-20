// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/types/runc/options"
	"github.com/sirupsen/logrus"
)

const ctrdConfiguredCgroup = "/eve/containerd"

// ErrNoCgroupTree is returned by the cgroup helpers when there is no cgroup
// v2 tree to create the cgroup in.
var ErrNoCgroupTree = errors.New("no cgroup v2 tree")

// A domain's cgroup, /eve-user-apps/<task>, is pillar's. It carries the
// domain's memory limit and its CPUs, and holds two children: appTaskCgroupName,
// where runc puts the domain itself, and appHelpersCgroupName, the helper
// processes EVE runs for the domain, its containerd shim and its swtpm.
//
// The helpers are per-domain overhead, like the domain's qemu, but EVE's
// services, containerd and vtpm, start them in their own cgroups, whose memory
// limits are fixed and shared under /eve: fifty domains bring fifty shims and
// swtpms, enough to exhaust that budget and stall the services. Under the
// domain's cgroup they count against the domain's limit instead, which the
// admission check already pays for, and run on the domain's CPUs rather than
// on the few EVE's services share.
//
// runc gets a child of its own because it refuses a cgroup that already holds
// a process, and the shim joins the helpers child before it runs runc. runc
// destroys only that child with the task; the helpers child, whose shim is
// still alive then, and the domain's cgroup are pillar's to empty and remove.
const (
	appTaskCgroupName    = "task"
	appHelpersCgroupName = "helpers"
)

// UserAppsCgroup creates the cgroup /eve-user-apps/<name>, where the
// per-domain helper processes of EVE's services are charged beside the domains
// they belong to rather than to the service's budget under /eve. root is the
// cgroup v2 tree, normally cgroup.Root. It returns the cgroup's path in the
// tree and its directory on the host, or ErrNoCgroupTree when root holds no
// cgroup v2 tree.
func UserAppsCgroup(root, name string) (string, string, error) {
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return "", "", ErrNoCgroupTree
	}
	cgroup := "/" + ctrdServicesNamespace + "/" + name
	hostDir := filepath.Join(root, cgroup)
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		return "", "", err
	}
	return cgroup, hostDir, nil
}

// AppTaskCgroup returns the cgroup runc puts the domain whose task is named
// task in: the task child of the domain's cgroup.
func AppTaskCgroup(task string) string {
	return "/" + ctrdServicesNamespace + "/" + task + "/" + appTaskCgroupName
}

// AppHelpersCgroup creates the helpers child of the cgroup of the domain whose
// task is named task, /eve-user-apps/<task>/helpers, in the cgroup tree root,
// normally cgroup.Root, and with it the domain's cgroup, with the controllers
// enabled down to its children so that a limit set on it holds. It returns the
// child's path in the tree and its directory on the host, or ErrNoCgroupTree
// when root holds no cgroup v2 tree.
func AppHelpersCgroup(root, task string) (string, string, error) {
	cgroup, hostDir, err := UserAppsCgroup(root, task+"/"+appHelpersCgroupName)
	if err != nil {
		return "", "", err
	}
	for _, dir := range []string{filepath.Dir(filepath.Dir(hostDir)), filepath.Dir(hostDir)} {
		if err := enableControllers(dir); err != nil {
			return "", "", err
		}
	}
	return cgroup, hostDir, nil
}

// enableControllers enables every controller available in the cgroup at dir
// for its children. A directory without cgroup.controllers is not a cgroup,
// which the fake trees of unit tests have, and needs nothing.
func enableControllers(dir string) error {
	available, err := os.ReadFile(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	controllers := strings.Fields(string(available))
	if len(controllers) == 0 {
		return nil
	}
	enable := "+" + strings.Join(controllers, " +")
	if err := os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte(enable), 0644); err != nil {
		return fmt.Errorf("cannot enable the controllers of %s: %w", dir, err)
	}
	return nil
}

// setAppCgroupMemoryLimit sets limit as the memory limit of the cgroup of the
// domain whose task is named task, over the task child and the helpers child
// alike.
func setAppCgroupMemoryLimit(root, task string, limit int64) error {
	path := filepath.Join(root, ctrdServicesNamespace, task, "memory.max")
	if err := os.WriteFile(path, []byte(strconv.FormatInt(limit, 10)), 0644); err != nil {
		return fmt.Errorf("cannot set the memory limit of %s: %w", task, err)
	}
	return nil
}

// setAppCgroupCPUs confines the domain whose task is named task to cpus, a
// cpuset.cpus list, through the domain's cgroup: the task child and the
// helpers child inherit the CPUs, and domainmgr changes them there as the
// pinning of other domains changes.
func setAppCgroupCPUs(root, task, cpus string) error {
	path := filepath.Join(root, ctrdServicesNamespace, task, "cpuset.cpus")
	if err := os.WriteFile(path, []byte(cpus), 0644); err != nil {
		return fmt.Errorf("cannot set the CPUs of %s: %w", task, err)
	}
	return nil
}

// evictAppHelpers moves the helper processes of the domain whose task is named
// task out of the domain's cgroup, to containerd's, so that the cgroup can be
// removed: the shim is still alive when its task is deleted. The pages they
// hold stay charged where they are, so this is done as late as possible. A
// task without a helpers cgroup needs nothing.
func evictAppHelpers(root, task string) error {
	helpers := filepath.Join(root, ctrdServicesNamespace, task, appHelpersCgroupName)
	procs, err := os.ReadFile(filepath.Join(helpers, "cgroup.procs"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	dest, err := os.OpenFile(filepath.Join(root, ctrdConfiguredCgroup, "cgroup.procs"),
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

// removeAppCgroup removes the helpers child and the cgroup of the domain whose
// task is named task, once runc has removed the task child with the task and
// the helpers have been evicted. A domain without them needs nothing.
func removeAppCgroup(root, task string) error {
	domain := filepath.Join(root, ctrdServicesNamespace, task)
	for _, dir := range []string{filepath.Join(domain, appHelpersCgroupName), domain} {
		if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("cannot remove the cgroup %s: %w", dir, err)
		}
	}
	return nil
}

// shimCgroupOpt returns the container option that makes the shim of the
// container named task join the task's helpers cgroup as it starts, creating
// the cgroup if needed. The shim moves itself only once it runs, so the pages
// its start-up allocated in the cgroup it was born in, containerd's, stay
// charged there, about 2.5 MB per domain: a charge never migrates. Without a
// cgroup v2 tree at root, or when the cgroup cannot be created, it returns nil
// and the shim stays in containerd's cgroup altogether.
func shimCgroupOpt(runtime, root, task string) containerd.NewContainerOpts {
	cgroup, _, err := AppHelpersCgroup(root, task)
	if errors.Is(err, ErrNoCgroupTree) {
		logrus.Warnf("no cgroup v2 tree at %s, shims stay in containerd's cgroup", root)
		return nil
	}
	if err != nil {
		logrus.Errorf("cannot create the helpers cgroup of %s, its shim stays in containerd's cgroup: %v",
			task, err)
		return nil
	}
	return containerd.WithRuntime(runtime, &options.Options{ShimCgroup: cgroup})
}
