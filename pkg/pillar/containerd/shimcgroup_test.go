// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/api/types/runc/options"
	"github.com/containerd/containerd/containers"
	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/proto"
)

// A domain's shim is per-domain overhead, so it must be charged under the
// domain's own memory limit rather than to containerd's cgroup under /eve: the
// container record carries the runc option that makes the shim join the
// helpers child of the task's cgroup, which enables no controller of its own
// and is created ahead of the task.
func TestShimCgroupOpt(t *testing.T) {
	g := NewGomegaWithT(t)
	root := t.TempDir()
	g.Expect(os.WriteFile(filepath.Join(root, "cgroup.controllers"),
		[]byte("0\n"), 0644)).To(Succeed())

	opt := shimCgroupOpt("io.containerd.runc.v2", root, "task-1")
	g.Expect(opt).ToNot(BeNil())
	g.Expect(filepath.Join(root, "eve-user-apps", "task-1", "helpers")).To(BeADirectory())

	var c containers.Container
	g.Expect(opt(context.Background(), nil, &c)).To(Succeed())
	g.Expect(c.Runtime.Name).To(Equal("io.containerd.runc.v2"))
	g.Expect(c.Runtime.Options).ToNot(BeNil())
	g.Expect(c.Runtime.Options.GetTypeUrl()).To(HaveSuffix("containerd.runc.v1.Options"),
		"the message name the shim resolves the options by")
	var got options.Options
	g.Expect(proto.Unmarshal(c.Runtime.Options.GetValue(), &got)).To(Succeed())
	g.Expect(got.ShimCgroup).To(Equal("/eve-user-apps/task-1/helpers"))
}

// Without a cgroup v2 tree the shim stays in containerd's cgroup,
// and nothing is created where that hierarchy would be mounted.
func TestShimCgroupOptWithoutCgroupTree(t *testing.T) {
	g := NewGomegaWithT(t)
	root := t.TempDir()

	g.Expect(shimCgroupOpt("io.containerd.runc.v2", root, "task-1")).To(BeNil())
	g.Expect(filepath.Join(root, "eve-user-apps")).ToNot(BeAnExistingFile())
}

// runc destroys a task's cgroup, children included, when the task is deleted,
// and a shim is still alive at that point. So before the task is deleted,
// every process in the helpers child goes back to containerd's cgroup.
func TestEvictAppHelpers(t *testing.T) {
	g := NewGomegaWithT(t)
	root := t.TempDir()
	g.Expect(os.WriteFile(filepath.Join(root, "cgroup.controllers"),
		[]byte("0\n"), 0644)).To(Succeed())
	_, helpers, err := AppHelpersCgroup(root, "task-1")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(os.WriteFile(filepath.Join(helpers, "cgroup.procs"), []byte("4242\n4243\n"), 0644)).To(Succeed())
	ctrd := filepath.Join(root, "eve", "containerd")
	g.Expect(os.MkdirAll(ctrd, 0755)).To(Succeed())
	g.Expect(os.WriteFile(filepath.Join(ctrd, "cgroup.procs"), nil, 0644)).To(Succeed())

	g.Expect(evictAppHelpers(root, "task-1")).To(Succeed())
	moved, err := os.ReadFile(filepath.Join(ctrd, "cgroup.procs"))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(string(moved)).To(Equal("42424243"), "each pid written on its own, as cgroupfs takes them")
}

// A task that never had helpers, or whose cgroup is gone, needs nothing.
func TestEvictAppHelpersWithoutCgroup(t *testing.T) {
	g := NewGomegaWithT(t)
	root := t.TempDir()

	g.Expect(evictAppHelpers(root, "task-1")).To(Succeed())
	g.Expect(filepath.Join(root, "eve")).ToNot(BeAnExistingFile())
}

// The domain's cgroup is pillar's: it carries the memory limit for the task
// child, where runc puts the domain, and for the helpers child alike, and the
// controllers that make a limit effective are enabled on the way down to it.
func TestAppCgroupCarriesTheLimit(t *testing.T) {
	g := NewGomegaWithT(t)
	root := t.TempDir()
	g.Expect(os.WriteFile(filepath.Join(root, "cgroup.controllers"),
		[]byte("cpuset cpu memory\n"), 0644)).To(Succeed())
	apps := filepath.Join(root, "eve-user-apps")
	g.Expect(os.MkdirAll(apps, 0755)).To(Succeed())
	g.Expect(os.WriteFile(filepath.Join(apps, "cgroup.controllers"),
		[]byte("cpuset cpu memory\n"), 0644)).To(Succeed())

	_, helpers, err := AppHelpersCgroup(root, "task-1")
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(helpers).To(Equal(filepath.Join(apps, "task-1", "helpers")))
	enabled, err := os.ReadFile(filepath.Join(apps, "cgroup.subtree_control"))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(string(enabled)).To(Equal("+cpuset +cpu +memory"))
	// The fake domain cgroup lists no controllers, so nothing is enabled in it.
	g.Expect(filepath.Join(apps, "task-1", "cgroup.subtree_control")).ToNot(BeAnExistingFile())

	g.Expect(setAppCgroupMemoryLimit(root, "task-1", 123456789)).To(Succeed())
	limit, err := os.ReadFile(filepath.Join(apps, "task-1", "memory.max"))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(string(limit)).To(Equal("123456789"))

	g.Expect(AppTaskCgroup("task-1")).To(Equal("/eve-user-apps/task-1/task"))
}

// Once runc has deleted the task child, the helpers child and the domain's
// cgroup are pillar's to remove; a domain that never had them needs nothing.
func TestRemoveAppCgroup(t *testing.T) {
	g := NewGomegaWithT(t)
	root := t.TempDir()
	g.Expect(os.WriteFile(filepath.Join(root, "cgroup.controllers"),
		[]byte("memory\n"), 0644)).To(Succeed())
	_, helpers, err := AppHelpersCgroup(root, "task-1")
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(removeAppCgroup(root, "task-1")).To(Succeed())
	g.Expect(helpers).ToNot(BeAnExistingFile())
	g.Expect(filepath.Dir(helpers)).ToNot(BeAnExistingFile())
	g.Expect(removeAppCgroup(root, "task-2")).To(Succeed())
}

// A pinned domain's CPUs are pillar's to set as well: they go to the domain's
// cgroup, which the task child and the helpers child inherit, not into the
// spec, where runc would write them to the task child alone and domainmgr's
// later changes to the domain's cgroup could never widen them.
func TestAppCgroupCarriesTheCPUs(t *testing.T) {
	g := NewGomegaWithT(t)
	root := t.TempDir()
	g.Expect(os.WriteFile(filepath.Join(root, "cgroup.controllers"),
		[]byte("cpuset cpu memory\n"), 0644)).To(Succeed())
	_, _, err := AppHelpersCgroup(root, "task-1")
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(setAppCgroupCPUs(root, "task-1", "1,3")).To(Succeed())
	cpus, err := os.ReadFile(filepath.Join(root, "eve-user-apps", "task-1", "cpuset.cpus"))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(string(cpus)).To(Equal("1,3"))
}
