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
// helpers child of the task's cgroup, which exists in the memory hierarchy
// only and is created ahead of the task.
func TestShimCgroupOpt(t *testing.T) {
	g := NewGomegaWithT(t)
	root := t.TempDir()
	g.Expect(os.WriteFile(filepath.Join(root, "memory.usage_in_bytes"),
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

// Without a cgroup v1 memory hierarchy the shim stays in containerd's cgroup,
// and nothing is created where that hierarchy would be mounted.
func TestShimCgroupOptWithoutMemoryHierarchy(t *testing.T) {
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
	g.Expect(os.WriteFile(filepath.Join(root, "memory.usage_in_bytes"),
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
