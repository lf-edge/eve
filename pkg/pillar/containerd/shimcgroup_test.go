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
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/proto"
)

// A domain's shim is per-domain overhead, so it must start in a cgroup beside
// the domains rather than in containerd's own under /eve: the container record
// carries the runc option that makes the shim join shimCgroup, which exists in
// the memory hierarchy only.
func TestShimCgroupOpt(t *testing.T) {
	g := NewGomegaWithT(t)
	root := t.TempDir()
	g.Expect(os.WriteFile(filepath.Join(root, "memory.usage_in_bytes"),
		[]byte("0\n"), 0644)).To(Succeed())

	opt := shimCgroupOpt("io.containerd.runc.v2", root, t.TempDir())
	g.Expect(opt).ToNot(BeNil())
	g.Expect(filepath.Join(root, "eve-user-apps", "shims")).To(BeADirectory())

	var c containers.Container
	g.Expect(opt(context.Background(), nil, &c)).To(Succeed())
	g.Expect(c.Runtime.Name).To(Equal("io.containerd.runc.v2"))
	g.Expect(c.Runtime.Options).ToNot(BeNil())
	g.Expect(c.Runtime.Options.GetTypeUrl()).To(HaveSuffix("containerd.runc.v1.Options"),
		"the message name the shim resolves the options by")
	var got options.Options
	g.Expect(proto.Unmarshal(c.Runtime.Options.GetValue(), &got)).To(Succeed())
	g.Expect(got.ShimCgroup).To(Equal("/eve-user-apps/shims"))
}

// Without a cgroup v1 memory hierarchy the shim stays in containerd's cgroup,
// and nothing is created where that hierarchy would be mounted.
func TestShimCgroupOptWithoutMemoryHierarchy(t *testing.T) {
	g := NewGomegaWithT(t)
	root := t.TempDir()

	g.Expect(shimCgroupOpt("io.containerd.runc.v2", root, t.TempDir())).To(BeNil())
	g.Expect(filepath.Join(root, "eve-user-apps")).ToNot(BeAnExistingFile())
}

// The shim joins ShimCgroup only once it runs, after its runtime allocated its
// first pages in the cgroup it was born in, containerd's, where cgroup v1 leaves
// them charged. So when pillar's eve-shim wrapper is visible on the host, the
// domain's container names it as its runtime: it joins the shim cgroup and
// then executes the real shim, which is born there.
func TestShimCgroupOptStartsTheShimThroughTheWrapper(t *testing.T) {
	g := NewGomegaWithT(t)
	root := t.TempDir()
	g.Expect(os.WriteFile(filepath.Join(root, "memory.usage_in_bytes"),
		[]byte("0\n"), 0644)).To(Succeed())
	hostfs := t.TempDir()
	wrapper := filepath.Join(hostfs, shimWrapper)
	g.Expect(os.MkdirAll(filepath.Dir(wrapper), 0755)).To(Succeed())
	g.Expect(os.WriteFile(wrapper, []byte("#!/bin/sh\n"), 0755)).To(Succeed())

	opt := shimCgroupOpt("io.containerd.runc.v2", root, hostfs)
	g.Expect(opt).ToNot(BeNil())
	var c containers.Container
	g.Expect(opt(context.Background(), nil, &c)).To(Succeed())
	g.Expect(c.Runtime.Name).To(Equal(shimWrapper), "the runtime binary the daemon executes")
	var got options.Options
	g.Expect(proto.Unmarshal(c.Runtime.Options.GetValue(), &got)).To(Succeed())
	g.Expect(got.ShimCgroup).To(Equal("/eve-user-apps/shims"))
}
