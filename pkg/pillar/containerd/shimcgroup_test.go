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

	opt := shimCgroupOpt("io.containerd.runc.v2", root)
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

	g.Expect(shimCgroupOpt("io.containerd.runc.v2", root)).To(BeNil())
	g.Expect(filepath.Join(root, "eve-user-apps")).ToNot(BeAnExistingFile())
}
