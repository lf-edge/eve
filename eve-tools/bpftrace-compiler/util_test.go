// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

var exampleLinuxKitYaml = []byte(`
kernel:
  image: docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.38-generic-fb31ce85306c-gcc
init:
- docker.io/linuxkit/init:07d37c3ae7fad5ddcb54c8dc65774ae050851f04
- docker.io/linuxkit/runc:6062483d748609d505f2bcde4e52ee64a3329f5f
onboot:
- name: rngd
  image: docker.io/lfedge/eve-rngd:89f9e51e68888fb35f6072efb8e19dff864ca351-amd64
  command:
  - /sbin/rngd
  - "-1"
- name: sysctl
  image: docker.io/linuxkit/sysctl:c6f23919b8610c7645a89a89f863c6209bc84bee
  capabilities:
  - CAP_SYS_ADMIN
  - CAP_NET_ADMIN
  binds:
  - /etc/sysctl.d:/etc/sysctl.d
onshutdown: []
services:
- name: newlogd
  image: docker.io/lfedge/eve-newlog:0017b3503b49ec8e7d702ebbcfe1609b13f7d581-amd64
- name: edgeview
  image: docker.io/lfedge/eve-edgeview:5f9d4556e5a89ab135fe05af37454633a55af39e-amd64
- name: debug
  image: docker.io/lfedge/eve-debug:70d7198e17fe5b796d6ba5fe7795e5b2f04247f7-amd64
`)

func TestLinuxkitYml2KernelImage(t *testing.T) {
	t.Parallel()
	expectedImage := "docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.38-generic-fb31ce85306c-gcc"
	lkConf := linuxkitYml2KernelConf(exampleLinuxKitYaml)

	if lkConf.kernel != expectedImage {
		t.Fatalf("expected '%s', but got '%s'", expectedImage, lkConf)
	}
}
