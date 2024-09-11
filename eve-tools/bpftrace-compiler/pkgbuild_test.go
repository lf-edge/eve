// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestCreateMobyConfig(t *testing.T) {
	t.Parallel()

	lkConf := lkConf{kernel: "docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.38-generic-fb31ce85306c-gcc"}
	ib := newImageBuilder("amd64", lkConf, "./")

	err := ib.buildPkgs([]string{"root"})
	if err != nil {
		t.Fatal(err)
	}
	m, err := ib.createMobyConfig()
	if err != nil {
		t.Fatal(err)
	}

	if len(m.Services) > 0 {
		t.Fatal("config should not have any services")
	}

	lkConf.services = map[string]string{
		"foo": "fooImage",
	}
	lkConf.onboot = map[string]string{
		"bar": "barImage",
	}
	ib.lkConf = lkConf
	ib.userspace = serviceContainer("foo")
	m, err = ib.createMobyConfig()
	if err != nil {
		t.Fatal(err)
	}

	if m.Services[0].Name != "foo" {
		t.Fatalf("wrong service name '%s'", m.Services[0].Name)
	}
	if m.Services[0].Image != "fooImage" {
		t.Fatalf("wrong service image '%s'", m.Services[0].Image)
	}

	ib.userspace = onbootContainer("bar")
	m, err = ib.createMobyConfig()
	if err != nil {
		t.Fatal(err)
	}

	if m.Onboot[0].Name != "bar" {
		t.Fatalf("wrong onboot name '%s'", m.Onboot[0].Name)
	}
	if m.Onboot[0].Image != "barImage" {
		t.Fatalf("wrong onboot image '%s'", m.Onboot[0].Image)
	}
}
