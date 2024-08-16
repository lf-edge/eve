// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

func testList(arch string, kernel string, t *testing.T, expectedTracepoint string) {
	imageDir, err := os.MkdirTemp("/var/tmp", "bpftrace-image")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(imageDir)
	createImage(arch, lkConf{kernel: kernel}, nil, imageDir)

	var qr *qemuRunner
	if arch == "amd64" {
		qr = newQemuAmd64Runner(imageDir, "", "")
	} else if arch == "arm64" {
		qr = newQemuArm64Runner(imageDir, "", "")
	}

	output, err := qr.runList("")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(output, []byte(expectedTracepoint)) {
		t.Fatalf("output does not contain %s probe", expectedTracepoint)
	}
}

func TestListKernelProbesAmd64(t *testing.T) {
	_, err := exec.LookPath("/usr/bin/qemu-system-x86_64")
	if err != nil {
		t.Skipf("no qemu for amd64 installed, skipping this test")
		return
	}
	if testing.Short() {
		t.Skip("Test takes too long")
		return
	}
	kernel := "docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.38-generic-fb31ce85306c-gcc"
	arch := "amd64"
	expectedTracepoint := "tracepoint:syscalls:sys_enter_ptrace"

	testList(arch, kernel, t, expectedTracepoint)
}

func TestListKernelProbesArm64(t *testing.T) {
	_, err := exec.LookPath("/usr/bin/qemu-system-aarch64")
	if err != nil {
		t.Skipf("no qemu for aarch64 installed, skipping this test")
		return
	}
	if testing.Short() {
		t.Skip("Test takes too long")
		return
	}
	kernel := "docker.io/lfedge/eve-kernel:eve-kernel-arm64-v6.1.38-generic-394a3bcff39d-gcc"
	arch := "arm64"
	expectedTracepoint := "tracepoint:syscalls:sys_enter_ptrace"

	testList(arch, kernel, t, expectedTracepoint)
}
