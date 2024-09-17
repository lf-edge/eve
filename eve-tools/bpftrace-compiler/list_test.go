// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

func testList(arch string, kernel string, t *testing.T, kernelModules []string, expectedTracepoint string) {
	imageDir, err := os.MkdirTemp("/var/tmp", "bpftrace-image")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(imageDir)
	createImage(arch, lkConf{kernel: kernel}, nil, imageDir)

	qr := newQemuRunner(arch, imageDir, "", "")
	qr.withLoadKernelModule(kernelModules)

	output, err := qr.runList("")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(output, []byte(expectedTracepoint)) {
		t.Fatalf("output does not contain %s probe, arch: %s, kernel: %s", expectedTracepoint, arch, kernel)
	}
}

func skip(t *testing.T) bool {
	if testing.Short() {
		t.Skip("Test takes too long")
		return true
	}

	for _, qemuBin := range []string{"qemu-system-x86_64", "qemu-system-aarch64"} {
		_, err := exec.LookPath(qemuBin)
		if err != nil {
			t.Skipf("%s cannot be found, skipping", qemuBin)
			return true
		}
	}

	return false
}

func TestListKernelProbesAmd64(t *testing.T) {
	if skip(t) {
		return
	}
	kernel := "docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.38-generic-fb31ce85306c-gcc"
	arch := "amd64"
	expectedTracepoint := "tracepoint:syscalls:sys_enter_ptrace"

	testList(arch, kernel, t, []string{}, expectedTracepoint)
}

func TestListKernelProbesArm64(t *testing.T) {
	if skip(t) {
		return
	}
	kernel := "docker.io/lfedge/eve-kernel:eve-kernel-arm64-v6.1.38-generic-394a3bcff39d-gcc"
	arch := "arm64"
	expectedTracepoint := "tracepoint:syscalls:sys_enter_ptrace"

	testList(arch, kernel, t, []string{}, expectedTracepoint)
}

func TestListKernelProbesAmd64WithModules(t *testing.T) {
	if skip(t) {
		return
	}

	kernel := "docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.38-generic-fb31ce85306c-gcc"
	kernelModules := []string{"dm_crypt", "zfs"}
	arch := "amd64"
	expectedTracepoint := "kprobe:zfs_open"

	testList(arch, kernel, t, kernelModules, expectedTracepoint)
}

func TestCurrentKernels(t *testing.T) {
	kernels := testKernels()

	expectedTracepoint := "tracepoint:syscalls:sys_enter_ptrace"
	for _, kernel := range kernels {
		testList(kernel.arch, kernel.image, t, []string{}, expectedTracepoint)
	}
}
