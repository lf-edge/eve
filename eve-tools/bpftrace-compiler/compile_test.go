// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
)

func testCompile(t *testing.T, arch, eveKernel string) {
	btFh, err := os.CreateTemp("/var/tmp", "bpftrace-testcompileamd64bt")
	if err != nil {
		panic(err)
	}

	btFilename := btFh.Name()
	defer os.Remove(btFilename)

	_, err = btFh.WriteString(`kprobe:do_nanosleep { printf("PID %d sleeping...\n", pid); }`)
	if err != nil {
		panic(err)
	}
	btFh.Close()

	aotFh, err := os.CreateTemp("/var/tmp", fmt.Sprintf("bpftrace-testcompile-aoh-%s", arch))
	if err != nil {
		panic(err)
	}

	aotFilename := aotFh.Name()
	defer aotFh.Close()
	defer os.Remove(aotFilename)

	err = compile(arch, lkConf{kernel: eveKernel}, nil, []string{}, btFilename, aotFilename)
	if err != nil {
		t.Fatalf("compiling failed: %v", err)
	}

	slurp, err := io.ReadAll(aotFh)
	if err != nil {
		panic(err)
	}

	if !bytes.Contains(slurp, []byte("PID %d sleeping")) {
		t.Fatal("String missing")
	}

}

func TestCompileAmd64(t *testing.T) {
	_, err := exec.LookPath("/usr/bin/qemu-system-x86_64")
	if err != nil {
		t.Skipf("no qemu for amd64 installed, skipping this test")
		return
	}
	if testing.Short() {
		t.Skip("Test takes too long")
		return
	}
	arch := "amd64"
	eveKernel := "docker.io/lfedge/eve-kernel:eve-kernel-amd64-v6.1.38-generic-fb31ce85306c-gcc"

	testCompile(t, arch, eveKernel)
}

func TestCompileArm64(t *testing.T) {
	_, err := exec.LookPath("/usr/bin/qemu-system-aarch64")
	if err != nil {
		t.Skipf("no qemu for aarch64 installed, skipping this test")
		return
	}
	if testing.Short() {
		t.Skip("Test takes too long")
		return
	}
	arch := "arm64"
	eveKernel := "docker.io/lfedge/eve-kernel:eve-kernel-arm64-v6.1.38-generic-394a3bcff39d-gcc"

	testCompile(t, arch, eveKernel)
}
