// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/mod/semver"
)

type eveKernelWithArch struct {
	image string
	arch  string
}

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

func testKernels() []eveKernelWithArch {
	var err error

	ret := make([]eveKernelWithArch, 0)
	paths := []string{
		"kernel-commits.mk",
		"../kernel-commits.mk",
		"../../kernel-commits.mk",
	}

	var fh *os.File
	for _, path := range paths {
		fh, err = os.Open(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			log.Fatalf("could not open %s: %v", path, err)
		}
	}

	if fh == nil {
		log.Fatalf("could not read %+v: %v", paths, err)
	}

	defer fh.Close()

	// e.g.: KERNEL_COMMIT_amd64_v5.10.186_generic = d61682724485
	rex := regexp.MustCompile(`^\s*KERNEL_COMMIT_(?P<arch>[^_\s]+)_(?P<version>[^_\s]+)_(?P<flavor>[^_\s]+)\s*=\s*(?P<commit>\S+)\s*$`)
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		match := rex.FindStringSubmatch(line)
		result := make(map[string]string)
		for i, name := range rex.SubexpNames() {
			if i < 1 || name == "" {
				continue
			}

			result[name] = match[i]
		}

		version := result["version"]
		flavor := result["flavor"]
		arch := result["arch"]
		commit := result["commit"]
		compiler := "gcc"

		skip := false
		for _, str := range []string{
			version, flavor, arch, commit, compiler,
		} {
			if str == "" {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if arch != "amd64" && arch != "arm64" {
			continue
		}
		if semver.Compare(version, "v6.0.0") < 0 {
			continue
		}

		kernelBranch := fmt.Sprintf("eve-kernel-%s-%s-%s", arch, version, flavor)

		kernelDockerTag := fmt.Sprintf("docker.io/lfedge/eve-kernel:%s-%s-%s", kernelBranch, commit, compiler)

		ret = append(ret, eveKernelWithArch{
			image: kernelDockerTag,
			arch:  arch,
		})
	}

	err = scanner.Err()
	if err != nil {
		log.Fatalf("scanning %s failed: %v", fh.Name(), err)
	}

	return ret
}

func TestCurrentKernels(t *testing.T) {
	if skip(t) {
		return
	}

	kernels := testKernels()

	expectedTracepoint := "tracepoint:syscalls:sys_enter_ptrace"
	for _, kernel := range kernels {
		testList(kernel.arch, kernel.image, t, []string{}, expectedTracepoint)
	}
}
