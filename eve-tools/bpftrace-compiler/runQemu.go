// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type qemuArchArgs interface {
	archArgs() []string
	cmdlineArchArgs() []string
	verboseArchAppendLineArgs() []string
}

type qemuRunner struct {
	imageDir   string
	bpfPath    string
	aotPath    string
	qemuArgs   map[string]string
	appendArgs map[string]struct{}
	units      []string
	stdin      io.Reader
	stdout     io.Writer
	stderr     io.Writer
	timeout    time.Duration
	qemuArchArgs
}

func newQemuAmd64Runner(imageDir, bpfPath, aotPath string) *qemuRunner {
	return &qemuRunner{
		imageDir:     imageDir,
		bpfPath:      bpfPath,
		aotPath:      aotPath,
		units:        []string{},
		qemuArgs:     map[string]string{},
		appendArgs:   map[string]struct{}{},
		qemuArchArgs: qemuArchArgsAmd64{},
		timeout:      2 * time.Minute,
	}
}

func newQemuArm64Runner(imageDir, bpfPath, aotPath string) *qemuRunner {
	return &qemuRunner{
		imageDir:     imageDir,
		bpfPath:      bpfPath,
		aotPath:      aotPath,
		units:        []string{},
		qemuArchArgs: qemuArchArgsArm64{},
		appendArgs:   map[string]struct{}{},
		timeout:      2 * time.Minute,
	}
}

func (q *qemuRunner) qemuAppendArg() string {
	appends := q.cmdlineArchArgs()

	var unitString string
	if len(q.units) > 0 {
		for _, unit := range q.units {
			unitString += unit + ","
		}

		unitString = strings.TrimSuffix(unitString, ",")
		unitString = "units=" + unitString

		appends = append(appends, unitString)
	}

	if len(q.appendArgs) > 0 {
		for arg := range q.appendArgs {
			appends = append(appends, arg)
		}
	}

	appendLine := strings.Join(appends, " ")
	return appendLine
}

func (q *qemuRunner) runList(listArg string) ([]byte, error) {
	shareDir, err := os.MkdirTemp("/var/tmp", "bpftrace-9pshare")
	if err != nil {
		return []byte{}, err
	}
	defer os.RemoveAll(shareDir)

	unit := "list"
	if listArg != "" {
		unit = fmt.Sprintf("list@%s", listArg)
	}
	q.units = append(q.units, unit)
	args := q.runArgs(shareDir)

	err = q.execQemu(args)

	if err != nil {
		return []byte{}, fmt.Errorf("running qemu failed: %v", err)
	}

	stdout, err := os.ReadFile(filepath.Join(shareDir, "stdout.txt"))
	if err != nil {
		return []byte{}, fmt.Errorf("reading stdout.txt (%s) failed: %v", shareDir, err)
	}

	return stdout, err
}

func (q *qemuRunner) run() ([]byte, error) {
	shareDir, err := os.MkdirTemp("/var/tmp", "bpftrace-9pshare")
	if err != nil {
		return []byte{}, err
	}
	defer os.RemoveAll(shareDir)

	err = copyFile(q.bpfPath, filepath.Join(shareDir, "bpf.bt"))
	if err != nil {
		return []byte{}, err
	}

	q.units = append(q.units, "compile")
	args := q.runArgs(shareDir)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	q.stdin = nil
	q.stdout = &stdoutBuf
	q.stderr = &stderrBuf
	err = q.execQemu(args)

	stderrBytes := stderrBuf.Bytes()
	if len(stderrBytes) > 0 {
		stdoutBuf.Write([]byte("\nStderr:\n"))
		stdoutBuf.Write(stderrBytes)
	}
	qemuOutput := stdoutBuf.Bytes()
	if err != nil {
		return qemuOutput, err
	}

	err = copyFile(filepath.Join(shareDir, "bpf.aot"), q.aotPath)
	if err != nil {
		return qemuOutput, err
	}

	return qemuOutput, err
}

func (q *qemuRunner) runArgs(shareDir string) []string {
	args := q.archArgs()
	args = append(args, qemuImageDirArgs(q.imageDir)...)
	args = append(args, qemu9pShareArgs(shareDir)...)
	q.qemuQuietArgs()
	args = append(args, "-append", q.qemuAppendArg())
	return args
}

func (q *qemuRunner) runDebug(shareDir string) error {
	q.units = append(q.units, "shell")
	args := q.runDebugArgs(shareDir)
	err := q.execQemu(args)
	return err
}

func (q *qemuRunner) runDebugArgs(shareDir string) []string {
	args := q.archArgs()
	args = append(args, qemuImageDirArgs(q.imageDir)...)
	args = append(args, qemu9pShareArgs(shareDir)...)
	q.qemuVerboseArgs()
	args = append(args, "-append", q.qemuAppendArg())

	q.stdin = os.Stdin
	q.stdout = os.Stdout
	q.stderr = os.Stderr

	return args
}

func (q *qemuRunner) execQemu(args []string) error {
	var err error
	var ctx context.Context
	var cancel context.CancelFunc

	ctx = context.Background()
	if q.timeout > 0 {
		ctx, cancel = context.WithCancel(ctx)
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = q.stdin
	cmd.Stdout = q.stdout
	cmd.Stderr = q.stderr
	cmd.WaitDelay = 0

	log.Printf("running %q", cmd.Args)
	go func() {
		time.Sleep(q.timeout)
		if cancel != nil {
			cancel()
		}
	}()
	err = cmd.Run()

	return err
}

func qemuImageDirArgs(imageDir string) []string {
	return []string{
		"-kernel", filepath.Join(imageDir, "linuxkit-kernel"),
		"-hda", filepath.Join(imageDir, "linuxkit-squashfs.img"),
	}
}

func qemu9pShareArgs(srcPath string) []string {
	return []string{
		"-fsdev", fmt.Sprintf("local,id=dev,path=%s,security_model=mapped,multidevs=remap", srcPath),
		"-device", "virtio-9p-pci,fsdev=dev,mount_tag=9pmount",
	}
}

func (q *qemuRunner) qemuVerboseArgs() {
	for _, arg := range q.verboseArchAppendLineArgs() {
		q.appendArgs[arg] = struct{}{}
	}
}

func (q *qemuRunner) qemuQuietArgs() {
	q.appendArgs["console=null"] = struct{}{}
	q.appendArgs["quiet"] = struct{}{}
}

type qemuArchArgsArm64 struct{}

func (qemuArchArgsArm64) cmdlineArchArgs() []string {
	return []string{"root=/dev/vda"}
}

func (qemuArchArgsArm64) verboseArchAppendLineArgs() []string {
	return []string{
		"console=ttyAMA0",
	}
}

func (qemuArchArgsArm64) archArgs() []string {
	args := []string{
		"/usr/bin/qemu-system-aarch64",
		"-smp", "1",
		"-nographic",
		"-m", "256",
		"-cpu", "cortex-a57",
		"-machine", "virt",
		"-object", "rng-random,id=rng0,filename=/dev/urandom",
		"-device", "virtio-rng-pci,rng=rng0",
	}

	return args
}

type qemuArchArgsAmd64 struct{}

func (qemuArchArgsAmd64) verboseArchAppendLineArgs() []string {
	return []string{
		"console=ttyS0",
	}
}

func (qemuArchArgsAmd64) archArgs() []string {
	args := []string{
		"/usr/bin/qemu-system-x86_64",
		"-smp", "1",
		"-nographic",
		"-m", "256",
		"-device", "virtio-net-pci,netdev=t0,mac=5a:7e:cb:9c:12:67",
		"-netdev", "user,id=t0",
	}
	return args
}

func (qemuArchArgsAmd64) cmdlineArchArgs() []string {
	return []string{"root=/dev/sda"}
}
