// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"
)

type run struct {
	remoteRun
}

type remoteRun interface {
	arch() string
	lkConf() lkConf
	runBpftrace(aotFile string, timeout time.Duration) error
	end()
}

func (r *run) run(bpfFile string, uc userspaceContainer, timeout time.Duration) {
	fh, err := os.CreateTemp("/var/tmp", "bpftrace-aot")
	if err != nil {
		log.Fatalf("could not create temp file: %v", err)
	}
	outputFile := fh.Name()
	fh.Close()
	defer os.Remove(outputFile)

	arch := cleanArch(r.arch())
	lkConf := r.lkConf()
	err = compile(arch, lkConf, uc, bpfFile, outputFile)
	if err != nil {
		log.Fatalf("compiling for %s/%s failed: %v", arch, lkConf, err)
	}

	log.Printf("Running bpftrace ...")
	err = r.runBpftrace(outputFile, timeout)
	if err != nil {
		log.Fatalf("compiling for %s/%s on %s failed: %v", arch, lkConf, outputFile, err)
	}

}

func compile(arch string, lkConf lkConf, uc userspaceContainer, bpfFile string, outputFile string) error {
	arch = cleanArch(arch)
	imageDir, err := os.MkdirTemp("/var/tmp", "bpftrace-image")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(imageDir)
	createImage(arch, lkConf, uc, imageDir)

	var qr *qemuRunner
	if arch == "arm64" {
		qr = newQemuArm64Runner(imageDir, bpfFile, outputFile)
	} else if arch == "amd64" {
		qr = newQemuAmd64Runner(imageDir, bpfFile, outputFile)
	}

	qemuOutput, err := qr.run()
	if err != nil {
		qemuOutpuString := hex.Dump(qemuOutput)
		return fmt.Errorf("Copying AOT file (%s) failed: %w, qemu output is:\n%s", outputFile, err, qemuOutpuString)
	}

	return nil
}
