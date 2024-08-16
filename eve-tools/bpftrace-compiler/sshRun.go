// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshRun struct {
	sshClient *eveSSHClient
}

func newSSHRun(host, privKey string) (*run, error) {
	var err error
	var sr sshRun

	sr.sshClient, err = newSSHClient(host, privKey)
	if err != nil {
		return nil, fmt.Errorf("newSSHClient failed with: %v", err)
	}

	var r run

	r.remoteRun = &sr
	return &r, nil
}

func (sr *sshRun) lkConf() lkConf {

	ymlBytes := sr.sshClient.getLinuxkitYaml()
	lkConf := linuxkitYml2KernelConf(ymlBytes)
	if lkConf.kernel == "" {
		log.Fatal("could not determine kernel version")
	}

	return lkConf
}

func (sr *sshRun) arch() string {
	arch := string(sr.sshClient.getArch())
	arch = strings.TrimSpace(arch)
	if arch == "" {
		log.Fatal("could not determine architecture")
	}

	return arch
}

func (sr *sshRun) runBpftrace(aotFile string, timeout time.Duration) error {
	sr.sshClient.putFile(aotFile, "/tmp/bpf.aot")

	log.Printf("Running bpftrace program")
	bpfOutput, bpfErr, err := sr.sshClient.runWithTimeout("/usr/bin/bpftrace-aotrt -f json /tmp/bpf.aot", timeout)
	if err != nil {
		exitError, ok := err.(*ssh.ExitError)
		if ok && exitError.Signal() == "PIPE" {
			log.Printf("Timeout reached")
		} else {
			log.Printf("running bpftrace failed: %v\n", err)
		}
	}
	fmt.Println(string(bpfOutput))
	if len(bpfErr) > 0 {
		fmt.Printf("\n----\nStderr:\n%s\n", bpfErr)
	}

	return nil
}

func (sr *sshRun) end() {
	sr.sshClient.close()
}
