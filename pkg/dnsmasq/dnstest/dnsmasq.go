// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type dnsmasq struct {
	cmd *exec.Cmd
}

func (d *dnsmasq) Stop() {
	dnsmasqPidFile := "/var/run/dnsmasq.pid"
	bs, err := os.ReadFile(dnsmasqPidFile)
	if err == nil {
		pidString := string(bs)
		pidString = strings.TrimSpace(pidString)
		pid, err := strconv.Atoi(pidString)
		if err != nil {
			fmt.Printf("could not parse '%s': %v\n", pidString, err)
		} else {
			err := syscall.Kill(pid, syscall.SIGTERM)
			if err != nil {
				panic(err)
			}
			time.Sleep(time.Second)
			err = syscall.Kill(pid, syscall.SIGKILL)
			if err != nil && err != syscall.ESRCH {
				panic(err)
			}
		}
	}
	os.Remove(dnsmasqPidFile)

	err = d.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		fmt.Println(err)
	}
	time.Sleep(time.Second)
	err = d.cmd.Process.Signal(syscall.SIGKILL)
	if err != nil {
		fmt.Println(err)
	}
	err = d.cmd.Wait()
	if err != nil {
		fmt.Println(err)
	}

	d.cmd = nil
}

func startDnsmasq(loAddr net.IP) *dnsmasq {
	d := dnsmasq{}

	version := os.Getenv("DNSMASQ_VERSION")
	if version == "" {
		panic("DNSMASQ_VERSION env variable not set")
	}
	args := []string{
		"--no-resolv",
		"-S", loAddr.String(),
		"-a", "127.0.0.1",
		"-p", "1054",
	}
	dnsmasqBinaryPath := fmt.Sprintf("/dnsmasq/dnsmasq-%s/src/dnsmasq", version)
	d.cmd = exec.Command(dnsmasqBinaryPath, args...)
	d.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	d.cmd.Stdout = os.Stdout
	d.cmd.Stderr = os.Stderr

	err := d.cmd.Start()
	if err != nil {
		panic(err)
	}

	return &d
}
