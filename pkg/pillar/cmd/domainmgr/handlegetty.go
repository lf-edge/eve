// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/shirou/gopsutil/process"
)

// cmdlineGettyFlag should be aligned with grub.cfg in grub and 001-getty in dom0-ztools
const cmdlineGettyFlag = "getty"

var gettyStarted bool

func hasInitGettyStarted(log *base.LogObject) bool {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		log.Errorf("cannot read /proc/cmdline: %v", err)
		return false
	}
	bootArgs := strings.Fields(string(data))
	for _, arg := range bootArgs {
		if arg == cmdlineGettyFlag {
			return true
		}
	}
	return false
}

func startGetty(log *base.LogObject) {
	if gettyStarted {
		log.Noticeln("getty already started")
		return
	}
	if hasInitGettyStarted(log) {
		log.Noticeln("getty started in init")
		return
	}
	// INITGETTY option will run the script in background
	args := []string{"/hostfs", "/bin/sh", "-c", "INITGETTY=true INSECURE=true /usr/bin/rungetty.sh"}
	cmd := exec.Command("chroot", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to start getty: %v", err)
	}
	log.Noticeln("getty started")
	gettyStarted = true
}

func stopGetty(log *base.LogObject) {
	if !gettyStarted {
		return
	}
	if hasInitGettyStarted(log) {
		log.Noticeln("Not killing getty because it was started in init")
		return
	}

	// Find and send USR1 signal to all rungetty.sh processes
	procs, err := process.Processes()
	if err != nil {
		log.Errorf("Cannot list processes")
		return
	}
	for _, p := range procs {
		name, _ := p.Name()
		if strings.Contains(name, "rungetty.sh") {
			proc, err := os.FindProcess(int(p.Pid))
			if err != nil {
				continue
			}
			if err := proc.Signal(syscall.SIGUSR1); err != nil {
				log.Errorf("Failed to signal pid %d: %v", p.Pid, err)
			}
		}
	}
	gettyStarted = false
}
