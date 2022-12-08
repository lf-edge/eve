// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"os"
	"os/exec"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
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
	args := []string{"/hostfs", "/bin/sh", "-c", "INSECURE=true /usr/bin/rungetty.sh"}
	cmd := exec.Command("chroot", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatalf("failed to start getty: %v", err)
	}
	log.Noticeln("getty started")
	gettyStarted = true
	go func() {
		err := cmd.Wait()
		log.Fatalf("getty stopped: %v", err)
	}()
}
