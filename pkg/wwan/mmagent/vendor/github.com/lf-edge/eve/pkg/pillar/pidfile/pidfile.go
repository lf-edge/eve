// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage pidfile in /run/

package pidfile

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

const (
	rundir = "/run"
)

func writeMyPid(filename string) error {
	pid := os.Getpid()
	pidStr := fmt.Sprintf("%d", pid)
	b := []byte(pidStr)
	return os.WriteFile(filename, b, 0644)
}

// CheckProcessExists returns true if agent process is running
// returns string with description of check result
func CheckProcessExists(log *base.LogObject, agentName string) (bool, string) {
	filename := fmt.Sprintf("%s/%s.pid", rundir, agentName)
	if _, err := os.Stat(filename); err != nil && os.IsNotExist(err) {
		return false, err.Error()
	}
	log.Functionf("CheckProcessExists: found %s\n", filename)
	// Check if process still exists
	b, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("CheckProcessExists: %s", err)
	}
	oldPid, err := strconv.Atoi(string(b))
	if err != nil {
		return false, fmt.Sprintf("atoi of %s failed %s", filename, err)
	}
	// Does the old pid exist?
	p, err := os.FindProcess(oldPid)
	if err == nil {
		err = p.Signal(syscall.Signal(0))
		if err == nil {
			return true, fmt.Sprintf("old pid %d exists for agent %s", oldPid, agentName)
		}
	}
	return false, fmt.Sprintf("no running process found for agent %s", agentName)
}

// CheckAndCreatePidfile check if old process is not running and create new pid file
func CheckAndCreatePidfile(log *base.LogObject, agentName string) error {
	if exists, description := CheckProcessExists(log, agentName); exists {
		return fmt.Errorf("checkAndCreatePidfile: %s", description)
	}
	filename := fmt.Sprintf("%s/%s.pid", rundir, agentName)
	if err := writeMyPid(filename); err != nil {
		log.Fatalf("checkAndCreatePidfile: %s", err)
	}
	return nil
}
