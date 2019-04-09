// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage pidfile in /var/run/

package pidfile

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"strconv"
	"syscall"
)

const (
	rundir = "/var/run"
)

func writeMyPid(filename string) error {
	pid := os.Getpid()
	pidStr := fmt.Sprintf("%d", pid)
	b := []byte(pidStr)
	return ioutil.WriteFile(filename, b, 0644)
}

func CheckAndCreatePidfile(agentName string) error {
	filename := fmt.Sprintf("%s/%s.pid", rundir, agentName)
	if _, err := os.Stat(filename); err != nil {
		// Assume file does not exist; Create file
		if err := writeMyPid(filename); err != nil {
			log.Fatalf("checkAndCreatePidfile: %s\n", err)
		}
		return nil
	}
	log.Infof("checkAndCreatePidfile: found %s\n", filename)
	// Check if process still exists
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("checkAndCreatePidfile: %s\n", err)
	}
	oldPid, err := strconv.Atoi(string(b))
	if err != nil {
		log.Errorf("Atoi of %s failed %s; ignored\n", filename, err)
	} else {
		// Does the old pid exist?
		p, err := os.FindProcess(oldPid)
		if err == nil {
			err = p.Signal(syscall.Signal(0))
			if err == nil {
				errStr := fmt.Sprintf("Old pid %d exists for agent %s",
					oldPid, agentName)
				return errors.New(errStr)
			}
		}
	}
	if err := writeMyPid(filename); err != nil {
		log.Fatalf("checkAndCreatePidfile: %s\n", err)
	}
	return nil
}
