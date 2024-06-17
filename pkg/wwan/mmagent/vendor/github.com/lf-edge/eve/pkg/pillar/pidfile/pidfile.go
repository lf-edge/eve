// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage pidfile in /run/

package pidfile

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

const (
	defaultRundir = "/run"
)

func writeMyPid(filename string) error {
	pid := os.Getpid()
	pidStr := fmt.Sprintf("%d", pid)
	b := []byte(pidStr)
	// if the directory does not exist, try to create it
	if err := os.MkdirAll(path.Dir(filename), 0755); err != nil {
		return err
	}
	return os.WriteFile(filename, b, 0644)
}

// CheckProcessExists returns true if agent process is running
// returns string with description of check result
func CheckProcessExists(log *base.LogObject, agentName string, options ...Option) (bool, string) {
	opt := processOpts(options)
	return checkProcessExists(log, agentName, opt)
}

func checkProcessExists(log *base.LogObject, agentName string, opt opt) (bool, string) {
	filename := path.Join(opt.baseDir, agentName+".pid")
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
func CheckAndCreatePidfile(log *base.LogObject, agentName string, options ...Option) error {
	opt := processOpts(options)
	if exists, description := checkProcessExists(log, agentName, opt); exists {
		return fmt.Errorf("checkAndCreatePidfile: %s", description)
	}
	rundir := defaultRundir
	if opt.baseDir != "" {
		rundir = opt.baseDir
	}
	filename := path.Join(rundir, agentName+".pid")
	if err := writeMyPid(filename); err != nil {
		log.Fatalf("checkAndCreatePidfile: %s", err)
	}
	return nil
}

func processOpts(options []Option) opt {
	opt := opt{}
	for _, o := range options {
		o(&opt)
	}
	if opt.baseDir == "" {
		opt.baseDir = defaultRundir
	}
	return opt
}

type opt struct {
	baseDir string
}

// Option option function to pass to pidfile functions
type Option func(o *opt)

// WithBaseDir set the base directory for pidfiles. Default is /run.
func WithBaseDir(baseDir string) Option {
	return func(o *opt) {
		o.baseDir = baseDir
	}
}
