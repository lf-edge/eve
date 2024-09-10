// Copyright (c) 2017-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
)

// WatchdogKick is used in some proc functions that have a timeout,
// to tell the watchdog agent is still alive.
type WatchdogKick struct {
	ps        *pubsub.PubSub
	agentName string
	warnTime  time.Duration
	errTime   time.Duration
}

// NewWatchdogKick creates a new WatchdogKick.
func NewWatchdogKick(ps *pubsub.PubSub, agentName string, warnTime time.Duration, errTime time.Duration) *WatchdogKick {
	return &WatchdogKick{
		ps:        ps,
		agentName: agentName,
		warnTime:  warnTime,
		errTime:   errTime,
	}
}

// PkillArgs does a pkill
func PkillArgs(log *base.LogObject, match string, printOnError bool, kill bool) {
	cmd := "pkill"
	var args []string
	if kill {
		args = []string{
			"-kill",
			"-f",
			match,
		}
	} else {
		args = []string{
			"-f",
			match,
		}
	}
	var err error
	var out []byte
	for i := 0; i < 3; i++ {
		log.Functionf("Calling command %s %v\n", cmd, args)
		out, err = base.Exec(log, cmd, args...).CombinedOutput()
		if err == nil {
			break
		}
		if printOnError {
			log.Warnf("Retrying failed command %v %v: %s output %s",
				cmd, args, err, out)
		}
		time.Sleep(time.Second)
	}
	if err != nil && printOnError {
		log.Errorf("Command %v %v failed: %s output %s\n",
			cmd, args, err, out)
	}
}

// GetPidFromFile reads a pid from a file.
func GetPidFromFile(pidFile string) (int, error) {
	content, err := os.ReadFile(pidFile)
	if err != nil {
		return 0, fmt.Errorf("failed to read pid file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil {
		return 0, fmt.Errorf("failed to parse pid: %w", err)
	}

	return pid, nil
}

// GetPidFromFileTimeout reads a pid from a file with a timeout.
func GetPidFromFileTimeout(pidFile string, timeoutSeconds uint, wk *WatchdogKick) (int, error) {
	startTime := time.Now()
	for {
		if time.Since(startTime).Seconds() >= float64(timeoutSeconds) {
			return GetPidFromFile(pidFile)
		}

		pid, err := GetPidFromFile(pidFile)
		if err == nil {
			return pid, nil
		}

		if wk != nil {
			wk.ps.StillRunning(wk.agentName, wk.warnTime, wk.errTime)
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// IsProcAlive checks if a process is alive or not.
func IsProcAlive(pid int) bool {
	err := syscall.Kill(pid, syscall.Signal(0))
	if err != nil {
		if err == syscall.ESRCH {
			return false
		}
		//EPERM? then it is alive?
	}
	return true
}

// IsProcAliveTimeout checks if a process is alive for a given timeout.
func IsProcAliveTimeout(pid int, timeoutSeconds uint, wk *WatchdogKick) bool {
	startTime := time.Now()
	for {
		if time.Since(startTime).Seconds() >= float64(timeoutSeconds) {
			return IsProcAlive(pid)
		}

		if !IsProcAlive(pid) {
			return false
		}

		if wk != nil {
			wk.ps.StillRunning(wk.agentName, wk.warnTime, wk.errTime)
		}

		time.Sleep(500 * time.Millisecond)
	}
}
