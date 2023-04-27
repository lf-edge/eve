// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// Just a set of functions used by configurators managing items that represent processes
// (e.g. dnsmasq, radvd, etc.).

func startProcess(ctx context.Context, log *base.LogObject, cmd string, args []string,
	pidFile string, timeout time.Duration, willFork bool) error {
	startTime := time.Now()
	execCmd := exec.Command(cmd, args...)
	if willFork {
		// Process will "daemonize" itself by forking and intentionally becoming orphaned.
		// We can therefore start the command as a foreground process.
		out, err := execCmd.CombinedOutput()
		if err != nil {
			outStr := strings.TrimSpace(string(out))
			outStr = strings.ReplaceAll(outStr, "\n", "; ")
			err = fmt.Errorf("failed to start command %s (args: %v): %w, output: %s",
				cmd, args, err, outStr)
			log.Error(err)
			return err
		}
	} else {
		err := execCmd.Start()
		if err != nil {
			err = fmt.Errorf("failed to start command %s (args: %v): %w", cmd, args, err)
			log.Error(err)
			return err
		}
	}
	// Wait for the process to start.
	for !isProcessRunning(log, pidFile) {
		if time.Since(startTime) > timeout {
			err := fmt.Errorf("command %s (args: %v) failed to start in time", cmd, args)
			log.Error(err)
			return err
		}
		select {
		case <-ctx.Done():
			err := fmt.Errorf("command %s (args: %v) failed to start: canceled", cmd, args)
			log.Error(err)
			return err
		default:
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

func stopProcess(ctx context.Context, log *base.LogObject,
	pidFile string, timeout time.Duration) error {
	stopTime := time.Now()
	if err := sendSignalToProcess(log, pidFile, syscall.SIGTERM); err != nil {
		return err
	}
	// Wait for the process to stop.
	for isProcessRunning(log, pidFile) {
		if time.Since(stopTime) > timeout {
			err := fmt.Errorf("process pid-file=%s failed to stop in time", pidFile)
			log.Error(err)
			return err
		}
		select {
		case <-ctx.Done():
			err := fmt.Errorf("process pid-file=%s failed to stop: canceled", pidFile)
			log.Error(err)
			return err
		default:
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

func sendSignalToProcess(log *base.LogObject, pidFile string, sig os.Signal) error {
	process := getProcess(log, pidFile)
	if process == nil {
		err := fmt.Errorf("process pid-file=%s is not running", pidFile)
		log.Error(err)
		return err
	}
	err := process.Signal(sig)
	if err != nil {
		err = fmt.Errorf("signal %#v sent to process pid-file=%s failed: %w",
			sig, pidFile, err)
		log.Error(err)
		return err
	}
	return nil
}

func isProcessRunning(log *base.LogObject, pidFile string) bool {
	process := getProcess(log, pidFile)
	if process == nil {
		return false
	}
	err := process.Signal(syscall.Signal(0))
	if err != nil {
		if !errors.Is(err, os.ErrProcessDone) {
			log.Errorf("isProcessRunning(%s): signal failed with error: %v", pidFile, err)
		}
		return false
	}
	return true
}

func getProcess(log *base.LogObject, pidFile string) (process *os.Process) {
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		// Not running, return nil.
		return nil
	}
	pidStr := strings.TrimSpace(string(pidBytes))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		log.Errorf("getProcess(%s): strconv.Atoi of %s failed: %v",
			pidFile, pidStr, err)
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		log.Errorf("getProcess(%s): process PID=%d not found: %v",
			pidFile, pid, err)
		return nil
	}
	return p
}

func ensureDir(log *base.LogObject, dirname string) error {
	err := os.MkdirAll(dirname, 0755)
	if err != nil {
		err = fmt.Errorf("failed to create directory %s: %w", dirname, err)
		log.Error(err)
		return err
	}
	return nil
}
