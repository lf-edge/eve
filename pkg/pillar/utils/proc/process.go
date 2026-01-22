// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package proc

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
	log "github.com/sirupsen/logrus"
)

// ProcessManager provides a unified interface to manage a single OS-level process.
// It supports starting, stopping, sending signals, checking liveness, and waiting
// for PID files. Optional WatchdogKicker support allows keeping the watchdog alive
// while waiting for process startup/shutdown.
//
// It is suitable for managing long-running daemons such as wpa_supplicant, radvd,
// dnsmasq, etc.
type ProcessManager struct {
	// Log is used for logging messages about process lifecycle events.
	Log *base.LogObject

	// PidFile is the path to the PID file used by the process.
	PidFile string

	// Cmd is the executable name or path to run.
	Cmd string

	// Args are the command-line arguments for the process.
	Args []string

	// WithNohup specifies whether to prepend "nohup" to the command invocation.
	// This is useful for processes that fork themselves or need to survive container exits.
	WithNohup bool

	// WillFork specifies if the process will daemonize itself by forking when started.
	WillFork bool

	// Watchdog is an optional pointer to a WatchdogKicker.
	// If set, Kick() will be called periodically during waits.
	Watchdog *WatchdogKicker
}

// Start launches the process, optionally allowing the process to fork itself
// (daemonize). It waits until the process appears alive (PID file exists and process runs),
// or until the contexts expires or is canceled.
func (pm *ProcessManager) Start(ctx context.Context) error {
	var execCmd *exec.Cmd
	if pm.WithNohup {
		args := append([]string{pm.Cmd}, pm.Args...)
		execCmd = exec.Command("nohup", args...)
	} else {
		execCmd = exec.Command(pm.Cmd, pm.Args...)
	}

	if pm.WillFork {
		// Process will fork and daemonize itself.
		// We start it in the foreground and rely on it to detach properly.
		out, err := execCmd.CombinedOutput()
		if err != nil {
			outStr := strings.TrimSpace(string(out))
			outStr = strings.ReplaceAll(outStr, "\n", "; ")
			err = fmt.Errorf("failed to start command %s "+
				"(args: %v; PID: %s): %w, output: %s",
				pm.Cmd, pm.Args, pm.getPidOfExitedCmd(execCmd), err, outStr)
			pm.Log.Error(err)
			return err
		}
	} else {
		if err := execCmd.Start(); err != nil {
			err = fmt.Errorf("failed to start command %s (args: %v; PID: %s): %w",
				pm.Cmd, pm.Args, pm.getPidOfExitedCmd(execCmd), err)
			pm.Log.Error(err)
			return err
		}
	}

	// Wait for the process to appear alive.
	for !pm.IsRunning() {
		if ctx.Err() != nil {
			err := fmt.Errorf("command %s (args: %v) failed to start: %w",
				pm.Cmd, pm.Args, ctx.Err())
			pm.Log.Error(err)
			return err
		}
		pm.Watchdog.Kick()
		time.Sleep(500 * time.Millisecond)
	}

	pid, err := pm.PID()
	if err == nil {
		pm.Log.Noticef("Started process %s %v with PID %d", pm.Cmd, pm.Args, pid)
	} else {
		log.Warnf("Started process %s %v but PID is unknown (%v)", pm.Cmd, pm.Args, err)
	}
	return nil
}

// Stop sends the specified signal to the process and waits until it terminates
// or until the context expires or is canceled.
func (pm *ProcessManager) Stop(ctx context.Context) error {
	if err := pm.SendSignal(syscall.SIGTERM); err != nil {
		return err
	}

	for pm.IsRunning() {
		if ctx.Err() != nil {
			err := fmt.Errorf("process %s failed to stop: %w", pm.Cmd, ctx.Err())
			pm.Log.Error(err)
			return err
		}
		pm.Watchdog.Kick()
		time.Sleep(500 * time.Millisecond)
	}
	return nil
}

// PID returns the numeric PID of the managed process by reading the PID file.
func (pm *ProcessManager) PID() (int, error) {
	return GetPidFromFile(pm.PidFile)
}

// IsRunning checks if the process exists and is alive.
func (pm *ProcessManager) IsRunning() bool {
	process, err := pm.getProcess()
	if err != nil || process == nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	if err != nil {
		if !errors.Is(err, os.ErrProcessDone) {
			pm.Log.Errorf("IsRunning(%s): signal failed with error: %v",
				pm.PidFile, err)
		}
		return false
	}
	return true
}

// SendSignal sends the specified OS signal to the managed process.
// Returns an error if the process cannot be found or the signal fails.
func (pm *ProcessManager) SendSignal(sig os.Signal) error {
	process, err := pm.getProcess()
	if err != nil {
		return err
	}
	err = process.Signal(sig)
	if err != nil {
		err = fmt.Errorf("signal %#v sent to process PID-file=%s failed: %w",
			sig, pm.PidFile, err)
		pm.Log.Error(err)
		return err
	}
	return nil
}

// getProcess returns an *os.Process representing the process managed by this
// ProcessManager, based on the PID stored in PidFile. Returns an error if the
// PID cannot be read or the process cannot be found.
func (pm *ProcessManager) getProcess() (*os.Process, error) {
	pid, err := pm.PID()
	if err != nil {
		return nil, err
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		err = fmt.Errorf("failed to find process PID=%d: %w", pid, err)
		return nil, err
	}
	return p, nil
}

// getPidOfExitedCmd returns the PID of an exec.Cmd that has already exited,
// or "?" if the PID is not available. Useful for logging error messages
// after a command fails to start.
func (pm *ProcessManager) getPidOfExitedCmd(cmd *exec.Cmd) string {
	pid := "?"
	if cmd.ProcessState != nil && cmd.ProcessState.Pid() != 0 {
		pid = strconv.Itoa(cmd.ProcessState.Pid())
	}
	return pid
}

// GetPidFromFile reads a PID from the given file.
func GetPidFromFile(pidFile string) (int, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		err = fmt.Errorf("failed to read PID file %s: %w",
			pidFile, err)
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		err = fmt.Errorf("failed to convert PID %s to int: %w",
			string(data), err)
		return 0, err
	}
	return pid, nil
}

// GetPidFromFileTimeout attempts to read a PID file with a timeout,
// periodically kicking the provided WatchdogKicker if non-nil.
func GetPidFromFileTimeout(
	pidFile string, timeoutSeconds uint, wk *WatchdogKicker) (int, error) {
	startTime := time.Now()
	for {
		if time.Since(startTime).Seconds() >= float64(timeoutSeconds) {
			return GetPidFromFile(pidFile)
		}
		pid, err := GetPidFromFile(pidFile)
		if err == nil {
			return pid, nil
		}
		wk.Kick()
		time.Sleep(500 * time.Millisecond)
	}
}

// Pkill executes the `pkill` command for the given pattern. If kill is true,
// sends SIGKILL; otherwise just matches without killing. Retries up to 3 times
// on failure, optionally logging errors.
func Pkill(log *base.LogObject, match string, printOnError bool, kill bool) {
	cmd := "pkill"
	var args []string
	if kill {
		args = []string{"-kill", "-f", match}
	} else {
		args = []string{"-f", match}
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
		log.Errorf("Command %v %v failed: %s output %s\n", cmd, args, err, out)
	}
}
