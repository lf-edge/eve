// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// startSleeper returns a live process standing in for qemu and the state
// directory holding its pid file. Both the pid file and the monitor socket are
// looked for there, so nothing here can reach a domain on the test host.
func startSleeper(t *testing.T) (stateDir string, domainName string, pid int) {
	t.Helper()
	domainName = "forcetest"
	stateDir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(stateDir, domainName), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start stand-in process: %v", err)
	}
	pid = cmd.Process.Pid
	// A zombie still answers signal 0, which is how liveness is probed, so this
	// child has to be reaped as soon as it dies. qemu is not a child of pillar,
	// so this only matters here.
	go func() { _, _ = cmd.Process.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	pidFile := filepath.Join(stateDir, domainName, "pid")
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", pid)), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return stateDir, domainName, pid
}

// A domain whose QMP monitor cannot be reached still has to be terminated: that
// is the path a guest which never services the poweroff request takes.
func TestTerminateQemuKillsWhenMonitorUnreachable(t *testing.T) {
	stateDir, domainName, pid := startSleeper(t)

	// No qmp socket under the temporary state directory, so the quit is skipped
	// exactly as it is for a wedged or absent monitor.
	if err := terminateQemu(stateDir, domainName, "test"); err != nil {
		t.Errorf("terminateQemu: %v", err)
	}

	if err := syscall.Kill(pid, 0); err == nil {
		t.Errorf("process %d survived terminateQemu", pid)
	}
}

// The pid file is the only handle on the process, so a domain without one must
// not wedge the caller, and has nothing left to terminate so does not fail.
func TestTerminateQemuWithoutPidFile(t *testing.T) {
	domainName := "forcetest"
	stateDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(stateDir, domainName), 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- terminateQemu(stateDir, domainName, "test") }()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("terminateQemu: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("terminateQemu did not return without a pid file")
	}
}

// A pid file that is there but unusable leaves nothing to signal, so no kill is
// attempted; the caller has to hear about that rather than being told the forced
// stop succeeded over a domain that is still running.
func TestTerminateQemuReportsUnusablePidFile(t *testing.T) {
	stateDir, domainName, pid := startSleeper(t)
	pidFile := filepath.Join(stateDir, domainName, "pid")
	if err := os.WriteFile(pidFile, []byte("not-a-pid\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := terminateQemu(stateDir, domainName, "test"); err == nil {
		t.Error("terminateQemu reported success with an unusable pid file")
	}
	if err := syscall.Kill(pid, 0); err != nil {
		t.Errorf("stand-in process %d was signalled despite an unusable pid file: %v", pid, err)
	}
}
