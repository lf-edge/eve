// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package vnc manages a VNC proxy for KubeVirt VMIs. It watches a
// JSON configuration file written by edgeview and starts/stops a
// virtctl vnc subprocess accordingly. An optional caller-PID
// watchdog cleans up if the requesting edgeview process crashes.
package vnc

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Paths and process knobs. Vars so tests can route them onto tmp
// fixtures; treat as constants in production.
var (
	vncConfigDir   = "/run/edgeview/VncParams"
	vncConfigFile  = vncConfigDir + "/vmiVNC.run"
	virtctlPath    = "/usr/bin/virtctl"
	virtctlLogFile = "/tmp/virtctl-vnc.log"

	maxRetries          = 5
	retryDelay          = 2 * time.Second
	portWaitTimeout     = 5 * time.Second
	pollInterval        = 1 * time.Second
	callerCheckInterval = 5 * time.Second
)

// vncNamespace is the kubernetes namespace where VMIs live. Fixed
// by EVE convention; not configurable per call.
const vncNamespace = "eve-kube-app"

// vncConfig is the on-disk request payload written by edgeview.
type vncConfig struct {
	VMIName   string `json:"VMIName"`
	VNCPort   int    `json:"VNCPort"`
	CallerPID int    `json:"CallerPID,omitempty"`
}

// Manager controls the lifecycle of a single virtctl vnc proxy
// process. One Manager runs per kube-init daemon instance.
type Manager struct {
	mu           sync.Mutex
	running      bool
	virtctlCmd   *exec.Cmd
	logFile      *os.File
	callerCancel context.CancelFunc
	exitCh       chan error
}

// NewManager returns a ready-to-use Manager.
func NewManager() *Manager { return &Manager{} }

// Run is the main poll loop. Watches vncConfigFile and brings the
// virtctl proxy up when the file appears, tears it down when the
// file disappears, and reaps the proxy if it dies on its own.
// Blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	if err := os.MkdirAll(vncConfigDir, 0755); err != nil {
		log.Printf("vnc: failed to create %s: %v", vncConfigDir, err)
		return
	}
	log.Printf("vnc: watching %s for VNC config", vncConfigFile)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.handleStop()
			log.Printf("vnc: context cancelled, manager exiting")
			return
		case <-ticker.C:
			present := isRegularFile(vncConfigFile)

			m.mu.Lock()
			running := m.running
			if running && m.exitCh != nil {
				// Detect a virtctl that died on us.
				select {
				case <-m.exitCh:
					log.Printf("vnc: virtctl process died unexpectedly")
					m.clearRunningLocked()
					running = false
				default:
				}
			}
			m.mu.Unlock()

			switch {
			case present && !running:
				if err := m.handleStart(ctx); err != nil {
					log.Printf("vnc: failed to start proxy: %v", err)
				}
			case !present && running:
				m.handleStop()
			}
		}
	}
}

// clearRunningLocked resets the live-process fields. Caller must
// hold m.mu.
func (m *Manager) clearRunningLocked() {
	m.running = false
	m.virtctlCmd = nil
	m.exitCh = nil
	if m.logFile != nil {
		m.logFile.Close()
		m.logFile = nil
	}
}

// handleStart reads the on-disk config and brings virtctl up with
// bounded retries. After a successful start it kicks off the
// caller-PID watchdog if the config specified one.
func (m *Manager) handleStart(ctx context.Context) error {
	data, err := os.ReadFile(vncConfigFile)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var cfg vncConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if cfg.VMIName == "" || cfg.VNCPort == 0 {
		return fmt.Errorf("invalid config: VMIName=%q VNCPort=%d",
			cfg.VMIName, cfg.VNCPort)
	}

	log.Printf("vnc: starting proxy for VMI %s on port %d", cfg.VMIName, cfg.VNCPort)

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := m.startVirtctl(&cfg); err != nil {
			lastErr = err
			log.Printf("vnc: attempt %d/%d failed: %v", attempt, maxRetries, err)
			if attempt < maxRetries {
				// time.Sleep is fine here: handleStart already
				// re-checks ctx.Done at the top of every iteration.
				time.Sleep(retryDelay)
			}
			continue
		}
		if cfg.CallerPID > 0 {
			callerCtx, cancel := context.WithCancel(ctx)
			m.mu.Lock()
			m.callerCancel = cancel
			m.mu.Unlock()
			go m.callerPIDWatchdog(callerCtx, cfg.CallerPID)
		}
		return nil
	}
	return fmt.Errorf("all %d retries exhausted: %w", maxRetries, lastErr)
}

// startVirtctl launches the virtctl proxy and waits for its port
// to become listenable. On premature exit or port-wait timeout it
// reaps the process and returns the failure.
func (m *Manager) startVirtctl(cfg *vncConfig) error {
	logFile, err := os.OpenFile(virtctlLogFile,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	cmd := exec.Command(virtctlPath,
		"vnc", cfg.VMIName,
		"-n", vncNamespace,
		"--port", fmt.Sprintf("%d", cfg.VNCPort),
		"--proxy-only",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("start virtctl: %w", err)
	}

	// Background reaper so cmd.Wait's exit lands on a channel we can
	// select against alongside the port-listening probe.
	exitCh := make(chan error, 1)
	go func() { exitCh <- cmd.Wait() }()

	deadline := time.Now().Add(portWaitTimeout)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for time.Now().Before(deadline) {
		select {
		case <-exitCh:
			logFile.Close()
			return fmt.Errorf("virtctl exited before port was ready")
		case <-tick.C:
			if portListening(cfg.VNCPort) {
				m.mu.Lock()
				m.virtctlCmd = cmd
				m.logFile = logFile
				m.exitCh = exitCh
				m.running = true
				m.mu.Unlock()
				log.Printf("vnc: proxy running (pid %d) on port %d for VMI %s",
					cmd.Process.Pid, cfg.VNCPort, cfg.VMIName)
				return nil
			}
		}
	}

	// Port never came up — kill and reap.
	_ = cmd.Process.Kill()
	<-exitCh
	logFile.Close()
	return fmt.Errorf("port %d not listening after %v", cfg.VNCPort, portWaitTimeout)
}

// handleStop cancels the caller watchdog and tears the virtctl
// process down.
func (m *Manager) handleStop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return
	}
	if m.callerCancel != nil {
		m.callerCancel()
		m.callerCancel = nil
	}
	if m.virtctlCmd != nil && m.virtctlCmd.Process != nil {
		log.Printf("vnc: stopping proxy (pid %d)", m.virtctlCmd.Process.Pid)
		_ = m.virtctlCmd.Process.Kill()
		if m.exitCh != nil {
			<-m.exitCh
		}
	}
	m.clearRunningLocked()
}

// callerPIDWatchdog stops the proxy and removes the config file
// when the caller process dies. Used to recover from a crashed
// edgeview that won't clean up after itself.
func (m *Manager) callerPIDWatchdog(ctx context.Context, pid int) {
	log.Printf("vnc: watching caller PID %d", pid)
	ticker := time.NewTicker(callerCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !processAlive(pid) {
				log.Printf("vnc: caller PID %d is gone, cleaning up", pid)
				m.handleStop()
				if err := os.Remove(vncConfigFile); err != nil && !os.IsNotExist(err) {
					log.Printf("vnc: remove %s: %v", vncConfigFile, err)
				}
				return
			}
		}
	}
}

// portListening dials 127.0.0.1:<port> with a 1-second budget and
// returns true if anything answered.
func portListening(port int) bool {
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// processAlive reports whether the given PID exists. Signal 0 is a
// no-op delivery probe: nil error means the process is alive.
func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// isRegularFile reports whether path resolves to a regular file.
// Errors collapse to false — for the poll loop they're indistinguishable
// from "absent" and the loop will pick the file up on the next tick
// when it actually appears.
func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
