// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package coverage holds the peer coverage flushing shared by zedbox
// (agentlog) and kube-init, which are separate processes that must agree on
// how a flush is requested (SIGUSR2) and how its completion is detected (one
// new covcounters file per flush). Only used in COVER=y builds.
package coverage

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// PeerFlushTimeout caps the wait for the peers' flush. COVER=y images
// are never used in production, so this cannot delay a production reboot.
const PeerFlushTimeout = 10 * time.Second

// FlushWithPeers sends SIGUSR2 to each of peerPids, runs flush for
// the calling process, then waits up to PeerFlushTimeout for every
// signalled peer to write its counters file into dir. logf reports failures.
func FlushWithPeers(dir string, peerPids []int, flush func(),
	logf func(format string, args ...interface{})) {
	before := countCounterFiles(dir)
	peers := 0
	for _, pid := range peerPids {
		if err := syscall.Kill(pid, syscall.SIGUSR2); err != nil {
			logf("coverage: kill -USR2 %d failed: %v", pid, err)
			continue
		}
		peers++
	}
	flush()
	// Our own flush adds one file, each peer one more.
	deadline := time.Now().Add(PeerFlushTimeout)
	for peers > 0 && countCounterFiles(dir) < before+1+peers {
		if time.Now().After(deadline) {
			logf("coverage: peers did not flush within %v",
				PeerFlushTimeout)
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	syscall.Sync()
}

// FindPidsByComm returns the pids of all processes whose /proc/<pid>/comm
// equals name.
func FindPidsByComm(name string) []int {
	var pids []int
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err == nil && strings.TrimSpace(string(comm)) == name {
			pids = append(pids, pid)
		}
	}
	return pids
}

func countCounterFiles(dir string) int {
	files, _ := filepath.Glob(filepath.Join(dir, "covcounters.*"))
	return len(files)
}
