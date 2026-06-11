// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// StaleMountCleanupBinary is the on-disk path of the stale-mount-
// cleanup daemon, built and installed by pkg/kube/Dockerfile. var
// so tests can redirect.
var StaleMountCleanupBinary = "/usr/bin/stale-mount-cleanup"

// StartStaleMountCleanup launches the stale-mount-cleanup daemon
// if not already running. Idempotent via /proc scan.
//
// The daemon detects and clears stale Longhorn CSI block-volume
// staging mounts left over when a Longhorn iSCSI session is
// replaced without NodeUnstageVolume being called. Without it,
// every NodePublishVolume attempt against the affected PV fails
// with a misleading ENOENT on the publish path. See the package
// doc on pkg/kube/stale-mount-cleanup/main.go for the detection
// signals (nlink==0, Rdev mismatch) and the cleanup sequence.
//
// Must run inside the kube container — that's the namespace that
// shares the kubelet mount namespace and can see
// /var/lib/kubelet/... The reaper goroutine LOGS the exit error so
// a daemon that crashes seconds after start surfaces in the
// kube-init log rather than vanishing silently.
//
// Mirrors the launch sequence in cluster-init.sh's main loop from
// upstream commit b036179da ("kube: add stale-mount-cleanup daemon
// to kube container").
func StartStaleMountCleanup() error {
	if isStaleMountCleanupRunning() {
		return nil
	}
	cmd := exec.Command(StaleMountCleanupBinary)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start stale-mount-cleanup: %w", err)
	}
	pid := cmd.Process.Pid
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("stale-mount-cleanup (pid %d) exited: %v", pid, err)
		}
	}()
	log.Printf("stale-mount-cleanup daemon started (pid %d)", pid)
	return nil
}

// isStaleMountCleanupRunning scans /proc for a process whose
// argv[0] basename equals the daemon binary's basename. argv[0]
// matching avoids false positives from anything that happens to
// have "stale-mount-cleanup" in its cmdline as an argument (e.g.
// pgrep, this very kube-init process if it ever logs the name).
func isStaleMountCleanupRunning() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	wantBase := filepath.Base(StaleMountCleanupBinary)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", name, "cmdline"))
		if err != nil {
			continue
		}
		argv0 := string(cmdline)
		if i := strings.IndexByte(argv0, 0); i >= 0 {
			argv0 = argv0[:i]
		}
		if filepath.Base(argv0) == wantBase {
			return true
		}
	}
	return false
}
