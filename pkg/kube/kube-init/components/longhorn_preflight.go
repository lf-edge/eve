// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Advisory floors for the Longhorn pre-flight check. A node below
// these values is unlikely to bring Longhorn up or place replicas
// reliably; the check logs a WARNING but never fails the install.
const (
	// Longhorn documents a 4 GiB per-node minimum, and that is for
	// Longhorn alone. It runs alongside k3s and kubevirt here, so
	// a node at the floor is already tight.
	// https://longhorn.io/docs/1.9.1/best-practices/
	longhornMinMemGiB = 4

	// Longhorn refuses to place replicas once a disk drops below
	// storageMinimalAvailablePercentage (default 25%). On a small
	// /persist (e.g. a 32 GiB boot disk) EVE's own usage pushes
	// available under that floor and no replica can be placed;
	// 64 GiB gives adequate headroom. Warn when the schedulable
	// slice is below longhornMinSchedulableGiB.
	longhornMinStoragePct     = 25
	longhornMinSchedulableGiB = 16
)

// longhornDiskPath is the default disk path Longhorn is told to
// use (see applyLonghornDiskConfig).
const longhornDiskPath = "/persist/vault/volumes"

// longhornPreflightCheck warns when node memory or the schedulable
// space on the Longhorn default-disk path is below what Longhorn
// needs to start and place replicas. Advisory only: it never fails
// the install. Redoes intent from upstream commit 0a468d90f.
func longhornPreflightCheck() {
	if mem, err := readMemTotalGiB(); err != nil {
		log.Printf("WARNING: could not read MemTotal from /proc/meminfo (%v); skipping Longhorn memory pre-flight", err)
	} else if mem < longhornMinMemGiB {
		log.Printf("WARNING: node has %d GiB RAM; Longhorn documents a %d GiB per-node minimum (and it runs alongside k3s/kubevirt here). Longhorn may fail to start reliably; provision more memory.",
			mem, longhornMinMemGiB)
	}

	path := longhornDiskPath
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		path = "/persist"
	}
	total, avail, err := statfsGiB(path)
	if err != nil {
		log.Printf("WARNING: statfs(%s) failed (%v); skipping Longhorn storage pre-flight", path, err)
		return
	}
	reserve := total * longhornMinStoragePct / 100
	sched := avail - reserve
	if sched < 0 {
		sched = 0
	}
	if sched < longhornMinSchedulableGiB {
		log.Printf("WARNING: Longhorn default disk %s has %d GiB free of %d GiB; after the %d%% Longhorn reserve only ~%d GiB is schedulable (< %d GiB). Replicas may fail to schedule; a 64 GiB boot disk is recommended for EVE-k.",
			path, avail, total, longhornMinStoragePct, sched, longhornMinSchedulableGiB)
	}
}

// readMemTotalGiB reads /proc/meminfo and returns MemTotal rounded
// down to GiB. Kept as a package-level function (not a method) so
// tests can override /proc/meminfo via a temp file if needed.
func readMemTotalGiB() (int64, error) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("malformed MemTotal line: %q", line)
		}
		kib, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse MemTotal kib: %w", err)
		}
		return kib / 1024 / 1024, nil
	}
	return 0, fmt.Errorf("MemTotal not found in /proc/meminfo")
}

// statfsGiB returns (total, available) in GiB for the filesystem
// containing path. Uses statfs(2); mirrors the accounting the
// shell's `df -kP <path>` produces.
func statfsGiB(path string) (total, avail int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := int64(st.Bsize)
	total = int64(st.Blocks) * bsize / 1024 / 1024 / 1024
	avail = int64(st.Bavail) * bsize / 1024 / 1024 / 1024
	return total, avail, nil
}
