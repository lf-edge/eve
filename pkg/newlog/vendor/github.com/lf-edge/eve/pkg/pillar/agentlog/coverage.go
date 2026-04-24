// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build cover

package agentlog

import (
	"os"
	"runtime/coverage"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// This file is compiled only when the binary is built with -tags cover (i.e.
// COVER=y in the pillar Makefile).
//
// NOTE: Go's binary coverage runtime writes covmeta only via WriteMetaDir
// (or at normal os.Exit); signal termination does NOT flush the meta file.
// We therefore call WriteMetaDir explicitly on each SIGUSR2.

// MaybeInitSigUsr2 sets up a SIGUSR2 handler if !coverage
// This is a no-op with coverage to avoid having two very different actions
// for SIGUSR2
func MaybeInitSigUsr2(sigs chan os.Signal) {
}

// FlushCoverage writes the current in-memory coverage counters to GOCOVERDIR.
// It is a no-op when GOCOVERDIR is unset.
//
// Call this before any operation that bypasses a normal os.Exit, such as
// zboot.Reset or zboot.Poweroff, to ensure coverage data accumulated since
// the last SIGUSR2 snapshot is not lost when the device reboots.
func FlushCoverage(log *base.LogObject) {
	dir := os.Getenv("GOCOVERDIR")
	if dir == "" {
		log.Notice("FlushCoverage: no GOCOVERDIR")
		return
	}
	log.Notice("FlushCoverage")
	if err := coverage.WriteMetaDir(dir); err != nil {
		log.Errorf("FlushCoverage: WriteMetaDir(%s) failed: %v", dir, err)
	}
	if err := coverage.WriteCountersDir(dir); err != nil {
		log.Errorf("FlushCoverage: WriteCountersDir(%s) failed: %v", dir, err)
	}
	syscall.Sync()
}
