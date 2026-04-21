// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build cover

package main

// This file is compiled only when the binary is built with -tags cover (i.e.
// COVER=y in the pillar Makefile).  It wires up two things:
//
//  1. Sets GOCOVERDIR so that Go's binary coverage instrumentation
//     (go build -cover -covermode=atomic) knows where to write data.
//     If GOCOVERDIR is already set in the environment (e.g. for testing on
//     the host), that value is preserved; otherwise it defaults to
//     types.CoverageDir on the EVE persistent partition.
//
//  2. Installs a SIGUSR2 handler that calls runtime/coverage.WriteMetaDir
//     and runtime/coverage.WriteCountersDir to dump a live snapshot of
//     coverage data *without* terminating the process.  Eden uses this
//     signal after the end-to-end test suite finishes to collect coverage
//     from all running zedbox agents.
//
// NOTE: Go's binary coverage runtime writes covmeta only via WriteMetaDir
// (or at normal os.Exit); signal termination does NOT flush the meta file.
// We therefore call WriteMetaDir explicitly on both startup and each SIGUSR2.

import (
	"os"
	"os/signal"
	"runtime/coverage"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func init() {
	// Use GOCOVERDIR from the environment if already set (e.g. host testing),
	// otherwise default to the EVE persistent coverage directory.
	dir := os.Getenv("GOCOVERDIR")
	if dir == "" {
		dir = types.CoverageDir
		if err := os.MkdirAll(dir, 0755); err != nil {
			return
		}
		_ = os.Setenv("GOCOVERDIR", dir)
	}

	// Install a SIGUSR2 handler so Eden can trigger a live coverage snapshot
	// at any point during a test run without killing the process.
	// WriteMetaDir is called first so go tool covdata textfmt can find the
	// covmeta.* file alongside the covcounters.* files.
	go func() {
		// Write meta once at startup so it is present even if the process
		// is later killed before a clean os.Exit.
		_ = coverage.WriteMetaDir(dir)

		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGUSR2)
		for range c {
			_ = coverage.WriteMetaDir(dir)
			_ = coverage.WriteCountersDir(dir)
		}
	}()
}
