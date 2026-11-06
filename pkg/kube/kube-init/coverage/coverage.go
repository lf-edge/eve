// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build cover

// Package coverage wires kube-init into Go binary coverage (COVER=y builds,
// go build -cover -tags cover), mirroring pkg/pillar/agentlog/coverage.go.
//
// On start it installs a SIGUSR2 handler that dumps a live snapshot to
// GOCOVERDIR without stopping the daemon, then creates Marker so collectors
// (evetest) can tell this kube-init supports flushing. Flush must be called
// before any exit that bypasses a normal return from main, e.g. a reboot.
package coverage

import (
	"log"
	"os"
	"os/signal"
	"runtime/coverage"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// Marker exists while this kube-init can flush coverage on SIGUSR2.
const Marker = "/run/kube-init-cover"

func init() {
	if os.Getenv("GOCOVERDIR") == "" {
		if err := os.MkdirAll(types.CoverageDir, 0755); err != nil {
			return
		}
		_ = os.Setenv("GOCOVERDIR", types.CoverageDir)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR2)
	go func() {
		// covmeta is written only by WriteMetaDir or at normal exit.
		Flush()
		_ = os.WriteFile(Marker, nil, 0644)
		for range c {
			Flush()
		}
	}()
}

// Flush writes the current coverage meta and counters to GOCOVERDIR.
func Flush() {
	dir := os.Getenv("GOCOVERDIR")
	if dir == "" {
		return
	}
	if err := coverage.WriteMetaDir(dir); err != nil {
		log.Printf("coverage: WriteMetaDir(%s): %v", dir, err)
	}
	if err := coverage.WriteCountersDir(dir); err != nil {
		log.Printf("coverage: WriteCountersDir(%s): %v", dir, err)
	}
	syscall.Sync()
}
