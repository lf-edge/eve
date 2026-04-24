// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !cover

package agentlog

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// MaybeInitSigUsr2 sets up a SIGUSR2 handler if !coverage
func MaybeInitSigUsr2(sigs chan os.Signal) {
	signal.Notify(sigs, syscall.SIGUSR2)
}

// FlushCoverage is a no-op in non-coverage builds.
func FlushCoverage(_ *base.LogObject) {}
