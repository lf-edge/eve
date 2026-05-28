// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !k

package mgmtproxy

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
)

const (
	agentName            = "mgmtproxy"
	errorTime            = 3 * time.Minute
	warningTime          = 40 * time.Second
	stillRunningInterval = 25 * time.Second
)

type mgmtProxyContext struct {
	agentbase.AgentBase
}

// Run is a no-op stub for non-k builds. mgmtproxy is only meaningful in EVE-K
// where containerd does its own image pulls; on KVM/Xen images all downloads
// already flow through pillar's cost-aware controllerconn path.
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject,
	arguments []string, baseDir string) int {

	ctx := mgmtProxyContext{}
	agentbase.Init(&ctx, loggerArg, logArg, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithWatchdog(ps, warningTime, errorTime),
		agentbase.WithArguments(arguments))

	tick := time.NewTicker(stillRunningInterval)
	for range tick.C {
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	return 0
}
