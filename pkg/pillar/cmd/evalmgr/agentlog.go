// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// RealAgentLog implements AgentLogInterface using the real agentlog package
type RealAgentLog struct{}

func (r *RealAgentLog) GetRebootReason(log *base.LogObject) (string, time.Time, string) {
	return agentlog.GetRebootReason(log)
}

func (r *RealAgentLog) RebootReason(reason string, bootReason types.BootReason, agentName string, agentPid int, normal bool) {
	agentlog.RebootReason(reason, bootReason, agentName, agentPid, normal)
}

func (r *RealAgentLog) DiscardRebootReason(log *base.LogObject) {
	agentlog.DiscardRebootReason(log)
}
