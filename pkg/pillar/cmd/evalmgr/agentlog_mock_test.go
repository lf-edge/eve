// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/spf13/afero"
)

// MockAgentLog implements AgentLogInterface for testing with in-memory filesystem
type MockAgentLog struct {
	fs afero.Fs
}

// NewMockAgentLog creates a mock agentlog that uses the provided filesystem
func NewMockAgentLog(fs afero.Fs) *MockAgentLog {
	return &MockAgentLog{fs: fs}
}

func (m *MockAgentLog) GetRebootReason(log *base.LogObject) (string, time.Time, string) {
	reasonFile := filepath.Join(types.PersistDir, "reboot-reason")
	stackFile := filepath.Join(types.PersistDir, "reboot-stack")

	// Read reason file
	reasonBytes, err := afero.ReadFile(m.fs, reasonFile)
	var reason string
	var ts time.Time
	if err == nil && len(reasonBytes) > 0 {
		reason = string(reasonBytes)
		// Get file mod time
		if fi, err := m.fs.Stat(reasonFile); err == nil {
			ts = fi.ModTime()
		}
	}

	// Read stack file
	stackBytes, err := afero.ReadFile(m.fs, stackFile)
	var stack string
	if err == nil {
		stack = string(stackBytes)
	}

	return reason, ts, stack
}

func (m *MockAgentLog) RebootReason(reason string, bootReason types.BootReason, agentName string, agentPid int, normal bool) {
	reasonFile := filepath.Join(types.PersistDir, "reboot-reason")
	bootReasonFile := filepath.Join(types.PersistDir, "boot-reason")

	dateStr := time.Now().Format(time.RFC3339Nano)
	if !normal {
		reason = fmt.Sprintf("Reboot from agent %s[%d] at %s: %s\n",
			agentName, agentPid, dateStr, reason)
	} else {
		reason = fmt.Sprintf("%s at %s\n", reason, dateStr)
	}

	// Check if boot-reason file exists to decide append vs overwrite
	_, err := m.fs.Stat(bootReasonFile)
	if err != nil {
		// boot-reason doesn't exist, so we append to reboot-reason
		// (this is a subsequent reboot reason)
		existing, _ := afero.ReadFile(m.fs, reasonFile)
		afero.WriteFile(m.fs, reasonFile, append(existing, []byte(reason)...), 0644)
	} else {
		// First reboot reason, overwrite
		afero.WriteFile(m.fs, reasonFile, []byte(reason), 0644)
	}

	// Write boot reason
	afero.WriteFile(m.fs, bootReasonFile, []byte(bootReason.String()), 0644)
}

func (m *MockAgentLog) DiscardRebootReason(log *base.LogObject) {
	reasonFile := filepath.Join(types.PersistDir, "reboot-reason")
	stackFile := filepath.Join(types.PersistDir, "reboot-stack")
	bootReasonFile := filepath.Join(types.PersistDir, "boot-reason")

	m.fs.Remove(reasonFile)
	m.fs.Remove(stackFile)
	m.fs.Remove(bootReasonFile)
}
