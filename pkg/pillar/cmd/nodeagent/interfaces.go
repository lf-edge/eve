// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

// Zboot is the subset of the pillar/zboot package that nodeagent uses.
// Wrapping it as an interface lets tests substitute a stub so they don't
// actually call /sbin/zboot or reset the host.
type Zboot interface {
	EveCurrentPartition() string
	IsCurrentPartitionStateInProgress() bool
	IsValidPartitionLabel(string) bool
	GetValidPartitionLabels() []string
	GetOtherPartition() string
	IsOtherPartitionStateUpdating() bool
	Reset()
	Poweroff()
}

// RebootStore is the subset of pillar/agentlog that nodeagent uses to
// read and write the reboot/boot reason files in /persist. Wrapping it
// lets tests work against in-memory state.
type RebootStore interface {
	GetRebootReason() (reason string, ts time.Time, stack string)
	GetBootReason() (br types.BootReason, ts time.Time)
	GetRebootImage() string
	DiscardRebootReason()
	DiscardBootReason()
	DiscardRebootImage()
	WriteRebootReason(reason string, br types.BootReason,
		agent string, pid int, last bool)
}

// pathConfig holds the on-disk paths nodeagent reads or writes.
// Centralising them makes the agent unit-testable against a t.TempDir().
type pathConfig struct {
	firstbootFile      string
	installLog         string
	installLogSendReq  string
	restartCounterFile string
	faultInjectionFile string
	smartCurrent       string
	smartPrevious      string
}

func defaultPathConfig() pathConfig {
	return pathConfig{
		firstbootFile:      firstbootFile,
		installLog:         installLog,
		installLogSendReq:  installLogSendReq,
		restartCounterFile: restartCounterFile,
		faultInjectionFile: "/persist/fault-injection/readfile",
		smartCurrent:       "/persist/SMART_details.json",
		smartPrevious:      "/persist/SMART_details_previous.json",
	}
}

// realZboot adapts the pillar/zboot package to the Zboot interface.
type realZboot struct{}

func (realZboot) EveCurrentPartition() string { return agentlog.EveCurrentPartition() }
func (realZboot) IsCurrentPartitionStateInProgress() bool {
	return zboot.IsCurrentPartitionStateInProgress()
}
func (realZboot) IsValidPartitionLabel(s string) bool { return zboot.IsValidPartitionLabel(s) }
func (realZboot) GetValidPartitionLabels() []string   { return zboot.GetValidPartitionLabels() }
func (realZboot) GetOtherPartition() string           { return zboot.GetOtherPartition() }
func (realZboot) IsOtherPartitionStateUpdating() bool { return zboot.IsOtherPartitionStateUpdating() }
func (z realZboot) Reset()                            { zboot.Reset(log) }
func (z realZboot) Poweroff()                         { zboot.Poweroff(log) }

// realRebootStore adapts pillar/agentlog to the RebootStore interface.
type realRebootStore struct {
	log *base.LogObject
}

func (r realRebootStore) GetRebootReason() (string, time.Time, string) {
	return agentlog.GetRebootReason(r.log)
}
func (r realRebootStore) GetBootReason() (types.BootReason, time.Time) {
	return agentlog.GetBootReason(r.log)
}
func (r realRebootStore) GetRebootImage() string { return agentlog.GetRebootImage(r.log) }
func (r realRebootStore) DiscardRebootReason()   { agentlog.DiscardRebootReason(r.log) }
func (r realRebootStore) DiscardBootReason()     { agentlog.DiscardBootReason(r.log) }
func (r realRebootStore) DiscardRebootImage()    { agentlog.DiscardRebootImage(r.log) }
func (r realRebootStore) WriteRebootReason(reason string, br types.BootReason,
	agent string, pid int, last bool) {
	agentlog.RebootReason(reason, br, agent, pid, last)
}
