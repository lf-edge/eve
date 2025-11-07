// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// SchedulerState tracks the current scheduling state
type SchedulerState int

const (
	// SchedulerIdle - no active scheduling
	SchedulerIdle SchedulerState = iota
	// SchedulerStabilityWait - waiting for current slot to prove stable
	SchedulerStabilityWait
	// SchedulerScheduled - next slot scheduled, waiting for reboot
	SchedulerScheduled
	// SchedulerFinalized - evaluation complete, best slot selected
	SchedulerFinalized
)

// String returns the string representation of SchedulerState
func (s SchedulerState) String() string {
	switch s {
	case SchedulerIdle:
		return "idle"
	case SchedulerStabilityWait:
		return "stability_wait"
	case SchedulerScheduled:
		return "scheduled"
	case SchedulerFinalized:
		return "finalized"
	default:
		return "unknown"
	}
}

// Constants for stability period and reboot reasons
const (
	// StabilityPeriod is how long we wait to consider a slot stable
	StabilityPeriod = 15 * time.Minute
	// RebootReasonEvalNextSlot is the reason we write when switching to next slot
	RebootReasonEvalNextSlot = "evaluation-next-slot"
	// RebootReasonEvalFinalize is the reason when switching to best slot
	RebootReasonEvalFinalize = "evaluation-finalize"
)

// PartitionManagerInterface abstracts partition management operations for Evaluation EVE
// This interface provides high-level operations for the evaluation workflow:
// - All partitions start as "scheduled" (0x013: priority=3, tries=1, successful=0)
// - After testing, partitions are marked "good" (0x102: priority=2, successful=1)
// - Failed partitions are marked "bad" (0x000: all zeros)
// - Final best partition is marked "best" (0x103: priority=3, successful=1)
// PartitionManagerInterface manages partition attributes and state transitions
// Used for GPT partition attribute manipulation (priority, tries, successful bits)
type PartitionManagerInterface interface {
	// === Query Operations ===

	// GetCurrentPartition returns the currently booted partition label (e.g., "IMGA")
	GetCurrentPartition() string

	// GetValidPartitionLabels returns all valid partition labels for this platform
	// For evaluation platforms: ["IMGA", "IMGB", "IMGC"]
	// For standard platforms: ["IMGA", "IMGB"]
	GetValidPartitionLabels() []string

	// === Evaluation Workflow Operations ===

	// MarkGood marks a partition as successfully tested and stable
	// Use after: stability timer passes for current partition
	// Effect: scheduled (0x013) or inprogress (0x003) → good (0x102)
	//         Sets priority=2, tries=0, successful=1
	// Result: Partition becomes fallback, next untested partition boots automatically
	MarkGood(partition string) error

	// MarkBad marks a partition as failed and unusable
	// Use when: partition found in inprogress state but we booted from different partition
	// Effect: inprogress (0x003) → bad (0x000)
	//         Sets priority=0, tries=0, successful=0
	// Result: GRUB will never boot this partition
	MarkBad(partition string) error

	// SetBest marks a partition as the final chosen partition
	// Use when: all partitions tested, selected best based on inventory
	// Effect: good (0x102) → best (0x103)
	//         Sets priority=3, tries=0, successful=1
	// Result: Partition becomes primary boot target with highest priority
	SetBest(partition string) error

	// FindFailedPartitions detects partitions that failed to boot
	// Returns: list of partition labels in inprogress state that are not current partition
	// These should be marked bad by caller
	FindFailedPartitions() ([]string, error)
}

// SystemResetInterface handles system reboot operations
// Separate interface because system reset is a different concern than partition management
// Production implementation uses Zboot, test implementation simulates reboot
type SystemResetInterface interface {
	// Reset triggers a system reboot
	// Production: calls actual system reboot (zboot)
	// Tests: signals mock to stop run() loop and simulate reboot
	Reset(log *base.LogObject)
}

// GptAttributeAccess defines the low-level interface for reading/writing GPT partition attributes
// This interface abstracts the underlying access mechanism (cgpt on real hardware, in-memory for tests)
// Implementations should only handle primitive operations - no business logic!
type GptAttributeAccess interface {
	// GetPartitionAttributes reads the raw GPT attribute value for a partition
	// Returns the 16-bit attribute value as stored in GPT
	// Bit layout: bits 0-3=priority, bits 4-7=tries, bit 8=successful
	GetPartitionAttributes(partition string) (uint16, error)

	// SetPartitionAttributes writes the raw GPT attribute value for a partition
	// The attr parameter is a 16-bit value with encoded priority, tries, and successful bits
	SetPartitionAttributes(partition string, attr uint16) error

	// GetCurrentPartition returns the label of the currently booted partition
	GetCurrentPartition() string

	// GetValidPartitionLabels returns all valid partition labels for this platform
	// For evaluation EVE: returns ["IMGA", "IMGB", "IMGC"]
	// For regular EVE: returns ["IMGA", "IMGB"]
	GetValidPartitionLabels() []string
}

// AgentLogInterface defines the interface for agentlog operations
// This allows us to mock agentlog in tests
type AgentLogInterface interface {
	GetRebootReason(log *base.LogObject) (string, time.Time, string)
	RebootReason(reason string, bootReason types.BootReason, agentName string, agentPid int, normal bool)
	DiscardRebootReason(log *base.LogObject)
}
