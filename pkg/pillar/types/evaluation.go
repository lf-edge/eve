// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

// EvalPhase represents the current phase of evaluation
type EvalPhase string

const (
	// EvalPhaseInit - Initial phase, evaluation manager starting up
	EvalPhaseInit EvalPhase = "init"
	// EvalPhaseTesting - Currently testing slots one by one
	EvalPhaseTesting EvalPhase = "testing"
	// EvalPhaseFinal - Evaluation complete, best slot selected and running
	EvalPhaseFinal EvalPhase = "final"
)

// SlotName represents a partition slot name
type SlotName string

const (
	// SlotIMGA - Image A partition
	SlotIMGA SlotName = "IMGA"
	// SlotIMGB - Image B partition
	SlotIMGB SlotName = "IMGB"
	// SlotIMGC - Image C partition
	SlotIMGC SlotName = "IMGC"
	// SlotFinal - Special value indicating no more slots to test (evaluation complete)
	SlotFinal SlotName = "FINAL"
)

// AllSlots returns all valid slot names
func AllSlots() []SlotName {
	return []SlotName{SlotIMGA, SlotIMGB, SlotIMGC}
}

// SlotEvalState tracks the evaluation state of a single slot
type SlotEvalState struct {
	// Tried indicates if this slot has been attempted to boot
	Tried bool `json:"tried"`
	// Success indicates if the slot booted successfully
	Success bool `json:"success"`
	// Note contains additional information about this slot's evaluation
	Note string `json:"note,omitempty"`
	// AttemptTime when this slot was last attempted
	AttemptTime time.Time `json:"attempt_time,omitempty"`
}

// EvalPersist represents the persistent state stored in /persist/eval/state.json
type EvalPersist struct {
	// Slots maps slot names to their evaluation state
	Slots map[SlotName]SlotEvalState `json:"slots"`
	// BestSlot is the slot determined to be the best after evaluation
	BestSlot SlotName `json:"best_slot,omitempty"`
	// Phase tracks the current evaluation phase
	Phase EvalPhase `json:"phase"`
	// LastUpdated timestamp of last state update
	LastUpdated time.Time `json:"last_updated"`
}

// EvalStatus is published by evalmgr to communicate evaluation state
type EvalStatus struct {
	// IsEvaluationPlatform indicates if this is an evaluation device
	IsEvaluationPlatform bool
	// CurrentSlot is the currently booted slot
	CurrentSlot SlotName
	// Phase is the current evaluation phase
	Phase EvalPhase
	// AllowOnboard gates whether onboarding should proceed
	AllowOnboard bool
	// Note contains human-readable status information
	Note string
	// LastUpdated timestamp when this status was last updated
	LastUpdated time.Time
	// TestStartTime when current test phase started
	TestStartTime time.Time
	// TestDuration total duration for current test phase
	TestDuration time.Duration
	// RebootCountdown seconds until reboot (0 if no reboot pending)
	RebootCountdown int
	// InventoryCollected indicates if hardware inventory was collected for current slot
	InventoryCollected bool
	// InventoryDir is the directory path where inventory was stored (empty if not collected)
	InventoryDir string
}

// Key returns the key for pubsub (single instance)
func (status EvalStatus) Key() string {
	return "evalmgr"
}

// LogCreate logs the creation of EvalStatus
func (status EvalStatus) LogCreate(logBase *base.LogObject) {
	logObject := base.NewLogObject(logBase, base.EvalStatusLogType, "",
		nilUUID, status.LogKey())
	if logObject == nil {
		return
	}
	logObject.CloneAndAddField("is-evaluation", status.IsEvaluationPlatform).
		AddField("current-slot", string(status.CurrentSlot)).
		AddField("phase", string(status.Phase)).
		AddField("allow-onboard", status.AllowOnboard).
		AddField("note", status.Note).
		AddField("test-duration", status.TestDuration).
		AddField("reboot-countdown", status.RebootCountdown).
		Noticef("EvalStatus create")
}

// LogModify logs modifications to EvalStatus
func (status EvalStatus) LogModify(logBase *base.LogObject, old interface{}) {
	logObject := base.EnsureLogObject(logBase, base.EvalStatusLogType, "",
		nilUUID, status.LogKey())

	oldStatus, ok := old.(EvalStatus)
	if !ok {
		logObject.Clone().Fatalf("LogModify: Old object interface passed is not of EvalStatus type")
	}

	// Log changes to key fields
	if oldStatus.Phase != status.Phase ||
		oldStatus.AllowOnboard != status.AllowOnboard ||
		oldStatus.CurrentSlot != status.CurrentSlot {

		logObject.CloneAndAddField("phase", string(status.Phase)).
			AddField("old-phase", string(oldStatus.Phase)).
			AddField("allow-onboard", status.AllowOnboard).
			AddField("old-allow-onboard", oldStatus.AllowOnboard).
			AddField("current-slot", string(status.CurrentSlot)).
			AddField("old-current-slot", string(oldStatus.CurrentSlot)).
			AddField("note", status.Note).
			Noticef("EvalStatus modify")
	}
}

// LogDelete logs the deletion of EvalStatus
func (status EvalStatus) LogDelete(logBase *base.LogObject) {
	logObject := base.EnsureLogObject(logBase, base.EvalStatusLogType, "",
		nilUUID, status.LogKey())
	logObject.CloneAndAddField("phase", string(status.Phase)).
		AddField("allow-onboard", status.AllowOnboard).
		Noticef("EvalStatus delete")

	base.DeleteLogObject(logBase, status.LogKey())
}

// LogKey returns the log key for EvalStatus
func (status EvalStatus) LogKey() string {
	return string(base.EvalStatusLogType) + "-evalmgr"
}

// IsOnboardingAllowed returns whether onboarding should be allowed based on the current evaluation status.
// This method encapsulates the logic for determining onboarding permission based on multiple internal states.
func (status EvalStatus) IsOnboardingAllowed() bool {
	// If not an evaluation platform, always allow onboarding
	if !status.IsEvaluationPlatform {
		return true
	}

	// For evaluation platforms, check multiple conditions:

	// 1. Explicit AllowOnboard flag (primary control)
	if !status.AllowOnboard {
		return false
	}

	// 2. Phase-based logic - don't allow onboarding during active testing
	switch status.Phase {
	case EvalPhaseInit:
		// During init phase, allow if explicitly permitted
		return status.AllowOnboard
	case EvalPhaseTesting:
		// During testing phase, be more restrictive
		// Only allow if explicitly set (for manual overrides)
		return status.AllowOnboard
	case EvalPhaseFinal:
		// Final phase - evaluation complete, allow onboarding
		return true
	default:
		// Unknown phase - be conservative
		return false
	}
}

// OnboardingBlockReason returns a human-readable reason why onboarding is blocked.
// Returns empty string if onboarding is allowed.
func (status EvalStatus) OnboardingBlockReason() string {
	// If not an evaluation platform, always allow onboarding
	if !status.IsEvaluationPlatform {
		return ""
	}

	// Check if onboarding is allowed first
	if status.IsOnboardingAllowed() {
		return ""
	}

	// Provide specific reasons based on state
	if !status.AllowOnboard {
		switch status.Phase {
		case EvalPhaseInit:
			return "evaluation platform initializing"
		case EvalPhaseTesting:
			return "evaluation platform testing in progress"
		case EvalPhaseFinal:
			return "evaluation complete but onboarding explicitly disabled"
		default:
			return "evaluation platform not ready"
		}
	}

	// Phase-based restrictions
	switch status.Phase {
	case EvalPhaseTesting:
		return "evaluation testing in progress"
	default:
		return "evaluation platform in unknown state"
	}
}

// RemainingTime returns the remaining time for current test phase
func (status EvalStatus) RemainingTime() time.Duration {
	if status.TestStartTime.IsZero() || status.TestDuration == 0 {
		return 0
	}
	elapsed := time.Since(status.TestStartTime)
	if elapsed >= status.TestDuration {
		return 0
	}
	return status.TestDuration - elapsed
}

// ElapsedTime returns elapsed time since test started
func (status EvalStatus) ElapsedTime() time.Duration {
	if status.TestStartTime.IsZero() {
		return 0
	}
	return time.Since(status.TestStartTime)
}

// ProgressPercent returns test progress as percentage (0-100)
func (status EvalStatus) ProgressPercent() int {
	if status.TestDuration == 0 {
		return 0
	}
	elapsed := status.ElapsedTime()
	if elapsed >= status.TestDuration {
		return 100
	}
	return int((elapsed * 100) / status.TestDuration)
}

// TimeStatusString returns human-readable time status
func (status EvalStatus) TimeStatusString() string {
	if status.Phase != EvalPhaseTesting {
		return ""
	}

	remaining := status.RemainingTime()
	elapsed := status.ElapsedTime()
	progress := status.ProgressPercent()

	if remaining == 0 {
		return fmt.Sprintf("Test complete (%v elapsed)", elapsed.Round(time.Second))
	}

	return fmt.Sprintf("Progress %d%% (%v/%v remaining: %v)",
		progress,
		elapsed.Round(time.Second),
		status.TestDuration.Round(time.Second),
		remaining.Round(time.Second))
}

// RebootStatusString returns reboot countdown status
func (status EvalStatus) RebootStatusString() string {
	if status.RebootCountdown <= 0 {
		return ""
	}
	return fmt.Sprintf("Requesting reboot in %d sec", status.RebootCountdown)
}

// DetailedNote returns comprehensive status with timing info
func (status EvalStatus) DetailedNote() string {
	parts := []string{status.Note}

	if timeStatus := status.TimeStatusString(); timeStatus != "" {
		parts = append(parts, timeStatus)
	}

	if rebootStatus := status.RebootStatusString(); rebootStatus != "" {
		parts = append(parts, rebootStatus)
	}

	if status.InventoryCollected && status.InventoryDir != "" {
		parts = append(parts, fmt.Sprintf("inventory=%s", status.InventoryDir))
	}

	return strings.Join(parts, "; ")
}
