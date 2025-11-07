// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"fmt"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/spf13/afero"
)

const (
	// AllowOnboardOverrideFile allows manual override of onboarding gate
	AllowOnboardOverrideFile = "/persist/eval/allow_onboard"
)

// initializeEvaluation performs initial evaluation setup for evaluation platforms
// Note: This function assumes ctx.isEvaluationPlatform is already set and true
func (ctx *evalMgrContext) initializeEvaluation() error {
	log.Functionf("initializeEvaluation starting")

	// Get current partition
	currentPartStr := ctx.partitionMgr.GetCurrentPartition()
	ctx.currentSlot = types.SlotName(currentPartStr)
	log.Noticef("Current partition: %s", ctx.currentSlot)

	// Perform partition state reconciliation
	log.Functionf("Performing partition state reconciliation")
	if err := ctx.reconcilePartitionStates(); err != nil {
		log.Errorf("Partition reconciliation failed: %v", err)
	}

	// Load persistent state to restore phase before creating evalStatus
	initialPhase := types.EvalPhaseInit
	state, err := ctx.loadEvalState()
	if err != nil {
		log.Warnf("Could not load persistent state during init: %v - using default phase", err)
	} else {
		initialPhase = state.Phase
		log.Noticef("Restored phase from persistent state: %s", initialPhase)
	}

	allowOnboard := ctx.shouldAllowOnboard()
	statusNote := ctx.generateStatusNote()

	log.Noticef("initializeEvaluation: platform=%t, slot=%s, phase=%s, allowOnboard=%t",
		ctx.isEvaluationPlatform, ctx.currentSlot, initialPhase, allowOnboard)

	ctx.evalStatus = types.EvalStatus{
		IsEvaluationPlatform: true, // This function only called for eval platforms
		CurrentSlot:          ctx.currentSlot,
		Phase:                initialPhase,
		AllowOnboard:         allowOnboard,
		Note:                 statusNote,
		LastUpdated:          time.Now(),
		InventoryCollected:   false, // Will be set after inventory collection
		InventoryDir:         "",    // Will be set after inventory collection
	}

	log.Functionf("initializeEvaluation completed")
	return nil
}

// shouldAllowOnboard determines if onboarding should be allowed
func (ctx *evalMgrContext) shouldAllowOnboard() bool {
	if !ctx.isEvaluationPlatform {
		log.Noticef("shouldAllowOnboard: not evaluation platform - allowing onboarding")
		return true
	}

	if ctx.hasOnboardOverride() {
		log.Noticef("shouldAllowOnboard: manual override file present - allowing onboarding")
		return true
	}

	// Check phase before scheduler state (works even during initialization)
	if ctx.evalStatus.Phase == types.EvalPhaseFinal {
		log.Noticef("shouldAllowOnboard: phase is final - allowing onboarding")
		return true
	}

	switch ctx.schedulerState {
	case SchedulerFinalized:
		log.Noticef("shouldAllowOnboard: scheduler finalized - allowing onboarding")
		return true
	case SchedulerIdle, SchedulerStabilityWait, SchedulerScheduled:
		log.Noticef("shouldAllowOnboard: scheduler state %v - blocking onboarding", ctx.schedulerState)
		return false
	default:
		log.Warnf("shouldAllowOnboard: unknown scheduler state %v - blocking onboarding", ctx.schedulerState)
		return false
	}
}

// hasOnboardOverride checks if manual onboard override is set
func (ctx *evalMgrContext) hasOnboardOverride() bool {
	content, err := afero.ReadFile(ctx.fs, AllowOnboardOverrideFile)
	if err != nil {
		log.Functionf("hasOnboardOverride: %s not found or unreadable: %v", AllowOnboardOverrideFile, err)
		return false
	}

	value := strings.TrimSpace(string(content))
	result := value == "1" || strings.ToLower(value) == "true" || strings.ToLower(value) == "yes"
	log.Noticef("hasOnboardOverride: file content='%s' -> override=%t", value, result)
	return result
}

func (ctx *evalMgrContext) generateStatusNote() string {
	if !ctx.isEvaluationPlatform {
		return "Normal platform, evaluation disabled"
	}

	var notes []string
	notes = append(notes, fmt.Sprintf("Slot %s", ctx.currentSlot))

	// Partition state is now managed by partition manager
	notes = append(notes, "state=managed")
	switch ctx.schedulerState {
	case SchedulerIdle:
		notes = append(notes, "scheduler idle")
	case SchedulerStabilityWait:
		if !ctx.stabilityStartTime.IsZero() {
			elapsed := time.Since(ctx.stabilityStartTime)
			notes = append(notes, fmt.Sprintf("stability check (%v)", elapsed.Truncate(time.Second)))
		} else {
			notes = append(notes, "stability check")
		}
	case SchedulerScheduled:
		notes = append(notes, "next slot scheduled")
	case SchedulerFinalized:
		notes = append(notes, "evaluation complete")
	}

	if ctx.shouldAllowOnboard() {
		notes = append(notes, "onboard allowed")
	} else {
		notes = append(notes, "onboard blocked")
	}

	return strings.Join(notes, ", ")
}

func (ctx *evalMgrContext) publishEvalStatus() {
	log.Functionf("Publishing EvalStatus: phase=%s, slot=%s, allowOnboard=%t",
		ctx.evalStatus.Phase, ctx.evalStatus.CurrentSlot, ctx.evalStatus.AllowOnboard)

	if err := ctx.pubEvalStatus.Publish(ctx.evalStatus.Key(), ctx.evalStatus); err != nil {
		log.Errorf("Failed to publish EvalStatus: %v", err)
	} else {
		log.Noticef("Published EvalStatus: %s", ctx.evalStatus.DetailedNote())
	}
}

func (ctx *evalMgrContext) updateEvalStatus() {
	oldStatus := ctx.evalStatus

	ctx.evalStatus.AllowOnboard = ctx.shouldAllowOnboard()
	ctx.evalStatus.Note = ctx.generateStatusNote()
	ctx.evalStatus.LastUpdated = time.Now()
	ctx.evalStatus.InventoryCollected = ctx.inventoryCollected
	ctx.evalStatus.InventoryDir = ctx.inventoryDir

	if oldStatus.AllowOnboard != ctx.evalStatus.AllowOnboard ||
		oldStatus.Note != ctx.evalStatus.Note ||
		oldStatus.Phase != ctx.evalStatus.Phase ||
		oldStatus.InventoryCollected != ctx.evalStatus.InventoryCollected {
		ctx.publishEvalStatus()
	}
}
