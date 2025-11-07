// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func (ctx *evalMgrContext) initializeScheduler() error {
	log.Functionf("initializeScheduler starting")

	ctx.analyzePreviousBoot()

	// Load state file for audit trail only (timestamps, notes, etc.)
	// Algorithm reconstructs everything from GPT - state file is not needed for logic
	state, err := ctx.loadEvalState()
	if err != nil {
		log.Errorf("Failed to load eval state: %v", err)
		state = ctx.createDefaultEvalState()
	}

	// Determine scheduling state by scanning GPT partition attributes
	// This reconstructs where we are in the evaluation process from GPT
	ctx.updateSchedulingState(state)

	// Reconstruct phase based on scheduler state (which was determined from GPT)
	// Phase is derived from GPT reality, not loaded from state file
	if ctx.schedulerState == SchedulerFinalized {
		ctx.evalStatus.Phase = types.EvalPhaseFinal
		log.Noticef("Reconstructed phase from GPT: Final (all slots tried)")
		// Trigger finalization immediately
		ctx.finalizeEvaluation(state)
	} else {
		// Still in evaluation - check if current slot needs testing
		currentSlotState := ctx.getSlotState(state, ctx.currentSlot)

		if !currentSlotState.Tried {
			// Current partition not yet tested - start stability check immediately
			ctx.evalStatus.Phase = types.EvalPhaseInit
			log.Noticef("Reconstructed phase from GPT: Init (current slot %s not yet tried)", ctx.currentSlot)
			ctx.startStabilityTimer()
		} else {
			// Current partition already tested - shouldn't normally be here
			// This means GRUB booted a fallback partition
			ctx.evalStatus.Phase = types.EvalPhaseInit
			log.Noticef("Reconstructed phase from GPT: Init (running fallback slot %s)", ctx.currentSlot)
		}
	}

	log.Functionf("initializeScheduler completed: schedulerState=%v, phase=%s",
		ctx.schedulerState, ctx.evalStatus.Phase)
	return nil
}

func (ctx *evalMgrContext) analyzePreviousBoot() error {
	prevReason, prevTime, prevStack := ctx.agentLog.GetRebootReason(log)
	if prevReason == "" {
		log.Functionf("No previous reboot reason found")
		return nil
	}

	log.Noticef("Previous reboot reason: %s at %s", prevReason, prevTime.Format(time.RFC3339))

	state, err := ctx.loadEvalState()
	if err != nil {
		log.Errorf("Failed to load state for previous boot analysis: %v", err)
		return err
	}

	analysis := ctx.classifyRebootReason(prevReason, prevStack)
	log.Noticef("Reboot analysis: planned=%t, successful=%t, reason=%s",
		analysis.WasPlanned, analysis.WasSuccessful, analysis.Classification)

	if analysis.WasPlanned {
		if analysis.TargetSlot != "" && analysis.TargetSlot != ctx.currentSlot {
			log.Errorf("Planned switch to slot %s failed, now running %s",
				analysis.TargetSlot, ctx.currentSlot)
			ctx.updateSlotState(state, analysis.TargetSlot, true, false,
				"Boot failed - fallback to "+string(ctx.currentSlot))
		} else {
			log.Noticef("Successful planned reboot to slot %s", ctx.currentSlot)
		}
	} else {
		if !analysis.WasSuccessful {
			log.Errorf("Unplanned reboot detected: %s", analysis.Classification)
			currentState := ctx.getSlotState(state, ctx.currentSlot)
			currentState.Note = fmt.Sprintf("Unplanned reboot: %s", analysis.Classification)
			state.Slots[ctx.currentSlot] = currentState
		}
	}

	if err := ctx.saveEvalState(state); err != nil {
		log.Errorf("Failed to save state after boot analysis: %v", err)
	}

	ctx.agentLog.DiscardRebootReason(log)
	return nil
}

// BootAnalysis contains the results of analyzing a previous boot cycle
type BootAnalysis struct {
	WasPlanned     bool
	WasSuccessful  bool
	Classification string
	TargetSlot     types.SlotName
}

func (ctx *evalMgrContext) classifyRebootReason(reason, stack string) BootAnalysis {
	analysis := BootAnalysis{
		WasPlanned:     false,
		WasSuccessful:  true,
		Classification: "unknown",
	}

	reasonLower := strings.ToLower(reason)

	if strings.Contains(reason, RebootReasonEvalNextSlot) {
		analysis.WasPlanned = true
		analysis.Classification = "planned evaluation slot switch"
		if strings.Contains(reason, "IMGA") {
			analysis.TargetSlot = types.SlotIMGA
		} else if strings.Contains(reason, "IMGB") {
			analysis.TargetSlot = types.SlotIMGB
		} else if strings.Contains(reason, "IMGC") {
			analysis.TargetSlot = types.SlotIMGC
		}
		return analysis
	}

	if strings.Contains(reason, RebootReasonEvalFinalize) {
		analysis.WasPlanned = true
		analysis.Classification = "planned evaluation finalization"
		return analysis
	}

	if strings.Contains(reasonLower, "watchdog") {
		analysis.WasSuccessful = false
		analysis.Classification = "watchdog timeout"
		return analysis
	}

	if strings.Contains(reasonLower, "kernel panic") || strings.Contains(reasonLower, "panic") {
		analysis.WasSuccessful = false
		analysis.Classification = "kernel panic"
		return analysis
	}

	if strings.Contains(reasonLower, "fatal") {
		analysis.WasSuccessful = false
		analysis.Classification = "fatal error"
		return analysis
	}

	if strings.Contains(reasonLower, "power") {
		analysis.Classification = "power failure"
		return analysis
	}

	if strings.Contains(reasonLower, "user") || strings.Contains(reasonLower, "requested") {
		analysis.WasPlanned = true
		analysis.Classification = "user requested"
		return analysis
	}

	if strings.Contains(reasonLower, "baseos") || strings.Contains(reasonLower, "update") {
		analysis.WasPlanned = true
		analysis.Classification = "baseos update"
		return analysis
	}

	analysis.Classification = "unknown"
	return analysis
}

func (ctx *evalMgrContext) updateSchedulingState(state *types.EvalPersist) {
	if state.Phase == types.EvalPhaseFinal {
		ctx.schedulerState = SchedulerFinalized
		log.Noticef("Evaluation already finalized (phase=%s, best_slot=%s)",
			state.Phase, state.BestSlot)
		return
	}

	if !ctx.isEvaluationPlatform {
		// For non-evaluation platforms, check persistent state
		allTried := true
		for _, slot := range types.AllSlots() {
			slotState := ctx.getSlotState(state, slot)
			if !slotState.Tried {
				allTried = false
				break
			}
		}
		if allTried {
			ctx.schedulerState = SchedulerFinalized
			log.Noticef("All slots have been tried - evaluation ready for finalization")
			return
		}
	} else {
		// For evaluation platforms, use GPT as source of truth
		// Scan all partitions to see if any are still untried
		allPartitions := ctx.partitionMgr.GetValidPartitionLabels()

		// Count how many partitions have been tried by checking if they've been marked good or bad
		// A partition is tried if it's been marked good (successful=1) or bad (priority=0)
		allTried := true
		for _, partition := range allPartitions {
			slot := types.SlotName(partition)
			slotState := ctx.getSlotState(state, slot)

			// If we have no record of trying this slot, it's still untried
			// The slot will be marked as tried when we mark it good after stability
			if !slotState.Tried {
				allTried = false
				break
			}
		}

		if allTried {
			ctx.schedulerState = SchedulerFinalized
			log.Noticef("All slots have been tried - evaluation ready for finalization")
			return
		}
	}

	// Not finalized yet, continue with normal scheduling
	ctx.schedulerState = SchedulerIdle
	log.Noticef("updateSchedulingState: evaluation in progress - idle")
}

func (ctx *evalMgrContext) shouldStartStabilityTimer(state *types.EvalPersist) bool {
	if ctx.schedulerState != SchedulerStabilityWait {
		return false
	}

	currentState := ctx.getSlotState(state, ctx.currentSlot)
	// Start timer if current slot is tried but not yet successful
	return currentState.Tried && !currentState.Success
}

// startStabilityTimer begins the stability validation period
func (ctx *evalMgrContext) startStabilityTimer() {
	// Use configured stability period (for testing override)
	if ctx.stabilityPeriod == 0 {
		ctx.stabilityPeriod = StabilityPeriod
	}

	log.Noticef("Starting stability timer for slot %s (period: %v)", ctx.currentSlot, ctx.stabilityPeriod)

	// Update slot state to show testing in progress
	state, err := ctx.loadEvalState()
	if err != nil {
		log.Errorf("Failed to load state for stability timer: %v", err)
	} else {
		ctx.updateSlotState(state, ctx.currentSlot, true, false,
			fmt.Sprintf("Testing - stability check in progress (%v)", ctx.stabilityPeriod))
		if err := ctx.saveEvalState(state); err != nil {
			log.Errorf("Failed to save state after starting stability timer: %v", err)
		}
	}

	// Stop any existing timer
	if ctx.stabilityTimer != nil {
		ctx.stabilityTimer.Stop()
	}

	// Set phase to testing so timing info appears in diag
	ctx.evalStatus.Phase = types.EvalPhaseTesting
	ctx.evalStatus.TestStartTime = time.Now()
	ctx.evalStatus.TestDuration = ctx.stabilityPeriod

	ctx.stabilityTimer = time.NewTimer(ctx.stabilityPeriod)
	ctx.stabilityStartTime = time.Now()
}

// handleStabilityTimeout is called when the stability timer expires
func (ctx *evalMgrContext) handleStabilityTimeout() {
	log.Noticef("Stability period completed for slot %s", ctx.currentSlot)

	// Load current state
	state, err := ctx.loadEvalState()
	if err != nil {
		log.Errorf("Failed to load state for stability timeout: %v", err)
		return
	}

	// Update audit trail: mark current slot as tried and successful
	// Note: GPT is already updated via MarkGood() - this is just for human visibility
	ctx.updateSlotState(state, ctx.currentSlot, true, true,
		fmt.Sprintf("Stable for %v", ctx.stabilityPeriod))

	// Mark current slot as good (downgrades priority from 3→2)
	log.Noticef("Marking slot %s as good after stability validation", ctx.currentSlot)
	if err := ctx.partitionMgr.MarkGood(string(ctx.currentSlot)); err != nil {
		log.Errorf("Failed to mark slot %s as good: %v", ctx.currentSlot, err)
		return
	}
	log.Noticef("Successfully marked slot %s as good", ctx.currentSlot)

	// Save state
	if err := ctx.saveEvalState(state); err != nil {
		log.Errorf("Failed to save state after stability validation: %v", err)
		return
	}

	// Update scheduling state and consider next slot
	ctx.schedulerState = SchedulerIdle
	ctx.scheduleNextSlotIfNeeded(state)

	// Update and publish status
	ctx.updateEvalStatus()
}

// scheduleNextSlotIfNeeded finds and schedules the next untried slot
func (ctx *evalMgrContext) scheduleNextSlotIfNeeded(state *types.EvalPersist) {
	nextSlot := ctx.findNextUntriedSlot(state)
	if nextSlot == types.SlotFinal {
		log.Noticef("No more untried slots - evaluation complete")
		ctx.schedulerState = SchedulerFinalized
		ctx.finalizeEvaluation(state)
		return
	}

	log.Noticef("Scheduling next slot for testing: %s", nextSlot)

	// Note: We do NOT update persistent state for next slot here
	// GPT already knows the boot order via priority cascade
	// The slot will be marked tried in persistent state when we boot into it

	// Save current state before reboot (for audit trail)
	if err := ctx.saveEvalState(state); err != nil {
		log.Errorf("Failed to save state before scheduling: %v", err)
		return
	}

	// Priority cascade handles automatic progression:
	// Current slot (now priority=2) allows GRUB to boot next slot (priority=3)
	log.Noticef("Next slot %s will boot automatically via priority cascade", nextSlot)

	ctx.schedulerState = SchedulerScheduled

	// Request reboot via nodeagent
	reasonStr := RebootReasonEvalNextSlot + "-" + string(nextSlot)
	if err := ctx.requestReboot(reasonStr); err != nil {
		log.Errorf("Failed to request reboot: %v", err)
		return
	}
	log.Noticef("Requested reboot to test slot %s", nextSlot)
}

// findNextUntriedSlot returns the next slot that hasn't been tried yet
//
// Tried tracking philosophy:
// - PRIMARY: Track in state file for convenience during normal operation
// - FALLBACK: Can reconstruct from GPT if state file lost/corrupted:
//   - successful=1 → tried and passed
//   - tries=0 AND priority=0 → tried and failed
//   - tries=1 AND priority=3 → not tried yet (scheduled)
//
// - GPT is always the source of truth, state file mirrors reality
func (ctx *evalMgrContext) findNextUntriedSlot(state *types.EvalPersist) types.SlotName {
	if !ctx.isEvaluationPlatform {
		// For non-evaluation platforms, use simple logic from persistent state
		for _, slot := range types.AllSlots() {
			if slot == ctx.currentSlot {
				continue // Skip current slot
			}
			slotState := ctx.getSlotState(state, slot)
			if !slotState.Tried {
				return slot
			}
		}
		return types.SlotFinal
	}

	// For evaluation platforms, find next untried partition
	// We track tried status in persistent state (which mirrors GPT reality)
	allPartitions := ctx.partitionMgr.GetValidPartitionLabels()

	for _, partition := range allPartitions {
		slot := types.SlotName(partition)
		slotState := ctx.getSlotState(state, slot)

		// Find first partition not yet tried
		if !slotState.Tried {
			log.Functionf("Next untried partition: %s", partition)
			return slot
		}
	}

	// All partitions have been tried
	log.Noticef("All partitions tried - no more slots to test")
	return types.SlotFinal
}

// finalizeEvaluation selects the best slot and finalizes evaluation
func (ctx *evalMgrContext) finalizeEvaluation(state *types.EvalPersist) {
	log.Noticef("Finalizing evaluation - selecting best slot")

	// TODO: Implement inventory collection for scoring
	inventories := make(map[types.SlotName]InventoryData)

	bestSlot := ctx.selectBestSlot(state, inventories)
	log.Noticef("Selected best slot: %s", bestSlot)

	// Update state
	state.BestSlot = bestSlot
	state.Phase = types.EvalPhaseFinal

	// Set best slot to priority=3
	log.Noticef("Setting best slot %s for finalization", bestSlot)
	if err := ctx.partitionMgr.SetBest(string(bestSlot)); err != nil {
		log.Errorf("Failed to set best slot %s: %v", bestSlot, err)
		return
	}

	if bestSlot != ctx.currentSlot {
		log.Noticef("Best slot %s differs from current %s - scheduling switch", bestSlot, ctx.currentSlot)

		// Request reboot to best slot
		reasonStr := RebootReasonEvalFinalize + "-" + string(bestSlot)
		if err := ctx.requestReboot(reasonStr); err != nil {
			log.Errorf("Failed to request reboot to best slot: %v", err)
			return
		}
		log.Noticef("Requested reboot to best slot %s", bestSlot)
	} else {
		log.Noticef("Already running best slot %s - evaluation complete", bestSlot)
		// Update allow onboard since we're finalized
		ctx.evalStatus.Phase = types.EvalPhaseFinal
		ctx.evalStatus.AllowOnboard = true
		ctx.evalStatus.Note = fmt.Sprintf("Evaluation complete - running best slot %s", bestSlot)
	}

	// Save final state
	if err := ctx.saveEvalState(state); err != nil {
		log.Errorf("Failed to save final evaluation state: %v", err)
	}

	// Publish status update so clients see finalization state
	ctx.updateEvalStatus()
}

// InventoryData represents hardware inventory for a slot (placeholder)
type InventoryData struct {
	CPUCount   int
	MemoryMB   int
	DiskCount  int
	NICCount   int
	PCIDevices int
	// TODO: Add more inventory fields
}

// selectBestSlot chooses the best slot based on success and inventory
func (ctx *evalMgrContext) selectBestSlot(state *types.EvalPersist, inventories map[types.SlotName]InventoryData) types.SlotName {
	// TODO: Implement configurable scoring algorithm
	// Priority:
	// 1. Successful slots only
	// 2. Biggest HW inventory (more hardware detected = better)
	// 3. Tie-breaker: "least letter" slot (A > B > C)
	// 4. If inventory sizes equal: prefer earlier slot

	var bestSlot types.SlotName
	var bestScore int

	for _, slot := range types.AllSlots() {
		slotState := ctx.getSlotState(state, slot)
		if !slotState.Success {
			continue // Only consider successful slots
		}

		// Calculate basic score (placeholder algorithm)
		score := 0
		inventory, hasInventory := inventories[slot]
		if hasInventory {
			score = inventory.CPUCount + inventory.DiskCount + inventory.NICCount + inventory.PCIDevices
		}

		// Tie-breaker: prefer earlier slots (A=3, B=2, C=1)
		switch slot {
		case types.SlotIMGA:
			score += 3
		case types.SlotIMGB:
			score += 2
		case types.SlotIMGC:
			score++
		}

		if bestSlot == "" || score > bestScore {
			bestSlot = slot
			bestScore = score
		}

		log.Functionf("Slot %s score: %d (success=%t)", slot, score, slotState.Success)
	}

	// Fallback to current slot if no successful slots found
	if bestSlot == "" {
		log.Warnf("No successful slots found - defaulting to current slot %s", ctx.currentSlot)
		bestSlot = ctx.currentSlot
	}

	return bestSlot
}

// requestReboot requests a system reboot with the given reason after a countdown
func (ctx *evalMgrContext) requestReboot(reason string) error {
	log.Noticef("Scheduling reboot in 15 seconds: %s", reason)

	// Start 15-second countdown
	ctx.rebootCountdown = 15
	ctx.evalStatus.Note = "Rebooting: " + reason

	// Store the reboot reason for later use in executeReboot
	ctx.scheduledRebootReason = reason

	// Update status immediately to show countdown
	ctx.updateTimingFields()
	ctx.publishEvalStatus()

	return nil
}

// executeReboot performs the actual reboot when countdown expires
func (ctx *evalMgrContext) executeReboot() error {
	log.Noticef("Executing direct reboot (nodeagent may not be active before onboarding)")

	// Save reboot reason before rebooting (nodeagent is not available pre-onboarding)
	ctx.agentLog.RebootReason(ctx.scheduledRebootReason, types.BootReasonRebootCmd, "evalmgr", os.Getpid(), true)

	// Sync filesystems before reboot (skip in test mode)
	if !ctx.testMode {
		log.Noticef("Syncing filesystems before reboot")
		syscall.Sync()
	}

	// Direct reboot via zboot (same as nodeagent would do)
	log.Noticef("Calling systemReset.Reset() for reboot, reason: %s", ctx.scheduledRebootReason)
	ctx.systemReset.Reset(log)

	// In production, we never reach here (system reboots)
	// In test mode with mock partition manager, Reset() returns and we should stop cleanly
	log.Noticef("Mock reboot completed successfully")
	return nil
}
