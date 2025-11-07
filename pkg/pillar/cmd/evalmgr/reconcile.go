// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// reconcilePartitionStates checks for failed boots and cleans up partition states
// Uses the new FindFailedPartitions() API to detect partitions that failed to boot
func (ctx *evalMgrContext) reconcilePartitionStates() error {
	log.Functionf("Starting partition state reconciliation")

	// Use new API to find failed partitions
	failedPartitions, err := ctx.partitionMgr.FindFailedPartitions()
	if err != nil {
		return fmt.Errorf("failed to detect failed partitions: %w", err)
	}

	if len(failedPartitions) == 0 {
		log.Functionf("No partition reconciliation needed")
		return nil
	}

	// Load current persistent state
	evalState, err := ctx.loadEvalState()
	if err != nil {
		return fmt.Errorf("failed to load eval state: %w", err)
	}

	var reconcileNotes []string

	// Mark each failed partition as bad
	for _, partition := range failedPartitions {
		log.Noticef("Detected failed boot for partition %s", partition)

		// Mark the partition as bad using new API
		if err := ctx.partitionMgr.MarkBad(partition); err != nil {
			log.Errorf("Failed to mark partition %s as bad: %v", partition, err)
			continue
		}

		// Update our persistent state to record the failure
		slot := types.SlotName(partition)
		ctx.updateSlotState(evalState, slot, true, false, "fallback observed - boot failed")

		reconcileNote := fmt.Sprintf("partition %s failed boot, marked bad", partition)
		reconcileNotes = append(reconcileNotes, reconcileNote)

		log.Noticef("Reconciled failed partition %s: marked as bad", partition)
	}

	// Save updated state
	if err := ctx.saveEvalState(evalState); err != nil {
		return fmt.Errorf("failed to save reconciled state: %w", err)
	}

	// Update our context's evaluation status note
	ctx.evalStatus.Note = fmt.Sprintf("Reconciled: %v", reconcileNotes)
	ctx.publishEvalStatus()

	log.Noticef("Partition reconciliation completed: %v", reconcileNotes)
	return nil
}
