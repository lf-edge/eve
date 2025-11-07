// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// State file philosophy:
//
// SOURCE OF TRUTH (for algorithm): GPT partition attributes
//   - Algorithm reads partition states from GPT via partition manager
//   - "Tried" status determined by GPT attributes (successful=1 or tries=0)
//   - Boot order determined by GRUB reading GPT priorities
//
// AUDIT TRAIL (for humans): /persist/eval/state.json
//   - Saved for human visibility and debugging
//   - Contains timestamps, notes, reboot reasons, best slot selection
//   - NOT used for control flow or algorithm decisions
//   - Helps operators understand what the algorithm did
//
// This design ensures:
//   - GPT and algorithm state never diverge (single source of truth)
//   - System can reconstruct state from GPT after power loss
//   - JSON provides clear audit trail for troubleshooting

package evalmgr

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/spf13/afero"
)

var (
	// EvalStateDir is the directory where evaluation state is persisted
	EvalStateDir = "/persist/eval"
	// EvalStateFile is the main state file
	EvalStateFile = "/persist/eval/state.json"
)

// loadEvalState loads the persistent evaluation state from disk
func (ctx *evalMgrContext) loadEvalState() (*types.EvalPersist, error) {
	// Ensure directory exists
	if err := ctx.fs.MkdirAll(EvalStateDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create eval state directory: %w", err)
	}

	data, err := afero.ReadFile(ctx.fs, EvalStateFile)
	if err != nil {
		if _, statErr := ctx.fs.Stat(EvalStateFile); statErr != nil {
			// First time - create default state
			log.Functionf("No existing eval state found, creating default")
			return ctx.createDefaultEvalState(), nil
		}
		return nil, fmt.Errorf("failed to read eval state: %w", err)
	}

	var state types.EvalPersist
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to parse eval state: %w", err)
	}

	log.Functionf("Loaded eval state: phase=%s, slots=%d", state.Phase, len(state.Slots))
	return &state, nil
}

// saveEvalState saves the current evaluation state to disk
func (ctx *evalMgrContext) saveEvalState(state *types.EvalPersist) error {
	// Update timestamp
	state.LastUpdated = time.Now()

	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal eval state: %w", err)
	}

	// Atomic write using temporary file
	tmpFile := EvalStateFile + ".tmp"
	if err := afero.WriteFile(ctx.fs, tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temporary eval state: %w", err)
	}

	if err := ctx.fs.Rename(tmpFile, EvalStateFile); err != nil {
		return fmt.Errorf("failed to rename eval state file: %w", err)
	}

	log.Functionf("Saved eval state: phase=%s, best_slot=%s", state.Phase, state.BestSlot)
	return nil
}

// createDefaultEvalState creates a new default evaluation state
func (ctx *evalMgrContext) createDefaultEvalState() *types.EvalPersist {
	state := &types.EvalPersist{
		Slots:       make(map[types.SlotName]types.SlotEvalState),
		Phase:       types.EvalPhaseInit,
		LastUpdated: time.Now(),
	}

	// Initialize all slots as untried
	// Note: Even current slot is not marked as tried yet - that happens after stability test passes
	for _, slot := range types.AllSlots() {
		state.Slots[slot] = types.SlotEvalState{
			Tried:   false,
			Success: false,
			Note:    "Not yet attempted",
		}
		if slot == ctx.currentSlot {
			state.Slots[slot] = types.SlotEvalState{
				Tried:       false, // Will be marked true after stability test
				Success:     false,
				Note:        "Currently running - evaluating stability",
				AttemptTime: time.Now(),
			}
			log.Functionf("Current slot %s initialized as untried in default state", slot)
		}
	}

	log.Functionf("Created default eval state with %d slots", len(state.Slots))
	return state
}

// updateSlotState updates the state for a specific slot
func (ctx *evalMgrContext) updateSlotState(state *types.EvalPersist, slot types.SlotName, tried bool, success bool, note string) {
	slotState := state.Slots[slot]
	slotState.Tried = tried
	slotState.Success = success
	slotState.Note = note
	slotState.AttemptTime = time.Now()
	state.Slots[slot] = slotState

	log.Functionf("Updated slot %s state: tried=%t, success=%t, note=%s",
		slot, tried, success, note)
}

// getSlotState gets the current state for a specific slot
func (ctx *evalMgrContext) getSlotState(state *types.EvalPersist, slot types.SlotName) types.SlotEvalState {
	if slotState, exists := state.Slots[slot]; exists {
		return slotState
	}
	// Return default state if not found
	return types.SlotEvalState{
		Tried:   false,
		Success: false,
		Note:    "Unknown state",
	}
}

// archiveEvalState creates a backup of the current state before major changes
func (ctx *evalMgrContext) archiveEvalState() error {
	if _, err := ctx.fs.Stat(EvalStateFile); err != nil {
		// No state file to archive
		return nil
	}

	timestamp := time.Now().Format("20060102-150405")
	archiveFile := filepath.Join(EvalStateDir, fmt.Sprintf("state-archive-%s.json", timestamp))

	// Copy current state to archive
	data, err := afero.ReadFile(ctx.fs, EvalStateFile)
	if err != nil {
		return fmt.Errorf("failed to read state for archiving: %w", err)
	}

	if err := afero.WriteFile(ctx.fs, archiveFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write archive: %w", err)
	}

	log.Functionf("Archived eval state to %s", archiveFile)
	return nil
}

// cleanupOldArchives removes old archive files to prevent disk space issues
func (ctx *evalMgrContext) cleanupOldArchives() error {
	entries, err := os.ReadDir(EvalStateDir)
	if err != nil {
		return fmt.Errorf("failed to read eval state directory: %w", err)
	}

	var archiveFiles []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) > 13 && name[:13] == "state-archive" && name[len(name)-5:] == ".json" {
			archiveFiles = append(archiveFiles, entry)
		}
	}

	// Keep only the most recent 10 archives
	if len(archiveFiles) > 10 {
		for i := 0; i < len(archiveFiles)-10; i++ {
			archiveFile := filepath.Join(EvalStateDir, archiveFiles[i].Name())
			if err := os.Remove(archiveFile); err != nil {
				log.Errorf("Failed to remove old archive %s: %v", archiveFile, err)
			} else {
				log.Functionf("Removed old archive %s", archiveFiles[i].Name())
			}
		}
	}

	return nil
}
