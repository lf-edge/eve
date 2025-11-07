// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"fmt"
)

// Compile-time check that PartitionManager implements PartitionManagerInterface
var _ PartitionManagerInterface = (*PartitionManager)(nil)

// PartitionManager implements partition management business logic
// It uses GptAttributeAccess interface for low-level operations
// All business logic is here - implementations only handle data access
type PartitionManager struct {
	store    GptAttributeAccess
	agentLog AgentLogInterface
}

// NewPartitionManager creates a partition manager with the given attribute store
// NewPartitionManager creates a new PartitionManager with the given GPT accessor and logger
func NewPartitionManager(store GptAttributeAccess, agentLog AgentLogInterface) *PartitionManager {
	return &PartitionManager{
		store:    store,
		agentLog: agentLog,
	}
}

// GetCurrentPartition returns the currently booted partition label
func (pm *PartitionManager) GetCurrentPartition() string {
	return pm.store.GetCurrentPartition()
}

// GetValidPartitionLabels returns all valid partition labels for this platform
func (pm *PartitionManager) GetValidPartitionLabels() []string {
	return pm.store.GetValidPartitionLabels()
}

// MarkGood marks a partition as successfully tested
// Effect: 0x013 or 0x003 → 0x102 (priority=2, tries=0, successful=1)
// This is idempotent - calling it on an already-good partition is a no-op
func (pm *PartitionManager) MarkGood(partition string) error {
	// Read current attributes
	attr, err := pm.store.GetPartitionAttributes(partition)
	if err != nil {
		return fmt.Errorf("failed to read attributes for %s: %w", partition, err)
	}

	// Check if already good (0x102)
	if attr == 0x102 {
		log.Noticef("Partition %s already marked good, no change needed", partition)
		return nil
	}

	// Set to good state: priority=2, tries=0, successful=1 (0x102)
	err = pm.store.SetPartitionAttributes(partition, 0x102)
	if err != nil {
		return fmt.Errorf("failed to mark %s as good: %w", partition, err)
	}

	log.Noticef("Marked partition %s as good (0x102)", partition)
	return nil
}

// MarkBad marks a partition as bad/failed
// Effect: any → 0x000 (priority=0, tries=0, successful=0)
// This removes the partition from the boot order completely
func (pm *PartitionManager) MarkBad(partition string) error {
	// Set to bad state: all zeros (0x000)
	err := pm.store.SetPartitionAttributes(partition, 0x000)
	if err != nil {
		return fmt.Errorf("failed to mark %s as bad: %w", partition, err)
	}

	log.Noticef("Marked partition %s as bad (0x000)", partition)
	return nil
}

// SetBest marks a partition as the best/finalized partition
// Effect: 0x102 → 0x103 (priority=3, tries=0, successful=1)
// This should only be called on partitions already in "good" state,
// but will work on any state (logs warning for non-good partitions)
func (pm *PartitionManager) SetBest(partition string) error {
	// Read current attributes to check state
	attr, err := pm.store.GetPartitionAttributes(partition)
	if err != nil {
		return fmt.Errorf("failed to read attributes for %s: %w", partition, err)
	}

	// Warn if not in good state (0x102)
	if attr != 0x102 {
		log.Warnf("SetBest called on partition %s with state 0x%03x (expected 0x102)", partition, attr)
	}

	// Set to best state: priority=3, tries=0, successful=1 (0x103)
	err = pm.store.SetPartitionAttributes(partition, 0x103)
	if err != nil {
		return fmt.Errorf("failed to set %s as best: %w", partition, err)
	}

	log.Noticef("Set partition %s as best (0x103)", partition)
	return nil
}

// FindFailedPartitions finds partitions that failed to boot
// Returns partitions in "inprogress" state (tries=0, successful=0, priority>0)
// that are not the current partition
//
// Business logic:
// - A partition is "failed" if GRUB tried to boot it but it didn't complete successfully
// - This is indicated by: tries=0 (GRUB decremented it), successful=0 (never marked good), priority>0 (was bootable)
// - We skip the current partition because it successfully booted (we're running on it!)
func (pm *PartitionManager) FindFailedPartitions() ([]string, error) {
	var failed []string
	currentPartition := pm.GetCurrentPartition()

	for _, partition := range pm.GetValidPartitionLabels() {
		// Skip current partition - it successfully booted
		if partition == currentPartition {
			continue
		}

		// Read attributes from store
		attr, err := pm.store.GetPartitionAttributes(partition)
		if err != nil {
			log.Errorf("Failed to read attributes for %s: %v", partition, err)
			continue
		}

		// Extract fields from attribute value
		// Bit layout: bits 0-3=priority, bits 4-7=tries, bit 8=successful
		priority := attr & 0xF
		triesLeft := (attr >> 4) & 0xF
		successful := (attr >> 8) & 0x1

		// Check for failed state: tries=0, successful=0, priority>0
		// This means GRUB tried to boot it (decremented tries to 0) but it never marked itself good
		if triesLeft == 0 && successful == 0 && priority > 0 {
			log.Noticef("Detected failed partition: %s (attr=0x%03x, p=%d, t=%d, s=%d)",
				partition, attr, priority, triesLeft, successful)
			failed = append(failed, partition)
		}
	}

	return failed, nil
}
