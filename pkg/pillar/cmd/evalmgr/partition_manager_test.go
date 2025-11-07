// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"io"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Initialize package-level log for tests with no-op logger
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	log = base.NewSourceLogObject(logger, "evalmgr-test", 0)
}

// TestPartitionManagerWithMockStore verifies the new architecture:
// - PartitionManager contains all business logic
// - MockGptAccess only handles data access
// - Tests exercise real logic with simulated GPT access
func TestPartitionManagerWithMockStore(t *testing.T) {
	mockStore := NewMockGptAccess()
	pm := NewPartitionManager(mockStore, nil)

	// Verify initial state - all partitions scheduled
	assert.Equal(t, "scheduled", mockStore.GetPartitionStateString("IMGA"))
	assert.Equal(t, "scheduled", mockStore.GetPartitionStateString("IMGB"))
	assert.Equal(t, "scheduled", mockStore.GetPartitionStateString("IMGC"))

	// Simulate first boot - GRUB selects IMGA
	slot, err := mockStore.SimulateReboot()
	require.NoError(t, err)
	assert.Equal(t, "IMGA", slot)
	assert.Equal(t, "inprogress", mockStore.GetPartitionStateString("IMGA"))

	// PartitionManager marks IMGA as good
	err = pm.MarkGood("IMGA")
	require.NoError(t, err)
	assert.Equal(t, "good", mockStore.GetPartitionStateString("IMGA"))

	// Simulate second boot - GRUB selects IMGB (priority=3 > IMGA priority=2)
	slot, err = mockStore.SimulateReboot()
	require.NoError(t, err)
	assert.Equal(t, "IMGB", slot)

	// CRITICAL TEST: FindFailedPartitions should NOT report IMGA as failed
	// This tests the bit extraction logic in PartitionManager.FindFailedPartitions
	failed, err := pm.FindFailedPartitions()
	require.NoError(t, err)
	assert.Empty(t, failed, "Good partition IMGA should not be reported as failed")
	assert.Equal(t, "good", mockStore.GetPartitionStateString("IMGA"))
}

// TestPartitionManagerFindFailedPartitions tests the FindFailedPartitions business logic
// This test catches bugs in bit extraction because mock now uses same logic as real code
func TestPartitionManagerFindFailedPartitions(t *testing.T) {
	mockStore := NewMockGptAccess()
	pm := NewPartitionManager(mockStore, nil)

	// Boot IMGA and mark good
	_, err := mockStore.SimulateReboot()
	require.NoError(t, err)
	err = pm.MarkGood("IMGA")
	require.NoError(t, err)

	// Boot IMGB but simulate crash (don't mark good)
	_, err = mockStore.SimulateReboot()
	require.NoError(t, err)
	assert.Equal(t, "IMGB", mockStore.GetCurrentPartition())
	assert.Equal(t, "inprogress", mockStore.GetPartitionStateString("IMGB"))

	// Boot IMGC (GRUB skips inprogress IMGB, boots IMGC)
	_, err = mockStore.SimulateReboot()
	require.NoError(t, err)
	assert.Equal(t, "IMGC", mockStore.GetCurrentPartition())

	// FindFailedPartitions should detect IMGB as failed
	failed, err := pm.FindFailedPartitions()
	require.NoError(t, err)
	require.Len(t, failed, 1)
	assert.Contains(t, failed, "IMGB")

	// IMGA and IMGC should NOT be reported as failed
	assert.NotContains(t, failed, "IMGA", "Good partition should not be failed")
	assert.NotContains(t, failed, "IMGC", "Current partition should not be failed")
}

// TestPartitionManagerMarkBad tests MarkBad business logic
func TestPartitionManagerMarkBad(t *testing.T) {
	mockStore := NewMockGptAccess()
	pm := NewPartitionManager(mockStore, nil)

	err := pm.MarkBad("IMGB")
	require.NoError(t, err)
	assert.Equal(t, "bad", mockStore.GetPartitionStateString("IMGB"))

	// Verify attribute is 0x000
	attr, err := mockStore.GetPartitionAttributes("IMGB")
	require.NoError(t, err)
	assert.Equal(t, uint16(0x000), attr)
}

// TestPartitionManagerSetBest tests SetBest business logic
func TestPartitionManagerSetBest(t *testing.T) {
	mockStore := NewMockGptAccess()
	pm := NewPartitionManager(mockStore, nil)

	// First mark partition as good
	_, err := mockStore.SimulateReboot()
	require.NoError(t, err)
	err = pm.MarkGood("IMGA")
	require.NoError(t, err)
	assert.Equal(t, "good", mockStore.GetPartitionStateString("IMGA"))

	// Then set as best
	err = pm.SetBest("IMGA")
	require.NoError(t, err)
	assert.Equal(t, "best", mockStore.GetPartitionStateString("IMGA"))

	// Verify attribute is 0x103
	attr, err := mockStore.GetPartitionAttributes("IMGA")
	require.NoError(t, err)
	assert.Equal(t, uint16(0x103), attr)
}

// TestPartitionManagerIdempotent tests that MarkGood is idempotent
func TestPartitionManagerIdempotent(t *testing.T) {
	mockStore := NewMockGptAccess()
	pm := NewPartitionManager(mockStore, nil)

	_, err := mockStore.SimulateReboot()
	require.NoError(t, err)

	// Mark good once
	err = pm.MarkGood("IMGA")
	require.NoError(t, err)
	state1 := mockStore.GetPartitionStateString("IMGA")

	// Mark good again - should be no-op
	err = pm.MarkGood("IMGA")
	require.NoError(t, err)
	state2 := mockStore.GetPartitionStateString("IMGA")

	assert.Equal(t, state1, state2, "MarkGood should be idempotent")
	assert.Equal(t, "good", state1)
}

// TestBitExtractionAccuracy verifies bit extraction is correct
// This is the critical test that would have caught the hardware bug
func TestBitExtractionAccuracy(t *testing.T) {
	mockStore := NewMockGptAccess()
	pm := NewPartitionManager(mockStore, nil)

	// Test case: IMGA=good (0x102), IMGB=scheduled, IMGC=scheduled
	// Boot IMGA
	_, err := mockStore.SimulateReboot()
	require.NoError(t, err)
	err = pm.MarkGood("IMGA")
	require.NoError(t, err)

	// Get IMGA attributes
	attr, err := mockStore.GetPartitionAttributes("IMGA")
	require.NoError(t, err)
	assert.Equal(t, uint16(0x102), attr, "IMGA should be 0x102 (good)")

	// Extract bits using same logic as PartitionManager.FindFailedPartitions
	priority := attr & 0xF
	triesLeft := (attr >> 4) & 0xF
	successful := (attr >> 8) & 0x1

	// Verify extraction for 0x102 (priority=2, tries=0, successful=1)
	assert.Equal(t, uint16(2), priority, "Priority should be 2")
	assert.Equal(t, uint16(0), triesLeft, "Tries should be 0")
	assert.Equal(t, uint16(1), successful, "Successful should be 1")

	// Boot IMGB
	_, err = mockStore.SimulateReboot()
	require.NoError(t, err)

	// Now IMGA should NOT be detected as failed
	// This is the exact bug we had on hardware!
	failed, err := pm.FindFailedPartitions()
	require.NoError(t, err)
	assert.NotContains(t, failed, "IMGA", "Good partition with 0x102 should NOT be detected as failed")
}

// TestNewArchitectureCompleteFlow tests full evaluation cycle with new architecture
func TestNewArchitectureCompleteFlow(t *testing.T) {
	mockStore := NewMockGptAccess()
	pm := NewPartitionManager(mockStore, nil)

	// Test all three partitions
	partitions := []string{"IMGA", "IMGB", "IMGC"}
	for i, partition := range partitions {
		t.Logf("Testing partition %s (step %d/3)", partition, i+1)

		// Boot partition
		slot, err := mockStore.SimulateReboot()
		require.NoError(t, err)
		assert.Equal(t, partition, slot)
		assert.Equal(t, "inprogress", mockStore.GetPartitionStateString(partition))

		// Mark as good
		err = pm.MarkGood(partition)
		require.NoError(t, err)
		assert.Equal(t, "good", mockStore.GetPartitionStateString(partition))

		// Verify no false positives in failed partition detection
		failed, err := pm.FindFailedPartitions()
		require.NoError(t, err)
		assert.Empty(t, failed, "No partitions should be reported as failed")
	}

	// All partitions are good now, select best (first one)
	err := pm.SetBest("IMGA")
	require.NoError(t, err)
	assert.Equal(t, "best", mockStore.GetPartitionStateString("IMGA"))
	assert.Equal(t, "good", mockStore.GetPartitionStateString("IMGB"))
	assert.Equal(t, "good", mockStore.GetPartitionStateString("IMGC"))
}
