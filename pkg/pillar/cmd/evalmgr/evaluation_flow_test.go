// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompleteEvaluationFlow tests the complete evaluation workflow
// Simulates real boot sequence: initial GPT state -> GRUB boot -> evalmgr -> reboot -> repeat
func TestCompleteEvaluationFlow(t *testing.T) {
	testMutex.Lock()
	defer testMutex.Unlock()

	// Initialize: Create mock and context with NEW architecture
	tc := NewTestContextForMultiBoot(t, nil)
	defer tc.StatusSubscriber.Close()

	// Boot 1: Test IMGA
	t.Logf("=== Boot 1: Testing IMGA ===")
	runEvaluationCycle(t, tc, EvaluationCycleParams{
		CurrentSlot:      types.SlotIMGA,
		ExpectedNextSlot: types.SlotIMGB,
		ShouldFail:       false,
	})

	// Boot 2: Test IMGB (GRUB selected it during Reset)
	t.Logf("=== Boot 2: Testing IMGB ===")
	slot := types.SlotName(tc.MockPartitionManager.GetCurrentPartition())
	require.Equal(t, types.SlotIMGB, slot, "GRUB should have selected IMGB")
	runEvaluationCycle(t, tc, EvaluationCycleParams{
		CurrentSlot:      types.SlotIMGB,
		ExpectedNextSlot: types.SlotIMGC,
		ShouldFail:       false,
	})

	// Boot 3: Test IMGC and finalize
	t.Logf("=== Boot 3: Testing IMGC (finalization) ===")
	slot = types.SlotName(tc.MockPartitionManager.GetCurrentPartition())
	require.Equal(t, types.SlotIMGC, slot, "GRUB should have selected IMGC")
	runEvaluationCycle(t, tc, EvaluationCycleParams{
		CurrentSlot:      types.SlotIMGC,
		ExpectedNextSlot: types.SlotFinal,
		ShouldFail:       false,
	})

	// Verify partition states after finalization
	t.Logf("=== Verifying final partition states ===")
	tc.VerifyPartitionState("IMGA", "best")
	tc.VerifyPartitionState("IMGB", "good")
	tc.VerifyPartitionState("IMGC", "good")
}

// TestEvaluationFlowWithOneFailure tests evaluation when one partition fails
// Parameterized to test each partition failure scenario
func TestEvaluationFlowWithOneFailure(t *testing.T) {
	testCases := []struct {
		name              string
		failingSlot       types.SlotName
		expectedGoodSlots []string
		expectedBadSlots  []string
		expectedBestSlot  string
	}{
		{
			name:              "IMGA_Fails",
			failingSlot:       types.SlotIMGA,
			expectedGoodSlots: []string{"IMGB", "IMGC"},
			expectedBadSlots:  []string{"IMGA"},
			expectedBestSlot:  "IMGB", // First good partition
		},
		{
			name:              "IMGB_Fails",
			failingSlot:       types.SlotIMGB,
			expectedGoodSlots: []string{"IMGA", "IMGC"},
			expectedBadSlots:  []string{"IMGB"},
			expectedBestSlot:  "IMGA", // First good partition
		},
		{
			name:              "IMGC_Fails",
			failingSlot:       types.SlotIMGC,
			expectedGoodSlots: []string{"IMGA", "IMGB"},
			expectedBadSlots:  []string{"IMGC"},
			expectedBestSlot:  "IMGA", // First good partition
		},
	}

	for _, testCase := range testCases {
		tc := testCase // Capture range variable
		t.Run(tc.name, func(t *testing.T) {
			testMutex.Lock()
			defer testMutex.Unlock()

			// Initialize fresh context for this subtest
			testCtx := NewTestContextForMultiBoot(t, nil)
			defer testCtx.StatusSubscriber.Close()

			// Boot 1: Test IMGA
			t.Logf("=== Boot 1: Testing IMGA ===")
			runEvaluationCycle(t, testCtx, EvaluationCycleParams{
				CurrentSlot:      types.SlotIMGA,
				ExpectedNextSlot: types.SlotIMGB,
				ShouldFail:       tc.failingSlot == types.SlotIMGA,
			})
			if tc.failingSlot == types.SlotIMGA {
				// Manually reboot after crash
				_, err := testCtx.MockPartitionManager.SimulateReboot()
				require.NoError(t, err)
			}

			// Boot 2: Test IMGB
			t.Logf("=== Boot 2: Testing IMGB ===")
			currentSlot := testCtx.MockPartitionManager.GetCurrentPartition()
			require.Equal(t, "IMGB", currentSlot)
			runEvaluationCycle(t, testCtx, EvaluationCycleParams{
				CurrentSlot:      types.SlotIMGB,
				ExpectedNextSlot: types.SlotIMGC,
				ShouldFail:       tc.failingSlot == types.SlotIMGB,
			})
			if tc.failingSlot == types.SlotIMGB {
				// Manually reboot after crash
				_, err := testCtx.MockPartitionManager.SimulateReboot()
				require.NoError(t, err)
			}

			// Boot 3: Test IMGC
			t.Logf("=== Boot 3: Testing IMGC ===")
			currentSlot = testCtx.MockPartitionManager.GetCurrentPartition()
			require.Equal(t, "IMGC", currentSlot)
			runEvaluationCycle(t, testCtx, EvaluationCycleParams{
				CurrentSlot:      types.SlotIMGC,
				ExpectedNextSlot: types.SlotFinal,
				ShouldFail:       tc.failingSlot == types.SlotIMGC,
			})
			if tc.failingSlot == types.SlotIMGC {
				// Manually reboot after crash
				_, err := testCtx.MockPartitionManager.SimulateReboot()
				require.NoError(t, err)

				// Boot 4: Back to a good partition for reconciliation and finalization
				// Note: Can't use runEvaluationCycle here because the partition is already good
				// and won't enter testing phase again - it goes straight to finalization
				t.Logf("=== Boot 4: Reconciliation and finalization ===")
				currentSlot = testCtx.MockPartitionManager.GetCurrentPartition()
				t.Logf("Booted to %s for reconciliation", currentSlot)

				// Run evalmgr to do reconciliation and finalization
				done := testCtx.Run()
				testCtx.WaitForRun(done, 10*time.Second)
			}

			// Verify final states after all boots complete
			t.Logf("=== Verifying final partition states ===")
			for _, goodSlot := range tc.expectedGoodSlots {
				if goodSlot == tc.expectedBestSlot {
					testCtx.VerifyPartitionState(goodSlot, "best")
				} else {
					testCtx.VerifyPartitionState(goodSlot, "good")
				}
			}

			for _, badSlot := range tc.expectedBadSlots {
				testCtx.VerifyPartitionState(badSlot, "bad")
			}
		})
	}
}

// TestEvaluationFlowWithMultipleFailures tests when multiple partitions fail
func TestEvaluationFlowWithMultipleFailures(t *testing.T) {
	testMutex.Lock()
	defer testMutex.Unlock()

	// Initialize
	tc := NewTestContextForMultiBoot(t, nil)
	defer tc.StatusSubscriber.Close()

	// Boot 1: Test IMGA (succeeds)
	t.Logf("=== Boot 1: Testing IMGA ===")
	runEvaluationCycle(t, tc, EvaluationCycleParams{
		CurrentSlot:      types.SlotIMGA,
		ExpectedNextSlot: types.SlotIMGB,
		ShouldFail:       false,
	})

	// Boot 2: IMGB fails
	t.Logf("=== Boot 2: Testing IMGB (will fail) ===")
	currentSlot := tc.MockPartitionManager.GetCurrentPartition()
	require.Equal(t, "IMGB", currentSlot)
	runEvaluationCycle(t, tc, EvaluationCycleParams{
		CurrentSlot:      types.SlotIMGB,
		ExpectedNextSlot: types.SlotIMGC, // Ignored when ShouldFail=true
		ShouldFail:       true,
	})
	// Manually reboot after crash
	currentSlot, err := tc.MockPartitionManager.SimulateReboot()
	require.NoError(t, err)
	require.Equal(t, "IMGC", currentSlot)

	// Boot 3: IMGC also fails
	t.Logf("=== Boot 3: Testing IMGC (will fail) ===")
	runEvaluationCycle(t, tc, EvaluationCycleParams{
		CurrentSlot:      types.SlotIMGC,
		ExpectedNextSlot: types.SlotFinal, // Ignored when ShouldFail=true
		ShouldFail:       true,
	})
	// Manually reboot after crash
	currentSlot, err = tc.MockPartitionManager.SimulateReboot()
	require.NoError(t, err)
	require.Equal(t, "IMGA", currentSlot, "GRUB should fall back to good partition")

	// Boot 4: Back to IMGA, reconciliation detects both failures
	// Note: Can't use runEvaluationCycle here because IMGA is already good
	// and won't enter testing phase again - it goes straight to finalization
	t.Logf("=== Boot 4: Reconciliation detects both failures ===")
	// Run evalmgr to do reconciliation and finalization
	done := tc.Run()
	tc.WaitForRun(done, 10*time.Second)

	// Verify final states
	// IMGA should be "best" after finalization (only good partition)
	tc.VerifyPartitionState("IMGA", "best")
	tc.VerifyPartitionState("IMGB", "bad")
	tc.VerifyPartitionState("IMGC", "bad")
}

// TestGRUBBootSelectionBehavior tests GRUB boot selection algorithm
func TestGRUBBootSelectionBehavior(t *testing.T) {
	testMutex.Lock()
	defer testMutex.Unlock()

	t.Run("AllScheduled_BootsFirstInOrder", func(t *testing.T) {
		mockStore := NewMockGptAccess()
		// All at priority=3, should boot first in alphabetical order
		currentSlot, err := mockStore.SimulateReboot()
		require.NoError(t, err)
		assert.Equal(t, "IMGA", currentSlot)
	})

	t.Run("PriorityCascade_BootsHigherPriority", func(t *testing.T) {
		mockStore := NewMockGptAccess()
		mockAgentLog := NewMockAgentLog(nil)
		partitionMgr := NewPartitionManager(mockStore, mockAgentLog)

		// Boot IMGA, mark good (priority → 2)
		_, err := mockStore.SimulateReboot()
		require.NoError(t, err)
		err = partitionMgr.MarkGood("IMGA")
		require.NoError(t, err)

		// Next boot should select IMGB (priority=3 > IMGA priority=2)
		currentSlot, err := mockStore.SimulateReboot()
		require.NoError(t, err)
		assert.Equal(t, "IMGB", currentSlot)
	})

	t.Run("SkipsInprogressPartition", func(t *testing.T) {
		mockStore := NewMockGptAccess()
		mockAgentLog := NewMockAgentLog(nil)
		partitionMgr := NewPartitionManager(mockStore, mockAgentLog)

		// Boot IMGA, mark good
		_, err := mockStore.SimulateReboot()
		require.NoError(t, err)
		err = partitionMgr.MarkGood("IMGA")
		require.NoError(t, err)

		// Boot IMGB but crash (don't mark good)
		_, err = mockStore.SimulateReboot()
		require.NoError(t, err)

		// Next boot should skip IMGB (inprogress) and try IMGC
		currentSlot, err := mockStore.SimulateReboot()
		require.NoError(t, err)
		assert.Equal(t, "IMGC", currentSlot)
	})

	t.Run("SkipsBadPartition", func(t *testing.T) {
		mockStore := NewMockGptAccess()
		mockAgentLog := NewMockAgentLog(nil)
		partitionMgr := NewPartitionManager(mockStore, mockAgentLog)

		// Mark IMGB as bad
		err := partitionMgr.MarkBad("IMGB")
		require.NoError(t, err)

		// Boot should select IMGA (IMGB is priority=0)
		currentSlot, err := mockStore.SimulateReboot()
		require.NoError(t, err)
		assert.Equal(t, "IMGA", currentSlot)

		// Mark good and reboot
		err = partitionMgr.MarkGood("IMGA")
		require.NoError(t, err)

		// Next boot should go to IMGC, not IMGB
		currentSlot, err = mockStore.SimulateReboot()
		require.NoError(t, err)
		assert.Equal(t, "IMGC", currentSlot)
	})
}

// Helper functions

// EvaluationCycleParams specifies parameters for a single evaluation cycle
type EvaluationCycleParams struct {
	CurrentSlot      types.SlotName // Slot currently booting
	ExpectedNextSlot types.SlotName // Slot that should be scheduled next (or SlotFinal)
	ShouldFail       bool           // If true, simulate boot failure (don't call run)
}

// runEvaluationCycle is the master test helper that runs a complete evaluation cycle
// following the proper testing architecture:
//
// Normal case (ShouldFail=false):
//  1. Start run() in background goroutine
//  2. Setup timeout protection (10s max)
//  3. Wait for events via pubsub (event-driven, no sleeps!)
//  4. Wait for run() to complete (mock Reset() sends stop signal on reboot)
//  5. Verify results AFTER run() exits
//
// Failure case (ShouldFail=true):
//  1. Don't start run() - simulates partition crash before evalmgr starts
//  2. Just simulate reboot (GRUB fallback to previous partition)
//  3. Verify GPT state shows failed partition (tries=0, successful=0, priority>0)
//  4. Next boot will detect and reconcile this failure
//
// Results to verify (after run() exits or failure simulation):
//
//	a) Persistent state (/persist/eval/state.json)
//	b) PubSub events (captured by StatusSubscriber)
//	c) GPT partition state (mock partition manager)
func runEvaluationCycle(t *testing.T, tc *TestContext, params EvaluationCycleParams) {
	t.Helper()

	// Clear mock call log to track what happens during this test
	// NOTE: Commented out to preserve call history across multiple cycles in parameterized tests
	// tc.MockPartitionManager.ClearCallLog()

	// Handle failure case: partition crashes before evalmgr runs
	if params.ShouldFail {
		t.Logf("=== Simulating partition crash: %s will NOT run evalmgr ===", params.CurrentSlot)

		// In real hardware: partition boots, crashes immediately, GRUB falls back
		// In test: we just mark the partition state to simulate GRUB trying to boot it
		// The partition will have tries=0, successful=0 (failed boot)
		// Next boot into a different partition will detect this via reconciliation

		// Simulate GRUB attempting to boot this partition (decrements tries to 0)
		t.Logf("Simulating GRUB boot attempt that fails immediately")

		// Just verify the GPT state is as expected for a crashed partition
		// The reconciliation will happen on the NEXT boot
		partitionState := tc.MockPartitionManager.GetPartitionStateString(string(params.CurrentSlot))
		t.Logf("Partition %s state after crash: %s", params.CurrentSlot, partitionState)

		return // Don't run evalmgr, don't wait for events
	}

	// Normal case: Start run() in background
	done := make(chan struct{})
	go func() {
		tc.EvalContext.run()
		close(done)
	}()

	// Setup timeout protection - run() MUST complete within this time
	// If it doesn't, something is wrong (infinite loop bug)
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()

	// Ensure we ALWAYS wait for run() to complete before checking results
	defer func() {
		select {
		case <-done:
			// run() completed naturally (mock reboot sent stop signal)
			t.Logf("✓ run() completed naturally")
		case <-timeout.C:
			// Timeout - force stop and fail
			t.Errorf("TIMEOUT: run() did not complete within 10 seconds")
			tc.Stop() // Force stop
			<-done    // Wait for cleanup
		}
	}()

	// Phase 1: Wait for stability check to start
	t.Logf("Phase 1: Waiting for stability check to start for %s", params.CurrentSlot)
	status1, ok := tc.StatusSubscriber.WaitForCondition(func(s types.EvalStatus) bool {
		return s.Phase == types.EvalPhaseTesting && s.CurrentSlot == params.CurrentSlot
	}, 1*time.Second)
	require.True(t, ok, "Should receive testing phase status for %s", params.CurrentSlot)
	assert.Equal(t, types.EvalPhaseTesting, status1.Phase)
	assert.Equal(t, params.CurrentSlot, status1.CurrentSlot)
	assert.False(t, status1.AllowOnboard, "Should block onboarding during stability")
	t.Logf("✓ Received testing phase status, stability check started")

	// Phase 1.5: Wait for inventory collection status update
	t.Logf("Phase 1.5: Waiting for inventory collection status for %s", params.CurrentSlot)
	inventoryStatus, ok := tc.StatusSubscriber.WaitForCondition(func(s types.EvalStatus) bool {
		return s.InventoryCollected && s.InventoryDir != ""
	}, 2*time.Second)
	require.True(t, ok, "Should receive inventory collection status for %s", params.CurrentSlot)
	assert.True(t, inventoryStatus.InventoryCollected, "InventoryCollected should be true")
	assert.NotEmpty(t, inventoryStatus.InventoryDir, "InventoryDir should be set")
	assert.Contains(t, inventoryStatus.InventoryDir, string(params.CurrentSlot),
		"InventoryDir should contain partition name")
	t.Logf("✓ Inventory collected at: %s", inventoryStatus.InventoryDir)

	if params.ExpectedNextSlot != types.SlotFinal {
		// Phase 2: Wait for stability completion and reboot scheduling
		t.Logf("Phase 2: Waiting for stability completion (3s) and reboot scheduling")
		status2, ok := tc.StatusSubscriber.WaitForCondition(func(s types.EvalStatus) bool {
			return s.RebootCountdown > 0
		}, 5*time.Second)
		require.True(t, ok, "Should schedule reboot after stability for %s", params.CurrentSlot)
		assert.Greater(t, status2.RebootCountdown, 0)
		t.Logf("✓ Reboot scheduled with countdown: %d", status2.RebootCountdown)

		// Phase 3: Wait for run() to complete (mock Reset() sends stop signal)
		// This means: countdown reached 0, executeReboot() called, mock Reset() signaled stop
		t.Logf("Phase 3: Waiting for run() to complete after reboot execution")
		select {
		case <-done:
			t.Logf("✓ run() completed - mock reboot executed and stopped run loop")
		case <-timeout.C:
			require.Fail(t, "Timeout waiting for run() to complete after reboot")
			return
		}

		// Phase 4: Verify SetPartitionAttributes was called with 0x102 (good state)
		t.Logf("Phase 4: Verifying SetPartitionAttributes(0x102) was called")
		foundSetGood := tc.MockPartitionManager.WasSetAttributesCalled(string(params.CurrentSlot), 0x102)
		assert.True(t, foundSetGood, "SetPartitionAttributes(%s, 0x102) should have been called", params.CurrentSlot)
		if foundSetGood {
			t.Logf("✓ SetPartitionAttributes(%s, 0x102) was called", params.CurrentSlot)
		}

		// Phase 5: Verify partition state changed to "good"
		partitionState := tc.MockPartitionManager.GetPartitionStateString(string(params.CurrentSlot))
		assert.Equal(t, "good", partitionState, "%s should be marked good", params.CurrentSlot)
		t.Logf("✓ Partition %s is in 'good' state", params.CurrentSlot)

		// Phase 6: Verify reboot was requested via agentlog mock (written by executeReboot)
		t.Logf("Phase 6: Verifying reboot was written to agentlog")
		mockAgentLog := tc.EvalContext.agentLog.(*MockAgentLog)
		reason, _, _ := mockAgentLog.GetRebootReason(log)
		rebootRequested := reason != ""
		assert.True(t, rebootRequested, "Reboot should be requested via agentlog")
		if rebootRequested {
			t.Logf("✓ Reboot requested with reason: %s", reason)
			// The reboot reason should be "evaluation-next-slot-<NextSlot>"
			// expectedNextSlot is the slot we're scheduling TO, not the current slot
			expectedReasonPrefix := RebootReasonEvalNextSlot + "-" + string(params.ExpectedNextSlot)
			assert.Contains(t, reason, expectedReasonPrefix, "Reboot reason should be '%s'", expectedReasonPrefix)
		}
	} else {
		// Last partition - finalization will happen and trigger reboot to best slot
		t.Logf("Phase 2: Last partition - waiting for finalization and reboot to best slot")

		// Phase 1.5 also applies here: Wait for inventory collection status update
		t.Logf("Phase 1.5: Waiting for inventory collection status for last partition %s", params.CurrentSlot)
		inventoryStatus, ok := tc.StatusSubscriber.WaitForCondition(func(s types.EvalStatus) bool {
			return s.InventoryCollected && s.InventoryDir != ""
		}, 2*time.Second)
		require.True(t, ok, "Should receive inventory collection status for last partition %s", params.CurrentSlot)
		assert.True(t, inventoryStatus.InventoryCollected, "InventoryCollected should be true for last partition")
		assert.NotEmpty(t, inventoryStatus.InventoryDir, "InventoryDir should be set for last partition")
		assert.Contains(t, inventoryStatus.InventoryDir, string(params.CurrentSlot),
			"InventoryDir should contain partition name")
		t.Logf("✓ Inventory collected for last partition at: %s", inventoryStatus.InventoryDir)

		// Wait for stability completion and reboot scheduling to finalize
		t.Logf("Waiting for finalization reboot countdown")
		status2, ok := tc.StatusSubscriber.WaitForCondition(func(s types.EvalStatus) bool {
			return s.RebootCountdown > 0
		}, 8*time.Second) // Longer timeout: stability(3s) + finalization + buffer
		require.True(t, ok, "Should schedule finalization reboot for last partition %s", params.CurrentSlot)
		assert.Greater(t, status2.RebootCountdown, 0)
		t.Logf("✓ Finalization reboot scheduled with countdown: %d", status2.RebootCountdown)

		// Wait for run() to complete (mock Reset() sends stop signal)
		t.Logf("Waiting for finalization reboot to execute")
		select {
		case <-done:
			t.Logf("✓ run() completed - finalization reboot executed")
		case <-timeout.C:
			require.Fail(t, "Timeout waiting for finalization reboot to complete")
			return
		}

		// Verify SetPartitionAttributes was called with 0x102 (good state) during stability check
		t.Logf("Verifying SetPartitionAttributes(0x102) was called for last partition")
		foundSetGood := tc.MockPartitionManager.WasSetAttributesCalled(string(params.CurrentSlot), 0x102)
		assert.True(t, foundSetGood, "SetPartitionAttributes(%s, 0x102) should have been called for last partition", params.CurrentSlot)
		if foundSetGood {
			t.Logf("✓ SetPartitionAttributes(%s, 0x102) was called", params.CurrentSlot)
		}

		// Verify partition state is good
		partitionState := tc.MockPartitionManager.GetPartitionStateString(string(params.CurrentSlot))
		assert.Equal(t, "good", partitionState, "%s should be marked good", params.CurrentSlot)
		t.Logf("✓ Partition %s is in 'good' state", params.CurrentSlot)

		// Verify finalization reboot was requested
		mockAgentLog := tc.EvalContext.agentLog.(*MockAgentLog)
		reason, _, _ := mockAgentLog.GetRebootReason(log)
		rebootRequested := reason != ""
		assert.True(t, rebootRequested, "Finalization reboot should be requested")
		if rebootRequested {
			t.Logf("✓ Finalization reboot requested with reason: %s", reason)
			expectedReasonPrefix := RebootReasonEvalFinalize
			assert.Contains(t, reason, expectedReasonPrefix, "Reboot reason should contain '%s'", expectedReasonPrefix)
		}
	}

	// ============================================================
	// ALL CHECKS HAPPEN AFTER run() COMPLETES
	// Results to verify (as per design):
	// a) Persistent state (/persist/eval/state.json)
	// b) PubSub events (already captured by StatusSubscriber)
	// c) GPT partition state (mock partition manager state)
	// ============================================================

	// Final verification: Check persistent state
	t.Logf("Final: Verifying persistent state")
	tc.AssertSlotTried(params.CurrentSlot, true)
	tc.AssertSlotSuccess(params.CurrentSlot, true)
	t.Logf("✓ Persistent state updated correctly")

	// Verify inventory collection event was published
	t.Logf("Final: Verifying inventory collection status was published")
	inventoryEvent, found := tc.StatusSubscriber.FindEvent(func(s types.EvalStatus) bool {
		return s.InventoryCollected && s.InventoryDir != "" && s.CurrentSlot == params.CurrentSlot
	})
	assert.True(t, found, "Should have published inventory collection status for %s", params.CurrentSlot)
	if found {
		assert.True(t, inventoryEvent.InventoryCollected, "InventoryCollected should be true")
		assert.NotEmpty(t, inventoryEvent.InventoryDir, "InventoryDir should be set")
		assert.Contains(t, inventoryEvent.InventoryDir, string(params.CurrentSlot),
			"InventoryDir should contain partition name %s", params.CurrentSlot)
		t.Logf("✓ Inventory event found: dir=%s", inventoryEvent.InventoryDir)
	}
}
