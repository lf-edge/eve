// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/afero"
)

// testMutex serializes test execution to prevent data races on global logger and log variables
var testMutex sync.Mutex

// TestContext holds common test dependencies and implements SystemResetInterface
type TestContext struct {
	TempDir              string
	MockPartitionManager *MockGptAccess    // NEW architecture: dumb storage
	PartitionManager     *PartitionManager // NEW architecture: business logic
	EvalContext          *evalMgrContext
	Logger               *base.LogObject
	T                    *testing.T
	StatusSubscriber     *StatusSubscriber
	PubSub               *pubsub.PubSub
	SharedFs             afero.Fs // Shared filesystem for persistent state across reboots
	stopChan             chan struct{}
	rebootCount          int
	stopOnce             sync.Once
}

// Reset implements SystemResetInterface for test reboots
// Does BOTH operations that happen during a real reboot:
// 1. Simulates GRUB selecting next partition (hardware boot)
// 2. Stops the run() loop (system going down)
func (tc *TestContext) Reset(log *base.LogObject) {
	tc.T.Helper()

	if log != nil {
		log.Noticef("TestContext: simulating system reboot")
	}

	// Step 1: Simulate GRUB boot selection (happens during hardware boot)
	nextPartition, err := tc.SimulateReboot()
	if err != nil {
		if log != nil {
			log.Errorf("GRUB simulation failed during reboot: %v", err)
		}
		tc.T.Fatalf("GRUB simulation failed: %v", err)
	} else {
		if log != nil {
			log.Noticef("GRUB selected next partition: %s", nextPartition)
		}
		tc.T.Logf("=== GRUB selected partition: %s ===", nextPartition)
	}

	// Step 2: Send stop signal to exit run() loop (system shutting down)
	select {
	case tc.stopChan <- struct{}{}:
		tc.T.Logf("Sent stop signal to run() via Reset()")
	default:
		tc.T.Logf("Stop signal already pending")
	}
}

// SimulateReboot simulates a GRUB boot cycle using the common GRUB simulator
func (tc *TestContext) SimulateReboot() (string, error) {
	tc.T.Helper()
	tc.rebootCount++
	tc.T.Logf("SimulateReboot() - boot #%d", tc.rebootCount)

	// Use common GRUB boot selection logic
	selected, err := SimulateGrubBoot(tc.MockPartitionManager, nil)
	if err != nil {
		return "", err
	}

	// Update current slot in MockGptAccess
	tc.MockPartitionManager.SetCurrentSlot(selected)

	return selected, nil
}

// GetStopChannel returns the channel used to signal run() loop to stop
func (tc *TestContext) GetStopChannel() chan struct{} {
	return tc.stopChan
}

// Compile-time check that TestContext implements SystemResetInterface
var _ SystemResetInterface = (*TestContext)(nil)

// SendStop sends a stop signal to the run loop (for emergency timeout or test control)
func (tc *TestContext) SendStop() {
	tc.T.Helper()

	select {
	case tc.EvalContext.stopChan <- struct{}{}:
		tc.T.Logf("Sent stop signal to run()")
	default:
		tc.T.Logf("Stop signal already pending")
	}
}

// Run starts the run() loop in background and returns a done channel
// Caller should wait on done channel or use WaitForRun()
func (tc *TestContext) Run() chan struct{} {
	tc.T.Helper()

	done := make(chan struct{})
	go func() {
		tc.EvalContext.run()
		close(done)
	}()
	return done
}

// WaitForRun waits for run() to complete with timeout protection
// Returns true if completed normally, false if timed out
func (tc *TestContext) WaitForRun(done chan struct{}, timeout time.Duration) bool {
	tc.T.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-done:
		tc.T.Logf("✓ run() completed")
		return true
	case <-timer.C:
		tc.T.Logf("⚠ TIMEOUT: run() did not complete within %v, sending stop signal", timeout)
		tc.SendStop()
		<-done // Wait for it to actually stop
		return false
	}
}

// VerifyPartitionState checks the GPT state of a partition
func (tc *TestContext) VerifyPartitionState(partition string, expectedState string) {
	tc.T.Helper()

	state := tc.MockPartitionManager.GetPartitionStateString(partition)
	if state != expectedState {
		tc.T.Errorf("Partition %s: expected state %s, got %s", partition, expectedState, state)
	} else {
		tc.T.Logf("✓ Partition %s is in '%s' state", partition, state)
	}
}

// StatusSubscriber tracks EvalStatus updates for testing
type StatusSubscriber struct {
	Updates     chan types.EvalStatus
	AllEvents   []types.EvalStatus // Stores all events for later analysis
	sub         pubsub.Subscription
	done        chan struct{}
	t           *testing.T
	eventsMutex sync.Mutex
}

// NewStatusSubscriber creates a subscriber that captures all EvalStatus updates
// Note: MemoryDriver doesn't support MsgChan, so we poll with GetAll()
func NewStatusSubscriber(t *testing.T, ps *pubsub.PubSub, logger *base.LogObject) (*StatusSubscriber, error) {
	t.Helper()

	ss := &StatusSubscriber{
		Updates: make(chan types.EvalStatus, 100), // Buffered to not block
		done:    make(chan struct{}),
		t:       t,
	}

	// Subscribe to EvalStatus
	sub, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "evalmgr",
		TopicImpl:     types.EvalStatus{},
		Activate:      false,
		CreateHandler: ss.handleCreate,
		ModifyHandler: ss.handleModify,
		DeleteHandler: ss.handleDelete,
		WarningTime:   time.Minute,
		ErrorTime:     time.Minute,
	})
	if err != nil {
		return nil, err
	}

	ss.sub = sub

	// Activate the subscription
	if err := sub.Activate(); err != nil {
		return nil, err
	}

	// Start polling for updates (MemoryDriver doesn't push to MsgChan)
	// Start processing messages from the subscription
	go ss.processMessages()

	return ss, nil
}

// pollForUpdates polls the subscription for new status updates
// This is needed because MemoryDriver doesn't support MsgChan
// processMessages processes subscription messages in the background
func (ss *StatusSubscriber) processMessages() {
	for {
		select {
		case change := <-ss.sub.MsgChan():
			ss.sub.ProcessChange(change)
		case <-ss.done:
			return
		}
	}
}

// handleCreate processes EvalStatus create events
func (ss *StatusSubscriber) handleCreate(ctxArg interface{}, key string, item interface{}) {
	ss.t.Logf("TEST HANDLER: handleCreate called, key=%s", key)
	status := item.(types.EvalStatus)

	// Store in AllEvents array
	ss.eventsMutex.Lock()
	ss.AllEvents = append(ss.AllEvents, status)
	ss.eventsMutex.Unlock()

	select {
	case ss.Updates <- status:
	case <-ss.done:
	}
}

// handleModify processes EvalStatus modify events
func (ss *StatusSubscriber) handleModify(ctxArg interface{}, key string, item interface{}, oldItem interface{}) {
	ss.t.Logf("TEST HANDLER: handleModify called, key=%s", key)
	status := item.(types.EvalStatus)

	// Store in AllEvents array
	ss.eventsMutex.Lock()
	ss.AllEvents = append(ss.AllEvents, status)
	ss.eventsMutex.Unlock()

	select {
	case ss.Updates <- status:
	case <-ss.done:
	}
}

// handleDelete processes EvalStatus delete events
func (ss *StatusSubscriber) handleDelete(ctxArg interface{}, key string, item interface{}) {
	// Usually don't care about deletes in tests
}

// WaitForCondition waits for a status update that satisfies the condition
func (ss *StatusSubscriber) WaitForCondition(condition func(types.EvalStatus) bool, timeout time.Duration) (types.EvalStatus, bool) {
	ss.t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case status := <-ss.Updates:
			if condition(status) {
				return status, true
			}
		case <-deadline:
			return types.EvalStatus{}, false
		case <-ss.done:
			return types.EvalStatus{}, false
		}
	}
}

// Close stops the subscriber
func (ss *StatusSubscriber) Close() {
	close(ss.done)
	if ss.sub != nil {
		ss.sub.Close()
	}
}

// FindEvent searches through all collected events for one matching the condition
func (ss *StatusSubscriber) FindEvent(condition func(types.EvalStatus) bool) (types.EvalStatus, bool) {
	ss.eventsMutex.Lock()
	defer ss.eventsMutex.Unlock()

	for _, event := range ss.AllEvents {
		if condition(event) {
			return event, true
		}
	}
	return types.EvalStatus{}, false
}

// GetAllEvents returns a copy of all collected events
func (ss *StatusSubscriber) GetAllEvents() []types.EvalStatus {
	ss.eventsMutex.Lock()
	defer ss.eventsMutex.Unlock()

	events := make([]types.EvalStatus, len(ss.AllEvents))
	copy(events, ss.AllEvents)
	return events
}

// ClearEvents clears the collected events array
func (ss *StatusSubscriber) ClearEvents() {
	ss.eventsMutex.Lock()
	defer ss.eventsMutex.Unlock()

	ss.AllEvents = nil
}

// newTestEvalContext creates an eval context with test-friendly settings
// newTestEvalContext creates an eval context with test-friendly settings (NEW ARCHITECTURE)
func newTestEvalContext(ps *pubsub.PubSub, testCtx *TestContext, partitionMgr *PartitionManager, memFs afero.Fs) *evalMgrContext {
	return &evalMgrContext{
		ps:           ps,
		partitionMgr: partitionMgr,
		systemReset:  testCtx, // TestContext implements SystemResetInterface
		agentLog:     NewMockAgentLog(memFs),
		// currentSlot will be set by initializeEvaluation() via GetCurrentPartition()
		schedulerState: SchedulerIdle,
		fs:             memFs,
		testMode:       true,
		stopChan:       testCtx.GetStopChannel(), // Use stop channel from TestContext
		// Fast timers for testing - maintaining production ratios
		// Production: stabilityPeriod=15min, statusUpdate=30s, rebootTick=1s, stillRunning=25s
		// Test: 100x faster but same ratios for realistic behavior
		stabilityPeriod:      3000 * time.Millisecond, // 3 seconds (was 15 minutes = 900,000ms)
		statusUpdateInterval: 300 * time.Millisecond,  // 300ms (1:10 ratio with stability)
		rebootTickInterval:   10 * time.Millisecond,   // 10ms (1:30 ratio with status update)
		stillRunningInterval: 250 * time.Millisecond,  // 250ms (close to 1:12 ratio with stability)
	}
}

// genScript creates a mock executable script that returns "executed: <script_name>"
func genScript(path string, scriptName string) error {
	content := "#!/bin/sh\necho \"executed: " + scriptName + "\"\n"
	return os.WriteFile(path, []byte(content), 0755)
}

// setupMockCommands creates mock command scripts for inventory collection
func setupMockCommands(fs afero.Fs) (string, error) {
	// Create /proc/cmdline on the mock filesystem
	if err := fs.MkdirAll("/proc", 0755); err != nil {
		return "", err
	}
	cmdline := "root=/dev/sda2 console=ttyS0 rootdelay=3"
	if err := afero.WriteFile(fs, "/proc/cmdline", []byte(cmdline), 0644); err != nil {
		return "", err
	}

	// Create temporary directory for mock scripts on real filesystem
	tmpDir, err := os.MkdirTemp("", "evalmgr-mock-scripts-*")
	if err != nil {
		return "", err
	}

	// Create mock scripts in temp directory
	iommuScript := filepath.Join(tmpDir, "iommu-groups.sh")
	if err := genScript(iommuScript, "iommu-groups.sh"); err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	specScript := filepath.Join(tmpDir, "spec.sh")
	if err := genScript(specScript, "spec.sh"); err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	// Override the script paths to point to our temp directory
	IOMmuGroupsScript = iommuScript
	SpecScript = specScript

	return tmpDir, nil
}

// cleanupMockCommands removes mock command scripts
func cleanupMockCommands(tmpDir string) error {
	if tmpDir == "" {
		return nil
	}
	return os.RemoveAll(tmpDir)
}

// NewTestContext creates a new test context with all dependencies initialized
// newTestContextCommon creates a TestContext with common setup for both eval and non-eval platforms
func newTestContextCommon(t *testing.T, currentSlot types.SlotName, isEvalPlatform bool) *TestContext {
	t.Helper()

	// Create in-memory filesystem for testing
	memFs := afero.NewMemMapFs()

	// Setup mock commands for inventory collection
	tmpDir, err := setupMockCommands(memFs)
	if err != nil {
		t.Fatalf("Failed to setup mock commands: %v", err)
	}

	// Create mock store and partition manager with new architecture
	mockStore := NewMockGptAccess()
	mockAgentLog := NewMockAgentLog(memFs)
	partitionMgr := NewPartitionManager(mockStore, mockAgentLog)

	// Create a test logger
	logger := base.NewSourceLogObject(logrus.StandardLogger(), "evalmgr_test", 0)

	// Initialize in-memory pubsub for testing
	ps := pubsub.New(pubsub.NewMemoryDriver(), logrus.StandardLogger(), logger)

	// Create status subscriber to track updates
	subscriber, err := NewStatusSubscriber(t, ps, logger)
	if err != nil {
		t.Fatalf("Failed to create status subscriber: %v", err)
	}

	// Create the platform file with appropriate platform name
	memFs.MkdirAll("/hostfs/etc", 0755)
	if isEvalPlatform {
		afero.WriteFile(memFs, utils.EvePlatformFile, []byte("evaluation\n"), 0644)
	} else {
		// Write a non-eval platform name (e.g., nvidia-jp6, generic, etc.)
		afero.WriteFile(memFs, utils.EvePlatformFile, []byte("nvidia-jp6\n"), 0644)
	}

	// Create state directory in memory filesystem
	stateDir := "/persist/eval"
	memFs.MkdirAll(stateDir, 0755)

	// Create directories for reboot logging to avoid file write errors
	memFs.MkdirAll("/persist", 0755)
	memFs.MkdirAll("/persist/log", 0755)
	memFs.MkdirAll("/dev", 0755)

	// Create TestContext first with stop channel
	testCtx := &TestContext{
		TempDir:              stateDir,
		MockPartitionManager: mockStore,
		PartitionManager:     partitionMgr,
		Logger:               logger,
		T:                    t,
		StatusSubscriber:     subscriber,
		PubSub:               ps,
		SharedFs:             memFs,
		stopChan:             make(chan struct{}, 1),
		rebootCount:          0,
	}

	// Register cleanup function to remove mock commands
	t.Cleanup(func() {
		cleanupMockCommands(tmpDir)
	})

	// Create eval context with fast timers for testing
	ctx := newTestEvalContext(ps, testCtx, partitionMgr, memFs)

	// Override state file paths to use in-memory filesystem paths
	EvalStateDir = stateDir
	EvalStateFile = filepath.Join(stateDir, "state.json")

	// Note: evalStatus will be initialized by initializeEvaluation() in run()
	// Note: publication will be created by initPubSub() in tests

	testCtx.EvalContext = ctx
	return testCtx
}

// NewTestContext creates a TestContext for an evaluation platform
func NewTestContext(t *testing.T, currentSlot types.SlotName) *TestContext {
	t.Helper()
	return newTestContextCommon(t, currentSlot, true)
}

// NewNonEvalTestContext creates a test context for non-evaluation platform testing
// NewNonEvalTestContext creates a TestContext for a non-evaluation platform
func NewNonEvalTestContext(t *testing.T, currentSlot types.SlotName) *TestContext {
	t.Helper()
	return newTestContextCommon(t, currentSlot, false)
}

// NewTestContextWithPartitionManager creates a test context with a specific partition manager
// and optional shared filesystem. This is useful for multi-boot test scenarios where you need
// to control the mock store and partition manager explicitly, or preserve state across "reboots".
//
// If sharedFs is nil, creates a new filesystem. Otherwise, reuses the provided filesystem.
// This allows persistent state to survive across "reboots" in multi-boot test scenarios.
func NewTestContextWithPartitionManager(t *testing.T, currentSlot types.SlotName, mockStore *MockGptAccess, partitionMgr *PartitionManager, sharedFs afero.Fs) *TestContext {
	t.Helper()

	// Create a test logger
	logger := base.NewSourceLogObject(logrus.StandardLogger(), "evalmgr_test", 0)

	// Initialize in-memory pubsub
	ps := pubsub.New(pubsub.NewMemoryDriver(), logrus.StandardLogger(), logger)

	// Create status subscriber
	subscriber, err := NewStatusSubscriber(t, ps, logger)
	if err != nil {
		t.Fatalf("Failed to create status subscriber: %v", err)
	}

	// Use shared filesystem if provided, otherwise create new one
	var memFs afero.Fs
	if sharedFs != nil {
		memFs = sharedFs
		t.Logf("Reusing shared filesystem (persistent state preserved across reboot)")
	} else {
		memFs = afero.NewMemMapFs()
		stateDir := "/persist/eval"
		err = memFs.MkdirAll(stateDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create state directory: %v", err)
		}

		// Create the platform file for evaluation platform
		// This is required so that initializeEvaluation() correctly detects isEvaluationPlatform
		memFs.MkdirAll("/hostfs/etc", 0755)
		afero.WriteFile(memFs, utils.EvePlatformFile, []byte("evaluation\n"), 0644)

		// Create directories for reboot logging
		memFs.MkdirAll("/persist/log", 0755)
		memFs.MkdirAll("/dev", 0755)

		t.Logf("Created new filesystem for first boot")
	}

	stateDir := "/persist/eval"

	// Create TestContext first with stop channel
	testCtx := &TestContext{
		TempDir:              stateDir,
		MockPartitionManager: mockStore,
		PartitionManager:     partitionMgr,
		Logger:               logger,
		T:                    t,
		StatusSubscriber:     subscriber,
		PubSub:               ps,
		SharedFs:             memFs,
		stopChan:             make(chan struct{}, 1),
		rebootCount:          0,
	}

	// Create eval context using TestContext as systemReset
	// Note: currentSlot will be auto-detected by initializeEvaluation() via GetCurrentPartition()
	ctx := newTestEvalContext(ps, testCtx, partitionMgr, memFs)
	testCtx.EvalContext = ctx

	return testCtx
}

// NewTestContextForMultiBoot creates a complete test context for multi-boot test scenarios.
// This is a convenience function that handles the common pattern:
//  1. Creates mock store and partition manager
//  2. Performs initial GRUB boot simulation
//  3. Creates TestContext with the booted partition
//  4. Initializes pubsub
//  5. Sets up global loggers
//
// If sharedFs is provided, it will be used to preserve state across reboots.
// Returns only the TestContext - access MockGptAccess via tc.MockPartitionManager
// and PartitionManager via tc.PartitionManager.
func NewTestContextForMultiBoot(t *testing.T, sharedFs afero.Fs) *TestContext {
	t.Helper()

	// Create mock store and partition manager
	mockStore := NewMockGptAccess()
	mockAgentLog := NewMockAgentLog(sharedFs)
	partitionMgr := NewPartitionManager(mockStore, mockAgentLog)

	// Perform initial GRUB boot
	slot, err := mockStore.SimulateReboot()
	if err != nil {
		t.Fatalf("Failed to simulate initial boot: %v", err)
	}
	t.Logf("Initial GRUB boot selected: %s", slot)

	// Create test context with the booted partition
	tc := NewTestContextWithPartitionManager(t, types.SlotName(slot), mockStore, partitionMgr, sharedFs)

	// Initialize pubsub
	err = tc.EvalContext.initPubSub()
	if err != nil {
		t.Fatalf("Failed to initialize pubsub: %v", err)
	}

	// Set global loggers for tests that need them
	logger = logrus.StandardLogger()
	log = tc.Logger

	return tc
}

// CreatePersistentState creates and saves a persistent state file
func (tc *TestContext) CreatePersistentState(state *types.EvalPersist) error {
	tc.T.Helper()
	return tc.EvalContext.saveEvalState(state)
}

// LoadPersistentState loads the persistent state from disk
func (tc *TestContext) LoadPersistentState() (*types.EvalPersist, error) {
	tc.T.Helper()
	return tc.EvalContext.loadEvalState()
}

// AssertSchedulerState asserts the scheduler is in the expected state
func (tc *TestContext) AssertSchedulerState(expected SchedulerState) {
	tc.T.Helper()
	if tc.EvalContext.schedulerState != expected {
		tc.T.Fatalf("Expected scheduler state %v, got %v", expected, tc.EvalContext.schedulerState)
	}
}

// AssertPhase asserts the evaluation phase is as expected
func (tc *TestContext) AssertPhase(expected types.EvalPhase) {
	tc.T.Helper()
	if tc.EvalContext.evalStatus.Phase != expected {
		tc.T.Fatalf("Expected phase %s, got %s", expected, tc.EvalContext.evalStatus.Phase)
	}
}

// AssertOnboardAllowed asserts the onboarding permission state
func (tc *TestContext) AssertOnboardAllowed(expected bool) {
	tc.T.Helper()
	if tc.EvalContext.evalStatus.AllowOnboard != expected {
		tc.T.Fatalf("Expected AllowOnboard=%v, got %v", expected, tc.EvalContext.evalStatus.AllowOnboard)
	}
}

// AssertSlotState asserts a slot has the expected partition state in zboot
// AssertSlotState verifies partition state using new API
func (tc *TestContext) AssertSlotState(slot types.SlotName, expectedState string) {
	tc.T.Helper()
	actualState := tc.MockPartitionManager.GetPartitionStateString(string(slot))
	if actualState != expectedState {
		tc.T.Fatalf("Expected slot %s state=%s, got %s", slot, expectedState, actualState)
	}
}

// AssertSlotTried asserts a slot has been marked as tried in persistent state
func (tc *TestContext) AssertSlotTried(slot types.SlotName, expectedTried bool) {
	tc.T.Helper()
	state, err := tc.LoadPersistentState()
	if err != nil {
		tc.T.Fatalf("Failed to load state: %v", err)
	}

	slotState, ok := state.Slots[slot]
	if !ok {
		if expectedTried {
			tc.T.Fatalf("Expected slot %s to be tried, but it has no state", slot)
		}
		return
	}

	if slotState.Tried != expectedTried {
		tc.T.Fatalf("Expected slot %s Tried=%v, got %v", slot, expectedTried, slotState.Tried)
	}
}

// AssertSlotSuccess asserts a slot's success status in persistent state
func (tc *TestContext) AssertSlotSuccess(slot types.SlotName, expectedSuccess bool) {
	tc.T.Helper()
	state, err := tc.LoadPersistentState()
	if err != nil {
		tc.T.Fatalf("Failed to load state: %v", err)
	}

	slotState, ok := state.Slots[slot]
	if !ok {
		tc.T.Fatalf("Slot %s has no state", slot)
	}

	if slotState.Success != expectedSuccess {
		tc.T.Fatalf("Expected slot %s Success=%v, got %v", slot, expectedSuccess, slotState.Success)
	}
}

// GetZbootCallLog returns the mock zboot call log for verification
func (tc *TestContext) GetZbootCallLog() []string {
	tc.T.Helper()
	return tc.MockPartitionManager.GetCallLog()
}

// ClearZbootCallLog clears the zboot call log
func (tc *TestContext) ClearZbootCallLog() {
	tc.T.Helper()
	tc.MockPartitionManager.ClearCallLog()
}

// AssertZbootCallContains asserts that the call log contains a specific call
func (tc *TestContext) AssertZbootCallContains(expectedCall string) {
	tc.T.Helper()
	callLog := tc.GetZbootCallLog()
	for _, call := range callLog {
		if call == expectedCall {
			return
		}
	}
	tc.T.Fatalf("Expected zboot call log to contain '%s', but it didn't.\nCall log: %v", expectedCall, callLog)
}

// AssertNoZbootCalls asserts that no zboot calls were made (except GetCurrentPartition during init)
func (tc *TestContext) AssertNoZbootCalls() {
	tc.T.Helper()
	callLog := tc.GetZbootCallLog()

	// Filter out GetCurrentPartition calls which happen during normal initialization
	relevantCalls := []string{}
	for _, call := range callLog {
		// Only count SetPartitionState calls and other mutation operations
		if len(call) > 18 && call[:18] == "SetPartitionState(" {
			relevantCalls = append(relevantCalls, call)
		}
	}

	if len(relevantCalls) > 0 {
		tc.T.Fatalf("Expected no zboot mutation calls, but found: %v", relevantCalls)
	}
}

// Stop gracefully stops the run() loop for testing
func (tc *TestContext) Stop() {
	tc.T.Helper()
	tc.stopOnce.Do(func() {
		close(tc.EvalContext.stopChan)
	})
}

// SetPartitionState sets a partition to a named state for testing
// Maps logical state names to GPT attributes for test setup
func (tc *TestContext) SetPartitionState(partition string, state string) {
	tc.T.Helper()

	var priority, tries int
	var successful bool

	// Map state names to GPT attributes
	switch state {
	case "scheduled":
		priority, tries, successful = 3, 1, false // 0x013
	case "inprogress":
		priority, tries, successful = 3, 0, false // 0x003
	case "good":
		priority, tries, successful = 2, 0, true // 0x102
	case "best", "active":
		priority, tries, successful = 3, 0, true // 0x103
	case "bad", "unused":
		priority, tries, successful = 0, 0, false // 0x000
	case "testing":
		// Legacy state - map to inprogress
		priority, tries, successful = 3, 0, false // 0x003
	default:
		tc.T.Fatalf("Unknown state: %s", state)
	}

	// Construct uint16 attribute value from components
	// Bit layout: bits 0-3=priority, bits 4-7=tries, bit 8=successful
	attr := uint16(priority) | (uint16(tries) << 4)
	if successful {
		attr |= (1 << 8)
	}

	err := tc.MockPartitionManager.SetPartitionAttributes(partition, attr)
	if err != nil {
		tc.T.Fatalf("Failed to set partition %s to state %s: %v", partition, state, err)
	}
}
