// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"fmt"
	"sort"
)

// MockGptAccess implements GptAttributeAccess for testing
// This allows testing the real PartitionManager business logic with simulated GPT access
// IMPORTANT: This is DUMB storage - just stores raw uint16 attributes, no logic!
type MockGptAccess struct {
	currentSlot string
	partitions  map[string]uint16 // partition label -> raw GPT attribute (uint16)
	validLabels []string
	callLog     []string // Track method calls for test verification
}

// NewMockGptAccess creates a new mock GPT accessor with default evaluation platform setup
// Initial state: all partitions "scheduled" (0x013 = priority=3, tries=1, successful=0)
func NewMockGptAccess() *MockGptAccess {
	return &MockGptAccess{
		currentSlot: "", // No partition booted yet
		partitions: map[string]uint16{
			"IMGA": 0x013, // scheduled
			"IMGB": 0x013, // scheduled
			"IMGC": 0x013, // scheduled
		},
		validLabels: []string{"IMGA", "IMGB", "IMGC"},
	}
}

// ============================================================================
// GptAttributeAccess Interface Implementation (low-level primitives)
// ============================================================================

// GetPartitionAttributes returns the raw GPT attribute value for a partition
// DUMB STORAGE: Just returns the stored uint16 value, no logic!
func (m *MockGptAccess) GetPartitionAttributes(partition string) (uint16, error) {
	m.logCall("GetPartitionAttributes(%s)", partition)

	attr, exists := m.partitions[partition]
	if !exists {
		return 0, fmt.Errorf("partition %s not found", partition)
	}

	return attr, nil
}

// SetPartitionAttributes sets the raw GPT attribute value for a partition
// DUMB STORAGE: Just stores the uint16 value, no logic!
func (m *MockGptAccess) SetPartitionAttributes(partition string, attr uint16) error {
	m.logCall("SetPartitionAttributes(%s, 0x%03x)", partition, attr)

	_, exists := m.partitions[partition]
	if !exists {
		return fmt.Errorf("partition %s not found", partition)
	}

	m.partitions[partition] = attr
	return nil
}

// GetCurrentPartition returns the currently booted partition label
func (m *MockGptAccess) GetCurrentPartition() string {
	m.logCall("GetCurrentPartition() -> %s", m.currentSlot)
	return m.currentSlot
}

// GetValidPartitionLabels returns all valid partition labels
func (m *MockGptAccess) GetValidPartitionLabels() []string {
	m.logCall("GetValidPartitionLabels() -> %v", m.validLabels)
	return m.validLabels
}

// ============================================================================
// Test Helper Methods (not part of interfaces)
// ============================================================================

// SimulateReboot simulates a GRUB boot cycle using the common GRUB simulator
// This is a convenience method for tests that don't use TestContext
func (m *MockGptAccess) SimulateReboot() (string, error) {
	selected, err := SimulateGrubBoot(m, nil)
	if err != nil {
		return "", err
	}
	m.SetCurrentSlot(selected)
	return selected, nil
}

// SetCurrentSlot sets the current slot (used by TestContext during boot simulation)
func (m *MockGptAccess) SetCurrentSlot(slot string) {
	m.currentSlot = slot
	m.logCall("SetCurrentSlot(%s)", slot)
}

// GetPartitionStateString returns a human-readable state string for debugging
func (m *MockGptAccess) GetPartitionStateString(partition string) string {
	attr, exists := m.partitions[partition]
	if !exists {
		return "unknown"
	}

	// Map attribute value to logical state names
	switch attr {
	case 0x000:
		return "bad"
	case 0x013:
		return "scheduled"
	case 0x003:
		return "inprogress"
	case 0x102:
		return "good"
	case 0x103:
		return "best"
	default:
		// Extract for custom display
		priority := attr & 0xF
		triesLeft := (attr >> 4) & 0xF
		successful := (attr >> 8) & 0x1
		return fmt.Sprintf("custom(p=%d,t=%d,s=%v)", priority, triesLeft, successful != 0)
	}
}

// DumpState returns a human-readable state dump for debugging
func (m *MockGptAccess) DumpState() string {
	result := fmt.Sprintf("Current: %s\n", m.currentSlot)
	result += "Partitions:\n"

	// Sort labels for deterministic output
	labels := make([]string, 0, len(m.partitions))
	for label := range m.partitions {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	for _, label := range labels {
		attr := m.partitions[label]
		stateStr := m.GetPartitionStateString(label)
		// Extract for display
		priority := attr & 0xF
		triesLeft := (attr >> 4) & 0xF
		successful := (attr >> 8) & 0x1
		result += fmt.Sprintf("  %s: %s (p=%d, t=%d, s=%v)\n",
			label, stateStr, priority, triesLeft, successful != 0)
	}

	return result
}

// GetCallLog returns the log of method calls for verification
func (m *MockGptAccess) GetCallLog() []string {
	return append([]string{}, m.callLog...) // Return copy
}

// ClearCallLog clears the method call log
func (m *MockGptAccess) ClearCallLog() {
	m.callLog = []string{}
}

// WasSetAttributesCalled checks if SetPartitionAttributes was called with specific partition and attribute value
func (m *MockGptAccess) WasSetAttributesCalled(partition string, attr uint16) bool {
	expectedCall := fmt.Sprintf("SetPartitionAttributes(%s, 0x%03x)", partition, attr)
	for _, call := range m.callLog {
		if call == expectedCall {
			return true
		}
	}
	return false
}

// WasCalledWith checks if a specific method call pattern exists in the call log
func (m *MockGptAccess) WasCalledWith(pattern string) bool {
	for _, call := range m.callLog {
		if call == pattern {
			return true
		}
	}
	return false
}

// logCall records a method call for test verification
func (m *MockGptAccess) logCall(format string, args ...interface{}) {
	m.callLog = append(m.callLog, fmt.Sprintf(format, args...))
}

// Compile-time check
var _ GptAttributeAccess = (*MockGptAccess)(nil)
