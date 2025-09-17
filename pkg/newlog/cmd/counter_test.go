// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
)

func Test_logsToCount_initialization(t *testing.T) {
	// Test that logsToCount can be safely accessed without panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Accessing logsToCount caused panic: %v", r)
		}
	}()

	// This should not panic if properly initialized
	value := logsToCount.Load()
	if value == nil {
		t.Error("logsToCount should not be nil after initialization")
	}

	// Verify it's initialized as an empty slice
	slice, ok := value.([]string)
	if !ok {
		t.Errorf("logsToCount should be initialized as []string, got %T", value)
	}
	if len(slice) != 0 {
		t.Errorf("logsToCount should be initialized as empty slice, got length %d", len(slice))
	}
}
