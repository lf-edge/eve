// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
)

func Test_filenameFilter_initialization(t *testing.T) {
	// Test that filenameFilter can be safely accessed without panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Accessing filenameFilter caused panic: %v", r)
		}
	}()

	// This should not panic if properly initialized
	value := filenameFilter.Load()
	if value == nil {
		t.Error("filenameFilter should not be nil after initialization")
	}

	// Verify it's initialized as an empty map
	filterMap, ok := value.(map[string]struct{})
	if !ok {
		t.Error("filenameFilter should be initialized as map[string]struct{}")
	}

	if filterMap == nil {
		t.Error("filenameFilter map should not be nil")
	}

	if len(filterMap) != 0 {
		t.Error("filenameFilter should be initialized as empty map")
	}
}
