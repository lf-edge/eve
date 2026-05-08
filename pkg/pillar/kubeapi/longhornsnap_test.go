// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package kubeapi

import (
	"testing"
)

// TestSetLonghornRecurringSnapshotIntegration exercises the create/update/delete
// state machine against a live cluster. Skipped when no cluster is available.
func TestSetLonghornRecurringSnapshotIntegration(t *testing.T) {
	if _, err := GetClientSet(); err != nil {
		t.Skipf("no local kube cluster: %v", err)
	}

	testCron := "0 3 * * *"

	// Create
	applied, err := SetLonghornRecurringSnapshot(testCron)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !applied {
		t.Fatal("create: expected applied=true")
	}

	// No-op (same cron)
	applied, err = SetLonghornRecurringSnapshot(testCron)
	if err != nil {
		t.Fatalf("no-op: %v", err)
	}
	if !applied {
		t.Fatal("no-op: expected applied=true")
	}

	// Update (different cron)
	newCron := "0 4 * * *"
	applied, err = SetLonghornRecurringSnapshot(newCron)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !applied {
		t.Fatal("update: expected applied=true")
	}

	// Delete
	applied, err = SetLonghornRecurringSnapshot("")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !applied {
		t.Fatal("delete: expected applied=true")
	}

	// Delete when already gone (no-op)
	applied, err = SetLonghornRecurringSnapshot("")
	if err != nil {
		t.Fatalf("delete no-op: %v", err)
	}
	if !applied {
		t.Fatal("delete no-op: expected applied=true")
	}
}
