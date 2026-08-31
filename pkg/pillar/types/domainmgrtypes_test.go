// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import "testing"

// A bare UUID must return an error instead of indexing a missing generation.
func TestDiskStatusGetPVCNameFromVolumeKeyNoGeneration(t *testing.T) {
	const id = "3b241101-e2bb-4255-8caf-4136c566a962"
	status := DiskStatus{VolumeKey: id}
	if _, err := status.GetPVCNameFromVolumeKey(); err == nil {
		t.Fatal("expected an error for a volume key without a generation")
	}
	status.VolumeKey = id + "#3"
	name, err := status.GetPVCNameFromVolumeKey()
	if err != nil || name != id+"-pvc-3" {
		t.Fatalf("valid volume key: got %q, %v", name, err)
	}
}
