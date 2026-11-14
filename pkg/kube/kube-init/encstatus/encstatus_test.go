// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package encstatus

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

func TestGet_EmptyState(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	if _, ok := Get(); ok {
		t.Errorf("Get() ok=true on empty state")
	}
	if Present() {
		t.Errorf("Present() = true on empty state")
	}
}

func TestPresent_ZeroUUIDReadsAsAbsent(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	// Pillar publishes a payload with zero ClusterID to signal a
	// controller-side cluster delete on a non-Persistent topic.
	setCached(types.EdgeNodeClusterStatus{
		ClusterID: types.UUIDandVersion{UUID: uuid.Nil},
	})
	if _, ok := Get(); !ok {
		t.Fatal("Get() ok=false after setCached")
	}
	if Present() {
		t.Errorf("Present() = true with zero ClusterID, want false")
	}
}

func TestPresent_NonZeroUUID(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	cid := uuid.FromStringOrNil("11111111-2222-3333-4444-555555555555")
	setCached(types.EdgeNodeClusterStatus{
		ClusterID: types.UUIDandVersion{UUID: cid},
	})
	if !Present() {
		t.Errorf("Present() = false with non-zero ClusterID")
	}
}

func TestHandleDelete_MarksCacheEmpty(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	cid := uuid.FromStringOrNil("11111111-2222-3333-4444-555555555555")
	setCached(types.EdgeNodeClusterStatus{
		ClusterID: types.UUIDandVersion{UUID: cid},
	})
	handleDelete(nil, "global", nil)
	if _, ok := Get(); ok {
		t.Errorf("Get() ok=true after handleDelete")
	}
	if Present() {
		t.Errorf("Present() = true after handleDelete")
	}
}

func TestHandleModify_LatestWins(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	setCached(types.EdgeNodeClusterStatus{ClusterInterface: "eth0"})
	handleModify(nil, "global",
		types.EdgeNodeClusterStatus{ClusterInterface: "eth1"}, nil)
	got, _ := Get()
	if got.ClusterInterface != "eth1" {
		t.Errorf("ClusterInterface = %q after modify, want eth1", got.ClusterInterface)
	}
}
