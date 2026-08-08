// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package encconfig

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
	if ct := ClusterType(); ct != types.ClusterTypeNone {
		t.Errorf("ClusterType() = %v on empty state, want ClusterTypeNone", ct)
	}
	if id := TieBreakerUUID(); id != "" {
		t.Errorf("TieBreakerUUID() = %q on empty state, want \"\"", id)
	}
}

func TestSetCached_PopulatesGetters(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	tbID := uuid.FromStringOrNil("11111111-2222-3333-4444-555555555555")
	setCached(types.EdgeNodeClusterConfig{
		ClusterType:      types.ClusterTypeReplicatedStorage,
		TieBreakerNodeID: types.UUIDandVersion{UUID: tbID},
	})

	if ct := ClusterType(); ct != types.ClusterTypeReplicatedStorage {
		t.Errorf("ClusterType() = %v, want ClusterTypeReplicatedStorage", ct)
	}
	if id := TieBreakerUUID(); id != tbID.String() {
		t.Errorf("TieBreakerUUID() = %q, want %q", id, tbID.String())
	}
}

func TestTieBreakerUUID_NilUUIDReadsAsEmpty(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	setCached(types.EdgeNodeClusterConfig{
		// TieBreakerNodeID with zero UUID (not configured).
		TieBreakerNodeID: types.UUIDandVersion{},
	})
	if id := TieBreakerUUID(); id != "" {
		t.Errorf("TieBreakerUUID() = %q with nil UUID, want \"\"", id)
	}
}

func TestHandleDelete_MarksCacheEmpty(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	setCached(types.EdgeNodeClusterConfig{ClusterType: types.ClusterTypeK3sBase})
	handleDelete(nil, "global", nil)
	if _, ok := Get(); ok {
		t.Errorf("Get() ok=true after handleDelete")
	}
	if ct := ClusterType(); ct != types.ClusterTypeNone {
		t.Errorf("ClusterType() = %v after delete, want ClusterTypeNone", ct)
	}
}

func TestHandleModify_LatestWins(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	setCached(types.EdgeNodeClusterConfig{ClusterType: types.ClusterTypeK3sBase})
	handleModify(nil, "global",
		types.EdgeNodeClusterConfig{ClusterType: types.ClusterTypeReplicatedStorage}, nil)
	if ct := ClusterType(); ct != types.ClusterTypeReplicatedStorage {
		t.Errorf("ClusterType() = %v, want latest write ReplicatedStorage", ct)
	}
}

// TestPresent_DistinguishesWithdrawalFromLateDelivery pins the rule the
// cluster-config monitor relies on to avoid converting a live cluster
// member back to a single node. The three states are genuinely
// different and only the last is a withdrawal:
//
//	no delivery yet   -> not present (say nothing, we know nothing)
//	real ClusterID    -> present     (controller wants a cluster)
//	zero ClusterID    -> not present (controller deleted the cluster;
//	                                  the non-Persistent publication
//	                                  stays but is zeroed)
func TestPresent_DistinguishesWithdrawalFromLateDelivery(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	if Present() {
		t.Error("Present() = true before any delivery")
	}

	setCached(types.EdgeNodeClusterConfig{
		ClusterID: types.UUIDandVersion{
			UUID: uuid.FromStringOrNil("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
		},
	})
	if !Present() {
		t.Error("Present() = false with a non-zero ClusterID")
	}

	// Controller-side delete on a non-Persistent topic: the publication
	// remains, its content is zeroed. Must read as "no cluster".
	setCached(types.EdgeNodeClusterConfig{})
	if Present() {
		t.Error("Present() = true for a zeroed ClusterID (controller deleted the cluster)")
	}

	setCached(types.EdgeNodeClusterConfig{
		ClusterID: types.UUIDandVersion{
			UUID: uuid.FromStringOrNil("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
		},
	})
	handleDelete(nil, "", nil)
	if Present() {
		t.Error("Present() = true after handleDelete")
	}
}
