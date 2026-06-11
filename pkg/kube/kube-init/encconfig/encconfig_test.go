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
