// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kcus

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func TestGet_EmptyState(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	if _, ok := Get(); ok {
		t.Errorf("Get() ok=true on empty state")
	}
}

func TestSetCached_PopulatesGet(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	want := types.KubeClusterUpdateStatus{
		CurrentNode:                  "edge-01",
		Component:                    types.CompK3s,
		Status:                       types.CompStatusFailed,
		DestinationKubeUpdateVersion: 3,
	}
	setCached(want)

	got, ok := Get()
	if !ok {
		t.Fatalf("Get() ok=false after setCached")
	}
	if got.Status != want.Status ||
		got.DestinationKubeUpdateVersion != want.DestinationKubeUpdateVersion {
		t.Errorf("Get() = %+v, want %+v", got, want)
	}
}

func TestHandleModify_LatestWins(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	setCached(types.KubeClusterUpdateStatus{
		Status:                       types.CompStatusInProgress,
		DestinationKubeUpdateVersion: 3,
	})
	handleModify(nil, "global", types.KubeClusterUpdateStatus{
		Status:                       types.CompStatusCompleted,
		DestinationKubeUpdateVersion: 3,
	}, nil)

	got, ok := Get()
	if !ok {
		t.Fatalf("Get() ok=false after handleModify")
	}
	if got.Status != types.CompStatusCompleted {
		t.Errorf("Status = %v, want CompStatusCompleted (latest write wins)", got.Status)
	}
}

func TestHandleDelete_MarksCacheEmpty(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	setCached(types.KubeClusterUpdateStatus{Status: types.CompStatusFailed})
	handleDelete(nil, "global", nil)
	if _, ok := Get(); ok {
		t.Errorf("Get() ok=true after handleDelete")
	}
}

func TestSetForTest_ExportedHelper(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	SetForTest(types.KubeClusterUpdateStatus{
		Status:                       types.CompStatusFailed,
		DestinationKubeUpdateVersion: 7,
	})
	got, ok := Get()
	if !ok || got.DestinationKubeUpdateVersion != 7 {
		t.Errorf("Get() after SetForTest = %+v ok=%v, want destination=7 ok=true", got, ok)
	}
}
