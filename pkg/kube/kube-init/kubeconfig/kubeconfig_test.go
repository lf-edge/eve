// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubeconfig

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// resetForTest wipes the package-level cache so tests don't see
// each other's state.
func resetForTest(t *testing.T) {
	t.Helper()
	mu.Lock()
	have = false
	cached = types.KubeConfig{}
	mu.Unlock()
}

func TestGet_EmptyState(t *testing.T) {
	resetForTest(t)
	if _, ok := Get(); ok {
		t.Errorf("Get() ok=true on empty state")
	}
	if v := K3sVersion(); v != "" {
		t.Errorf("K3sVersion() = %q on empty state, want \"\"", v)
	}
}

func TestSetCached_PopulatesGetters(t *testing.T) {
	resetForTest(t)
	want := types.KubeConfig{K3sVersion: "v1.34.2+k3s1"}
	setCached(want)

	got, ok := Get()
	if !ok {
		t.Fatalf("Get() ok=false after setCached")
	}
	if got.K3sVersion != want.K3sVersion {
		t.Errorf("Get() = %+v, want %+v", got, want)
	}
	if v := K3sVersion(); v != want.K3sVersion {
		t.Errorf("K3sVersion() = %q, want %q", v, want.K3sVersion)
	}
}

// TestK3sVersion_EmptyOverride pins the behaviour the caller
// (update.getDesiredK3sVersion) relies on: an explicit empty
// override is indistinguishable from "no delivery yet" — both
// yield "" and the caller falls back to the compile-time default.
func TestK3sVersion_EmptyOverride(t *testing.T) {
	resetForTest(t)
	setCached(types.KubeConfig{K3sVersion: ""})
	if v := K3sVersion(); v != "" {
		t.Errorf("K3sVersion() with empty override = %q, want \"\"", v)
	}
	// Get should still report ok=true (delivery happened), so a
	// caller that DOES want to distinguish them has the info.
	if _, ok := Get(); !ok {
		t.Errorf("Get() ok=false after a real but empty delivery")
	}
}

func TestHandleModify_LatestWins(t *testing.T) {
	resetForTest(t)
	setCached(types.KubeConfig{K3sVersion: "v1.34.0+k3s1"})
	handleModify(nil, "global",
		types.KubeConfig{K3sVersion: "v1.34.2+k3s1"}, nil)
	if v := K3sVersion(); v != "v1.34.2+k3s1" {
		t.Errorf("K3sVersion() = %q, want latest write v1.34.2+k3s1", v)
	}
}

func TestHandleDelete_MarksCacheEmpty(t *testing.T) {
	resetForTest(t)
	setCached(types.KubeConfig{K3sVersion: "v1.34.2+k3s1"})
	handleDelete(nil, "global", nil)
	if _, ok := Get(); ok {
		t.Errorf("Get() ok=true after handleDelete")
	}
	if v := K3sVersion(); v != "" {
		t.Errorf("K3sVersion() = %q after handleDelete, want \"\"", v)
	}
}
