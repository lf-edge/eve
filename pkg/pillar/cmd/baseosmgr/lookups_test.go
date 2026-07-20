// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func TestLookupBaseOsConfig_Found(t *testing.T) {
	tc := newTestCtx(t)
	cfg := types.BaseOsConfig{BaseOsVersion: "1.2", ContentTreeUUID: "uuid-A"}
	tc.subBaseOsConfig.items[cfg.Key()] = cfg

	got := lookupBaseOsConfig(tc.ctx, "uuid-A")
	if got == nil {
		t.Fatal("expected lookup hit")
	}
	if got.BaseOsVersion != "1.2" {
		t.Fatalf("got %q", got.BaseOsVersion)
	}
}

func TestLookupBaseOsConfig_Missing(t *testing.T) {
	tc := newTestCtx(t)
	if got := lookupBaseOsConfig(tc.ctx, "absent"); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestLookupBaseOsStatus_Found(t *testing.T) {
	tc := newTestCtx(t)
	st := types.BaseOsStatus{BaseOsVersion: "9", ContentTreeUUID: "uuid-X"}
	tc.pubBaseOsStatus.items[st.Key()] = st

	got := lookupBaseOsStatus(tc.ctx, "uuid-X")
	if got == nil {
		t.Fatal("expected lookup hit")
	}
	if got.BaseOsVersion != "9" {
		t.Fatalf("got %q", got.BaseOsVersion)
	}
}

func TestLookupBaseOsStatus_Missing(t *testing.T) {
	tc := newTestCtx(t)
	if got := lookupBaseOsStatus(tc.ctx, "absent"); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestLookupBaseOsStatusByPartLabel_Mismatch(t *testing.T) {
	// status keyed by ContentTreeUUID; lookup uses partLabel as the
	// key, so a status whose Key() differs from the requested label is
	// returned by Get but rejected by the wrapper.
	tc := newTestCtx(t)
	st := types.BaseOsStatus{ContentTreeUUID: "IMGA"}
	tc.pubBaseOsStatus.items["IMGA"] = st
	if got := lookupBaseOsStatusByPartLabel(tc.ctx, "IMGA"); got == nil {
		t.Fatal("expected hit (Key matches the part label here)")
	}

	tc2 := newTestCtx(t)
	// Now the key in the map is "IMGA" but the embedded ContentTreeUUID
	// is something different — the lookup should reject it.
	tc2.pubBaseOsStatus.items["IMGA"] = types.BaseOsStatus{ContentTreeUUID: "uuid-other"}
	if got := lookupBaseOsStatusByPartLabel(tc2.ctx, "IMGA"); got != nil {
		t.Fatalf("expected rejection, got %+v", got)
	}
}

func TestLookupBaseOsStatusesByContentID(t *testing.T) {
	tc := newTestCtx(t)
	tc.pubBaseOsStatus.items["a"] = types.BaseOsStatus{ContentTreeUUID: "ct-1"}
	tc.pubBaseOsStatus.items["b"] = types.BaseOsStatus{ContentTreeUUID: "ct-2"}
	tc.pubBaseOsStatus.items["c"] = types.BaseOsStatus{ContentTreeUUID: "ct-1"}

	got := lookupBaseOsStatusesByContentID(tc.ctx, "ct-1")
	if len(got) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(got))
	}
	if got := lookupBaseOsStatusesByContentID(tc.ctx, "absent"); got != nil {
		t.Fatalf("expected nil for absent ct, got %+v", got)
	}
}

func TestLookupBaseOsConfigByVersion(t *testing.T) {
	tc := newTestCtx(t)
	tc.subBaseOsConfig.items["x"] = types.BaseOsConfig{BaseOsVersion: "13.4"}
	tc.subBaseOsConfig.items["y"] = types.BaseOsConfig{BaseOsVersion: "14.5"}

	got := lookupBaseOsConfigByVersion(tc.ctx, "14.5")
	if got == nil || got.BaseOsVersion != "14.5" {
		t.Fatalf("got %+v", got)
	}
	if got := lookupBaseOsConfigByVersion(tc.ctx, "absent"); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestLookupContentTreeStatus_FoundAndMissing(t *testing.T) {
	tc := newTestCtx(t)
	tc.subContentTreeStatus.items["ct-1"] = types.ContentTreeStatus{
		DisplayName: "rootfs",
	}
	if got := lookupContentTreeStatus(tc.ctx, "ct-1"); got == nil ||
		got.DisplayName != "rootfs" {
		t.Fatalf("got %+v", got)
	}
	if got := lookupContentTreeStatus(tc.ctx, "absent"); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}
