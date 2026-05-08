// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// validateBaseOsConfig

func TestValidateBaseOsConfig_EmptyContentTreeRejected(t *testing.T) {
	initTestLog()
	cfg := types.BaseOsConfig{BaseOsVersion: "1.2.3", ContentTreeUUID: ""}
	err := validateBaseOsConfig(nil, cfg)
	if err == nil {
		t.Fatal("expected error for empty ContentTreeUUID")
	}
	if !strings.Contains(err.Error(), "empty ContentTreeUUID") {
		t.Fatalf("unexpected error text %q", err.Error())
	}
}

func TestValidateBaseOsConfig_NonEmptyAccepted(t *testing.T) {
	initTestLog()
	cfg := types.BaseOsConfig{BaseOsVersion: "1.2.3", ContentTreeUUID: "uuid-x"}
	if err := validateBaseOsConfig(nil, cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// appendError

func TestAppendError_FromEmpty(t *testing.T) {
	got := appendError("", "volumemgr", "boom")
	want := "volumemgr: boom\n\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAppendError_Stacks(t *testing.T) {
	got := appendError("a: 1\n\n", "b", "2")
	want := "a: 1\n\nb: 2\n\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// publishBaseOSMgrStatus is the simplest publish-and-stash test, useful
// to confirm the testCtx wiring.

func TestPublishBaseOSMgrStatus(t *testing.T) {
	tc := newTestCtx(t)
	tc.ctx.currentUpdateRetry = 7
	publishBaseOSMgrStatus(tc.ctx)

	got, err := tc.pubBaseOsMgrStatus.Get("global")
	if err != nil {
		t.Fatalf("BaseOSMgrStatus not published: %v", err)
	}
	st, ok := got.(types.BaseOSMgrStatus)
	if !ok {
		t.Fatalf("wrong published type: %T", got)
	}
	if st.CurrentRetryUpdateCounter != 7 {
		t.Fatalf("got counter %d, want 7", st.CurrentRetryUpdateCounter)
	}
}
