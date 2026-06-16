// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package baseosmgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

func init() {
	// markerVerdict/declineReason/baseOsTargetChanged are pure, but
	// readResizeFailedMarker logs on a parse error, so the package log must exist.
	log = base.NewSourceLogObject(logrus.StandardLogger(), "baseosmgr-test", 0)
}

func TestMarkerVerdict(t *testing.T) {
	m := resizeFailedMarker{EveRelease: "1.2.3", Step: "shrink", RC: "1"}
	tests := []struct {
		name        string
		m           resizeFailedMarker
		ok          bool
		running     string
		wantDecline bool
		wantClear   bool
	}{
		{"no marker -> proceed", resizeFailedMarker{}, false, "1.2.3", false, false},
		{"same version -> decline", m, true, "1.2.3", true, false},
		{"different version -> clear+proceed", m, true, "9.9.9", false, true},
		{"unreadable version -> decline (fail-safe)", m, true, "", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decline, clear := markerVerdict(tt.m, tt.ok, tt.running)
			if (decline != "") != tt.wantDecline {
				t.Errorf("declineReason=%q, wantDecline=%v", decline, tt.wantDecline)
			}
			if clear != tt.wantClear {
				t.Errorf("clearStale=%v, want %v", clear, tt.wantClear)
			}
		})
	}
}

func TestDeclineReason(t *testing.T) {
	preserved := resizeFailedMarker{EveRelease: "1.2.3", Step: "shrink", RC: "1"}.declineReason()
	if !strings.Contains(preserved, "/persist preserved") {
		t.Errorf("preserved reason = %q", preserved)
	}
	if strings.Contains(preserved, "workloads lost") {
		t.Errorf("preserved reason must not claim workloads lost: %q", preserved)
	}

	recreated := resizeFailedMarker{EveRelease: "1.2.3", Step: "grow", RC: "2", PersistRecreated: true}.declineReason()
	if !strings.Contains(recreated, "workloads lost") {
		t.Errorf("recreated reason = %q", recreated)
	}
	// the failing step, rc, and EVE version must be visible to the operator
	for _, want := range []string{"grow", "rc=2", "1.2.3"} {
		if !strings.Contains(recreated, want) {
			t.Errorf("recreated reason %q missing %q", recreated, want)
		}
	}
}

func TestReadResizeFailedMarker(t *testing.T) {
	dir := t.TempDir()

	if _, ok := readResizeFailedMarker(dir); ok {
		t.Error("expected ok=false for an absent marker")
	}

	js := `{"eve_release":"1.2.3","step":"shrink","rc":"1","ts":"t","persist_recreated":true}`
	if err := os.WriteFile(filepath.Join(dir, resizeFailedMarkerName), []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}
	m, ok := readResizeFailedMarker(dir)
	if !ok {
		t.Fatal("expected ok=true for a valid marker")
	}
	if m.EveRelease != "1.2.3" || m.Step != "shrink" || m.RC != "1" || !m.PersistRecreated {
		t.Errorf("parsed marker = %+v", m)
	}

	if err := os.WriteFile(filepath.Join(dir, resizeFailedMarkerName), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := readResizeFailedMarker(dir); ok {
		t.Error("expected ok=false for a malformed marker")
	}
}

func TestRunningEveRelease(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "eve-release")
	saved := eveVersionFile
	eveVersionFile = p
	defer func() { eveVersionFile = saved }()

	if got := runningEveRelease(); got != "" {
		t.Errorf("missing file: got %q, want \"\"", got)
	}
	if err := os.WriteFile(p, []byte("1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := runningEveRelease(); got != "1.2.3" {
		t.Errorf("got %q, want 1.2.3", got)
	}
}

func TestAdvanceSubState(t *testing.T) {
	var st types.BaseOsStatus // ConvertSubState defaults to UNSPECIFIED

	advanceSubState(&st, types.DEVICE_SUBSTATE_CONVERT_CREATING_PARTITIONS)
	if st.ConvertSubState != types.DEVICE_SUBSTATE_CONVERT_CREATING_PARTITIONS {
		t.Fatalf("advance from UNSPECIFIED: got %v", st.ConvertSubState)
	}

	advanceSubState(&st, types.DEVICE_SUBSTATE_CONVERT_INSTALLING)
	if st.ConvertSubState != types.DEVICE_SUBSTATE_CONVERT_INSTALLING {
		t.Fatalf("advance to INSTALLING: got %v", st.ConvertSubState)
	}

	// An earlier phase must not roll the sub-state back: the no-shrink grow
	// path re-checks as proceed on the next update and must not regress.
	advanceSubState(&st, types.DEVICE_SUBSTATE_CONVERT_CREATING_PARTITIONS)
	if st.ConvertSubState != types.DEVICE_SUBSTATE_CONVERT_INSTALLING {
		t.Errorf("sub-state rolled back to %v; advance must be monotonic", st.ConvertSubState)
	}

	// Equal is a no-op.
	advanceSubState(&st, types.DEVICE_SUBSTATE_CONVERT_INSTALLING)
	if st.ConvertSubState != types.DEVICE_SUBSTATE_CONVERT_INSTALLING {
		t.Errorf("equal advance changed state to %v", st.ConvertSubState)
	}
}

func TestBaseOsTargetChanged(t *testing.T) {
	a := types.BaseOsConfig{BaseOsVersion: "1.0", ContentTreeUUID: "uuid-a"}
	tests := []struct {
		name   string
		oldCfg types.BaseOsConfig
		newCfg types.BaseOsConfig
		want   bool
	}{
		{"identical", a, a, false},
		{"version changed", a, types.BaseOsConfig{BaseOsVersion: "2.0", ContentTreeUUID: "uuid-a"}, true},
		{"content tree changed", a, types.BaseOsConfig{BaseOsVersion: "1.0", ContentTreeUUID: "uuid-b"}, true},
		{"only activate", a, types.BaseOsConfig{BaseOsVersion: "1.0", ContentTreeUUID: "uuid-a", Activate: true}, false},
		{"only retry counter", a, types.BaseOsConfig{BaseOsVersion: "1.0", ContentTreeUUID: "uuid-a", RetryUpdateCounter: 5}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := baseOsTargetChanged(tt.oldCfg, tt.newCfg); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
