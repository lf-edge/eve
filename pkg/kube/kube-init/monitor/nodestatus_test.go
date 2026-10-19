// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"encoding/json"
	"testing"
	"time"
)

// TestSameAnnotations guards the check that keeps an unchanged tick from
// writing. Recovery status changes rarely and the tick runs every 15
// seconds, so patching regardless would be a steady stream of writes
// into etcd carrying no new information.
func TestSameAnnotations(t *testing.T) {
	cases := []struct {
		name string
		a, b map[string]string
		want bool
	}{
		{"both empty", map[string]string{}, map[string]string{}, true},
		{"identical", map[string]string{"k": "v"}, map[string]string{"k": "v"}, true},
		{"value differs", map[string]string{"k": "v"}, map[string]string{"k": "w"}, false},
		{"key added", map[string]string{"k": "v"},
			map[string]string{"k": "v", "j": "u"}, false},
		{"key removed", map[string]string{"k": "v", "j": "u"},
			map[string]string{"k": "v"}, false},
		{"against nil", map[string]string{"k": "v"}, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sameAnnotations(c.a, c.b); got != c.want {
				t.Errorf("sameAnnotations(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
			}
		})
	}
}

// TestRecoveryStatus pins when a node has a recovery status to report. A
// node that was never the seed holds a bump pending, so its applied
// generation trails the controller's with nothing owed, and reporting it
// would show a recovery that is not happening.
func TestRecoveryStatus(t *testing.T) {
	at := time.Date(2026, 10, 29, 18, 12, 38, 0, time.UTC)
	begun := at.Add(time.Hour)
	cases := []struct {
		name       string
		state      recoveryState
		wantNil    bool
		applied    uint32
		converging bool
		transition time.Time
		wantErr    bool
	}{
		{"never recorded", recoveryState{}, true, 0, false, time.Time{}, false},
		{"seed at its generation", recoveryState{applied: 1, recorded: true, asSeed: true, appliedAt: at},
			false, 1, false, at, false},
		{"non-seed holding a pending bump", recoveryState{applied: 0, recorded: true, appliedAt: at},
			true, 0, false, time.Time{}, false},
		{"non-seed converging", recoveryState{applied: 0, recorded: true, appliedAt: at, intent: &begun},
			false, 0, true, begun, false},
		{"seed converging", recoveryState{applied: 1, recorded: true, asSeed: true, appliedAt: at, intent: &begun},
			false, 1, true, begun, false},
		{"non-seed with a failure", recoveryState{applied: 0, recorded: true, appliedAt: at, failure: "rejected"},
			false, 0, false, at, true},
		{"failure before anything was recorded", recoveryState{failure: "rejected"},
			false, 0, false, time.Time{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.state.status()
			if c.wantNil {
				if got != nil {
					t.Fatalf("status() = %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("status() = nil, want a status")
			}
			if got.AppliedGeneration != c.applied || got.Converging != c.converging ||
				!got.LastTransitionAt.Equal(c.transition) || (got.Error.Error != "") != c.wantErr {
				t.Errorf("status() = %+v, want applied %d converging %v at %v error %v",
					got, c.applied, c.converging, c.transition, c.wantErr)
			}
		})
	}
}

// TestStatusPatch checks that a removed annotation is a null in the merge
// patch, which is what deletes it, and that the others are set.
func TestStatusPatch(t *testing.T) {
	patch, err := statusPatch(map[string]string{"set": "v"}, []string{"gone"})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Metadata struct {
			Annotations map[string]*string
		}
	}
	if err := json.Unmarshal(patch, &got); err != nil {
		t.Fatal(err)
	}
	ann := got.Metadata.Annotations
	if v, ok := ann["set"]; !ok || v == nil || *v != "v" {
		t.Errorf("set annotation = %v, want v", v)
	}
	if v, ok := ann["gone"]; !ok || v != nil {
		t.Errorf("removed annotation = %v present %v, want an explicit null", v, ok)
	}
}
