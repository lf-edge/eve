// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"testing"
)

func TestKubeInitStatusComponentPassOver(t *testing.T) {
	cases := []struct {
		name   string
		status KubeInitStatus
		want   bool
	}{
		{"nothing published yet", KubeInitStatus{}, false},
		{"pass running", KubeInitStatus{State: "WAIT_UPGRADE", UpdateState: "in_progress"}, false},
		{"before the pass", KubeInitStatus{State: "WAIT_K3S_READY", UpdateState: "none"}, false},
		{"no pass needed", KubeInitStatus{State: "RUNNING", ComponentsReady: true, UpdateState: "none"}, true},
		{"pass completed", KubeInitStatus{State: "RUNNING", ComponentsReady: true, UpdateState: "completed"}, true},
		{"pass failed", KubeInitStatus{State: "RUNNING", UpdateState: KubeInitUpdateStateFailed}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.status.ComponentPassOver(); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestKubeInitStatusDecodesPublisherPayload pins the field names shared
// with kube-init's own struct, and that the fields pillar does not mirror
// are ignored.
func TestKubeInitStatusDecodesPublisherPayload(t *testing.T) {
	payload := `{"AllComponentsInitialized":true,"State":"RUNNING",
		"Phase":"steady","Membership":"Single","ComponentsReady":true,
		"UpdateState":"completed","UpdateError":"",
		"UpdatedAt":"2026-11-17T10:00:00Z"}`
	var status KubeInitStatus
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		t.Fatal(err)
	}
	if !status.ComponentsReady || status.UpdateState != "completed" ||
		status.State != "RUNNING" || status.UpdatedAt.IsZero() {
		t.Errorf("decoded %+v", status)
	}
}
