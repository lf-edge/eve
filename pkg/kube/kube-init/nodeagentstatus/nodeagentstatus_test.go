// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagentstatus

import (
	"encoding/json"
	"testing"
)

func TestUpdateAllowed(t *testing.T) {
	cases := []struct {
		name   string
		status *NodeAgentStatus
		want   bool
	}{
		{"nothing published yet", nil, false},
		{"image not under test", &NodeAgentStatus{}, true},
		{"under test, controller not reached", &NodeAgentStatus{UpdateInprogress: true}, false},
		{"under test, controller reached",
			&NodeAgentStatus{UpdateInprogress: true, ControllerReached: true}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ResetForTest()
			t.Cleanup(ResetForTest)
			if c.status != nil {
				SetForTest(*c.status)
			}
			if got := UpdateAllowed(); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// TestDecodesPublisherPayload pins the field names shared with pillar's
// types.NodeAgentStatus.
func TestDecodesPublisherPayload(t *testing.T) {
	payload := `{"Name":"nodeagent","CurPart":"IMGB","UpdateInprogress":true,
		"ControllerReached":true,"RemainingTestTime":0,"HVTypeKube":true}`
	var status NodeAgentStatus
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		t.Fatal(err)
	}
	if status.Key() != "nodeagent" || !status.UpdateInprogress || !status.ControllerReached {
		t.Errorf("decoded %+v", status)
	}
}
