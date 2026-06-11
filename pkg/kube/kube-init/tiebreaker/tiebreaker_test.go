// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package tiebreaker

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/encconfig"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

func TestStatusIsSelf(t *testing.T) {
	cases := []struct {
		tie, self string
		want      bool
	}{
		{"abc-123", "abc-123", true},
		{"abc-123", "def-456", false},
		{"", "abc-123", false},
		{"abc-123", "", false},
	}
	for _, c := range cases {
		if got := StatusIsSelf(c.tie, c.self); got != c.want {
			t.Errorf("StatusIsSelf(%q, %q) = %v, want %v",
				c.tie, c.self, got, c.want)
		}
	}
}

func TestNodeSelectorPatch(t *testing.T) {
	got := nodeSelectorPatch("tie-breaker-node", "false")
	want := `{"spec":{"template":{"spec":{"nodeSelector":{"tie-breaker-node":"false"}}}}}`
	if got != want {
		t.Errorf("nodeSelectorPatch = %q, want %q", got, want)
	}
	// JSON round-trips clean.
	var sink map[string]interface{}
	if err := json.Unmarshal([]byte(got), &sink); err != nil {
		t.Errorf("patch is not valid JSON: %v", err)
	}
}

// TestConfigIsSetAndGet covers the ConfigIsSet/ConfigGetNodeUUID
// branches via the encconfig package's test helpers. ResetForTest
// in t.Cleanup pins isolation between cases.
func TestConfigIsSetAndGet(t *testing.T) {
	want := uuid.FromStringOrNil("11111111-2222-3333-4444-555555555555")

	cases := []struct {
		name  string
		seed  *types.EdgeNodeClusterConfig // nil = no delivery
		set   bool
		uuid  string
		err   bool
	}{
		{
			name: "no delivery",
			set:  false,
			err:  true,
		},
		{
			name: "TieBreakerNodeID absent",
			seed: &types.EdgeNodeClusterConfig{},
			set:  false,
			err:  true,
		},
		{
			name: "TieBreakerNodeID has nil UUID",
			seed: &types.EdgeNodeClusterConfig{
				TieBreakerNodeID: types.UUIDandVersion{},
			},
			set: false,
			err: true,
		},
		{
			name: "TieBreakerNodeID set",
			seed: &types.EdgeNodeClusterConfig{
				TieBreakerNodeID: types.UUIDandVersion{UUID: want},
			},
			set:  true,
			uuid: want.String(),
			err:  false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			encconfig.ResetForTest()
			t.Cleanup(encconfig.ResetForTest)
			if c.seed != nil {
				encconfig.SetForTest(*c.seed)
			}
			if got := ConfigIsSet(); got != c.set {
				t.Errorf("ConfigIsSet() = %v, want %v", got, c.set)
			}
			got, err := ConfigGetNodeUUID()
			if (err != nil) != c.err {
				t.Errorf("ConfigGetNodeUUID err = %v, wantErr = %v", err, c.err)
			}
			if !c.err && got != c.uuid {
				t.Errorf("ConfigGetNodeUUID = %q, want %q", got, c.uuid)
			}
		})
	}
}

// TestLonghornNodeDisksParsing covers the JSON shape we depend on
// from `kubectl get nodes.longhorn.io -o json`.
func TestLonghornNodeDisksParsing(t *testing.T) {
	body := `{
		"spec": {
			"disks": {
				"default-disk-1": {"path": "/var/lib/longhorn"},
				"ssd-disk-2":     {"path": "/mnt/ssd"}
			}
		}
	}`
	var n longhornNodeDisks
	if err := json.Unmarshal([]byte(body), &n); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(n.Spec.Disks) != 2 {
		t.Errorf("got %d disks, want 2", len(n.Spec.Disks))
	}
	if _, ok := n.Spec.Disks["default-disk-1"]; !ok {
		t.Errorf("missing default-disk-1")
	}
	if _, ok := n.Spec.Disks["ssd-disk-2"]; !ok {
		t.Errorf("missing ssd-disk-2")
	}
}

// TestPackageDocMentionsClusterNodeCount is a trivial guard — if
// someone changes clusterNodeCount they should also update the
// package doc.
func TestClusterNodeCountIsThree(t *testing.T) {
	if clusterNodeCount != 3 {
		t.Errorf("clusterNodeCount = %d, want 3 (three-node HA cluster)",
			clusterNodeCount)
	}
	// Spot-check that downstream string formatting hasn't drifted.
	if !strings.Contains(nodeSelectorPatch("a", "b"), `"a":"b"`) {
		t.Errorf("nodeSelectorPatch shape changed")
	}
}
