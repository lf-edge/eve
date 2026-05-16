// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package tiebreaker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
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

// TestReadENCC covers the JSON parsing branch via shadowed
// k3s.ClusterConfigFile.
func TestReadENCC(t *testing.T) {
	dir := t.TempDir()
	encc := filepath.Join(dir, "encc.json")
	orig := k3s.ClusterConfigFile
	k3s.ClusterConfigFile = encc
	t.Cleanup(func() { k3s.ClusterConfigFile = orig })

	// Missing file → error.
	if _, err := readENCC(); err == nil {
		t.Error("expected error for missing ENCC file")
	}
	if ConfigIsSet() {
		t.Error("ConfigIsSet should be false when ENCC missing")
	}

	// Malformed JSON → error.
	if err := os.WriteFile(encc, []byte("{not json"), 0644); err != nil {
		t.Fatalf("seed malformed: %v", err)
	}
	if _, err := readENCC(); err == nil {
		t.Error("expected parse error for malformed JSON")
	}

	// Valid but TieBreakerNodeID absent.
	if err := os.WriteFile(encc, []byte(`{}`), 0644); err != nil {
		t.Fatalf("seed empty: %v", err)
	}
	if ConfigIsSet() {
		t.Error("ConfigIsSet should be false when TieBreakerNodeID absent")
	}
	if _, err := ConfigGetNodeUUID(); err == nil {
		t.Error("ConfigGetNodeUUID should error when TieBreakerNodeID absent")
	}

	// Valid with TieBreakerNodeID empty UUID.
	if err := os.WriteFile(encc,
		[]byte(`{"TieBreakerNodeID":{"UUID":""}}`), 0644); err != nil {
		t.Fatalf("seed empty UUID: %v", err)
	}
	if ConfigIsSet() {
		t.Error("ConfigIsSet should be false when UUID is empty")
	}
	if _, err := ConfigGetNodeUUID(); err == nil {
		t.Error("ConfigGetNodeUUID should error when UUID empty")
	}

	// Valid with a UUID.
	if err := os.WriteFile(encc,
		[]byte(`{"TieBreakerNodeID":{"UUID":"abc-123"}}`), 0644); err != nil {
		t.Fatalf("seed valid: %v", err)
	}
	if !ConfigIsSet() {
		t.Error("ConfigIsSet should be true")
	}
	uuid, err := ConfigGetNodeUUID()
	if err != nil {
		t.Fatalf("ConfigGetNodeUUID: %v", err)
	}
	if uuid != "abc-123" {
		t.Errorf("uuid = %q, want %q", uuid, "abc-123")
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

// TestEnccJSONFieldNames smoke-tests the TieBreakerNodeID parse
// path with the canonical TitleCase keys zedagent writes.
func TestEnccJSONFieldNames(t *testing.T) {
	body := `{"TieBreakerNodeID":{"UUID":"x"}}`
	var e enccJSON
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.TieBreakerNodeID == nil || e.TieBreakerNodeID.UUID != "x" {
		t.Errorf("parsed = %+v, want UUID=x", e)
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
