// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"encoding/json"
	"testing"
)

// TestSameAnnotations guards the check that keeps an unchanged tick from
// writing. Status changes rarely and the tick runs every 15
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

// TestBuildStampPatch checks that an empty value becomes a JSON null,
// the merge-patch spelling of "delete this annotation".
func TestBuildStampPatch(t *testing.T) {
	patch, err := buildStampPatch(map[string]string{"set": "v", "gone": ""})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Metadata struct {
			Annotations map[string]*string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(patch, &got); err != nil {
		t.Fatal(err)
	}
	ann := got.Metadata.Annotations
	if v, ok := ann["set"]; !ok || v == nil || *v != "v" {
		t.Errorf("annotation %q = %v, want \"v\"", "set", v)
	}
	if v, ok := ann["gone"]; !ok || v != nil {
		t.Errorf("annotation %q = %v, want explicit null", "gone", v)
	}
}
