// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import "testing"

func TestToK8sName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"node1", "node1"},
		{"NODE1", "node1"},
		{"my_node_01", "my-node-01"},
		{"Mixed_Case_Name", "mixed-case-name"},
		{"", ""},
		// Edge: leading/trailing underscores produce leading/trailing
		// dashes. Kubernetes will reject the label later — we surface
		// the bad name rather than silently mangle it further.
		{"_foo_", "-foo-"},
	}
	for _, tc := range cases {
		if got := ToK8sName(tc.in); got != tc.want {
			t.Errorf("ToK8sName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
