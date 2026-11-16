// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import "testing"

func TestCPUTopology_IsSet(t *testing.T) {
	cases := []struct {
		name string
		topo CPUTopology
		want bool
	}{
		{"zero", CPUTopology{}, false},
		{"full", CPUTopology{Sockets: 1, Cores: 2, Threads: 2}, true},
		{"missing threads", CPUTopology{Sockets: 1, Cores: 2}, false},
		{"missing cores", CPUTopology{Sockets: 1, Threads: 2}, false},
		{"missing sockets", CPUTopology{Cores: 2, Threads: 2}, false},
	}
	for _, c := range cases {
		if got := c.topo.IsSet(); got != c.want {
			t.Errorf("%s: IsSet()=%v want %v", c.name, got, c.want)
		}
	}
}
