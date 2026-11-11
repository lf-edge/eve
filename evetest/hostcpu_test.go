// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"slices"
	"testing"
)

// A CPU left out of the topology would pass every check that two CPUs are on
// different cores, so a CPU that cannot be read fails the read instead. Only a
// missing package id is tolerated, as one socket.
func TestParseHostTopology(t *testing.T) {
	topo, err := parseHostTopology("0::0:0,2\n1::1:1,3\n2::0:0,2\n3::1:1,3\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := topo.IDs(); !slices.Equal(got, []uint32{0, 1, 2, 3}) {
		t.Fatalf("CPUs %v, want all four despite the missing package ids", got)
	}
	for _, tc := range []struct {
		a, b uint32
		same bool
	}{{0, 2, true}, {0, 1, false}} {
		same, err := topo.SameCore(tc.a, tc.b)
		if err != nil || same != tc.same {
			t.Errorf("SameCore(%d, %d) = %t, %v; want %t", tc.a, tc.b, same, err, tc.same)
		}
	}
	if _, err := topo.SameCore(0, 9); err == nil {
		t.Error("SameCore with a CPU the device does not have must be an error")
	}

	for name, out := range map[string]string{
		"no core id":          "0:0::0\n",
		"siblings without it": "0:0:0:1\n",
		"no siblings":         "0:0:0:\n",
		"a field missing":     "0:0:0\n",
		"not a CPU number":    "x:0:0:0\n",
	} {
		if _, err := parseHostTopology(out); err == nil {
			t.Errorf("%s: %q parsed without an error", name, out)
		}
	}
}
