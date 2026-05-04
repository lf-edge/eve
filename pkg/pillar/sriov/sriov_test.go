// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package sriov

import (
	"testing"
)

// TestParseVfIfaceName covers the round-trip with GetVfIfaceName plus a few
// edge cases.  The previous implementation used fmt.Sscanf with "%svf%d",
// which always returned ("", 0, error) because %s is greedy — regression
// test guards against falling back to that.
func TestParseVfIfaceName(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantIdx uint8
		wantPF  string
		wantErr bool
	}{
		{"basic", "eth2vf0", 0, "eth2", false},
		{"two_digit", "eth3vf19", 19, "eth3", false},
		{"five", "eth2vf5", 5, "eth2", false},
		{"renamed_pf", "keth2vf7", 7, "keth2", false},
		{"max_uint8", "ethxvf255", 255, "ethx", false},

		// Failure modes — must error, not silently return zero.
		{"no_vf_suffix", "eth2", 0, "", true},
		{"empty", "", 0, "", true},
		{"vf_only", "vf0", 0, "", true},
		{"non_numeric", "eth2vfabc", 0, "", true},
		{"overflow_uint8", "eth2vf256", 0, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idx, pf, err := ParseVfIfaceName(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if idx != tc.wantIdx {
				t.Errorf("idx=%d want %d", idx, tc.wantIdx)
			}
			if pf != tc.wantPF {
				t.Errorf("pf=%q want %q", pf, tc.wantPF)
			}
		})
	}
}

// TestParseVfIfaceNameRoundtrip ensures Parse(Get(idx, pf)) == (idx, pf) for
// every plausible (PF, VF index) combination — protects against a future
// rename mismatch between the two helpers.
func TestParseVfIfaceNameRoundtrip(t *testing.T) {
	pfs := []string{"eth0", "eth2", "keth2", "enp1s0f0"}
	for _, pf := range pfs {
		for _, idx := range []uint8{0, 1, 5, 19, 63, 255} {
			name := GetVfIfaceName(idx, pf)
			gotIdx, gotPF, err := ParseVfIfaceName(name)
			if err != nil {
				t.Errorf("PF=%s idx=%d name=%q parse error: %v", pf, idx, name, err)
				continue
			}
			if gotIdx != idx || gotPF != pf {
				t.Errorf("PF=%s idx=%d name=%q -> (%d, %q)", pf, idx, name, gotIdx, gotPF)
			}
		}
	}
}
