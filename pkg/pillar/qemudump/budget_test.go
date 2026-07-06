// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import "testing"

// ComputeBudget takes a bounded fraction (25%) of the compressor's available
// memory (the smaller of pillar's cgroup headroom and system RAM), hard-capped
// at 512 MiB, so the crash-time compressor can never claim more than a safe
// slice of pillar's headroom and OOM-kill zedbox.
func TestComputeBudget(t *testing.T) {
	cases := []struct {
		name  string
		avail uint64
		want  uint64
	}{
		{"lots of headroom caps at 512MiB", 8 * gib, 512 * mib},
		{"1GiB headroom uses 25%", 1 * gib, 256 * mib},
		{"512MiB headroom uses 25%", 512 * mib, 128 * mib},
		{"128MiB headroom uses 25%", 128 * mib, 32 * mib},
		{"tight cgroup, tiny budget", 40 * mib, 10 * mib},
		{"no headroom", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ComputeBudget(tc.avail); got != tc.want {
				t.Fatalf("ComputeBudget(%d) = %d, want %d", tc.avail, got, tc.want)
			}
		})
	}
}
