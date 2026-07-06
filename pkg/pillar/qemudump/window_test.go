// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package qemudump

import "testing"

const (
	kib = 1 << 10
	mib = 1 << 20
	gib = 1 << 30
)

// ChooseWindowLog picks the largest zstd windowLog whose estimated encoder RAM
// (perWorkerRAM * concurrency) fits the budget, clamped to [minWindowLog,
// maxWindowLog]. The estimate is perWorkerRAM(wl) = 3 * (1<<wl).
func TestChooseWindowLog(t *testing.T) {
	cases := []struct {
		name        string
		budget      uint64
		concurrency int
		want        uint8
	}{
		{"512MiB budget, 1 worker -> 128MiB window", 512 * mib, 1, 27},
		{"256MiB budget, 1 worker -> 64MiB window", 256 * mib, 1, 26},
		{"64MiB budget, 1 worker -> 16MiB window", 64 * mib, 1, 24},
		{"24MiB budget, 1 worker -> 8MiB window", 24 * mib, 1, 23},
		{"512MiB budget, 2 workers -> 64MiB window", 512 * mib, 2, 26},
		{"tiny budget clamps to floor", 1, 1, minWindowLog},
		{"huge budget clamps to cap", 1 << 60, 1, maxWindowLog},
		{"zero concurrency treated as 1", 64 * mib, 0, 24},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ChooseWindowLog(tc.budget, tc.concurrency)
			if got != tc.want {
				t.Fatalf("ChooseWindowLog(%d, %d) = %d, want %d",
					tc.budget, tc.concurrency, got, tc.want)
			}
		})
	}
}

// ChooseWindowLog must be monotonic non-decreasing in budget and non-increasing
// in concurrency, so a bigger memory budget never shrinks the window and adding
// workers never grows it.
func TestChooseWindowLogMonotonic(t *testing.T) {
	var prev uint8
	for budget := uint64(mib); budget <= 4*gib; budget *= 2 {
		got := ChooseWindowLog(budget, 1)
		if got < prev {
			t.Fatalf("budget %d gave windowLog %d, smaller than previous %d", budget, got, prev)
		}
		prev = got
	}
	if a, b := ChooseWindowLog(512*mib, 1), ChooseWindowLog(512*mib, 4); a < b {
		t.Fatalf("more workers grew the window: 1w=%d 4w=%d", a, b)
	}
}
