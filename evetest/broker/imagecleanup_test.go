// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"reflect"
	"testing"
)

func TestShouldEvict(t *testing.T) {
	const gib = uint64(bytesPerGiB)
	tests := []struct {
		name         string
		usage        diskUsage
		thresholdPct int
		minFreeGiB   int
		want         bool
	}{
		{"big disk over percentage but above floor", diskUsage{UsedPct: 90, FreeBytes: 300 * gib}, 90, 100, false},
		{"small disk over percentage and below floor", diskUsage{UsedPct: 95, FreeBytes: 20 * gib}, 90, 100, true},
		{"floor disabled keeps percentage-only: over", diskUsage{UsedPct: 90, FreeBytes: 300 * gib}, 90, 0, true},
		{"floor disabled keeps percentage-only: under", diskUsage{UsedPct: 89, FreeBytes: 1 * gib}, 90, 0, false},
		{"under percentage and below floor", diskUsage{UsedPct: 50, FreeBytes: 10 * gib}, 90, 100, false},
		{"exactly at floor is not below it", diskUsage{UsedPct: 95, FreeBytes: 100 * gib}, 90, 100, false},
		{"one byte under floor", diskUsage{UsedPct: 95, FreeBytes: 100*gib - 1}, 90, 100, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldEvict(tc.usage, tc.thresholdPct, tc.minFreeGiB)
			if got != tc.want {
				t.Errorf("shouldEvict(%+v, %d, %d) = %v, want %v",
					tc.usage, tc.thresholdPct, tc.minFreeGiB, got, tc.want)
			}
		})
	}
}

func TestStatDiskUsage(t *testing.T) {
	u, err := statDiskUsage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if u.UsedPct < 0 || u.UsedPct > 100 {
		t.Errorf("UsedPct out of range: %d", u.UsedPct)
	}
	if u.FreeBytes == 0 || u.FreeBytes > u.TotalBytes {
		t.Errorf("FreeBytes %d not in (0, TotalBytes=%d]", u.FreeBytes, u.TotalBytes)
	}
	if _, err := statDiskUsage("/nonexistent-evetest-path"); err == nil {
		t.Error("expected error for missing path")
	}
}

// runLoop drives evictWhilePressured with a scripted sequence of usages, one
// consumed per post-eviction re-check, and returns what was evicted.
func runLoop(ids []string, usages []diskUsage, thresholdPct, minFreeGiB int) ([]string, error) {
	var evicted []string
	i := 0
	err := evictWhilePressured(ids,
		func(id string) { evicted = append(evicted, id) },
		func() (diskUsage, error) {
			u := usages[i]
			i++
			return u, nil
		},
		func(u diskUsage) bool { return shouldEvict(u, thresholdPct, minFreeGiB) })
	return evicted, err
}

func TestEvictWhilePressured(t *testing.T) {
	const gib = uint64(bytesPerGiB)
	ids := []string{"a", "b", "c", "d"}
	pressured := func(free uint64) diskUsage { return diskUsage{UsedPct: 95, FreeBytes: free * gib} }

	t.Run("floor clears after two evictions", func(t *testing.T) {
		got, err := runLoop(ids, []diskUsage{pressured(10), pressured(50), pressured(120), pressured(0)}, 90, 100)
		if err != nil || !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
			// usages: after a=10 (<100 keep), after b=50 keep, after c=120 stop
			t.Errorf("got %v, %v; want [a b c]", got, err)
		}
	})
	t.Run("below, above stops after two", func(t *testing.T) {
		got, _ := runLoop(ids, []diskUsage{pressured(10), pressured(150), pressured(0)}, 90, 100)
		if !reflect.DeepEqual(got, []string{"a", "b"}) {
			t.Errorf("got %v, want [a b]", got)
		}
	})
	t.Run("percentage clears first", func(t *testing.T) {
		got, _ := runLoop(ids, []diskUsage{pressured(10), {UsedPct: 85, FreeBytes: 5 * gib}, pressured(0)}, 90, 100)
		if !reflect.DeepEqual(got, []string{"a", "b"}) {
			t.Errorf("got %v, want [a b]", got)
		}
	})
	t.Run("runs out of candidates", func(t *testing.T) {
		got, _ := runLoop(ids[:2], []diskUsage{pressured(1), pressured(1)}, 90, 100)
		if !reflect.DeepEqual(got, []string{"a", "b"}) {
			t.Errorf("got %v, want [a b]", got)
		}
	})
	t.Run("usage error aborts", func(t *testing.T) {
		boom := errors.New("boom")
		n := 0
		err := evictWhilePressured(ids, func(string) { n++ },
			func() (diskUsage, error) { return diskUsage{}, boom },
			func(diskUsage) bool { return true })
		if !errors.Is(err, boom) || n != 1 {
			t.Errorf("err=%v evictions=%d, want boom and 1", err, n)
		}
	})
}
