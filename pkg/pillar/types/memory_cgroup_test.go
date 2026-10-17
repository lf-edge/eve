// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"math"
	"runtime/debug"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup/cgrouptest"
)

func TestEveMemoryFromCgroupV2(t *testing.T) {
	cgrouptest.FakeTree(t, map[string]string{
		"eve/memory.max":                 "838860800\n",
		"eve/memory.current":             "500000000\n",
		"eve/memory.stat":                "anon 1\nkernel 4096\n",
		"eve/services/pillar/memory.max": "681574400\n",
	})
	for name, c := range map[string]struct {
		get  func() (uint64, error)
		want uint64
	}{
		"limit":        {GetEveMemoryLimitInBytes, 838860800},
		"usage":        {GetEveMemoryUsageInBytes, 500000000},
		"kmem":         {GetEveKmemUsageInBytes, 4096},
		"pillar limit": {GetPillarHardMemoryLimitInBytes, 681574400},
	} {
		got, err := c.get()
		if err != nil || got != c.want {
			t.Errorf("%s = %d, %v; want %d", name, got, err, c.want)
		}
	}
}

// 5.10/5.15 kernels have no "kernel" line in memory.stat.
func TestGetEveKmemUsageMissingKernelLine(t *testing.T) {
	cgrouptest.FakeTree(t, map[string]string{"eve/memory.stat": "anon 1\nfile 2\n"})
	got, err := GetEveKmemUsageInBytes()
	if err != nil || got != 0 {
		t.Errorf("GetEveKmemUsageInBytes() = %d, %v; want 0, nil", got, err)
	}
}

// pillar's cgroup without a memory limit must not turn into a negative Go
// memory limit.
func TestConfigureGOGCUnlimited(t *testing.T) {
	cgrouptest.FakeTree(t, map[string]string{"eve/services/pillar/memory.max": "max\n"})
	prevLimit, prevPercent := debug.SetMemoryLimit(-1), debug.SetGCPercent(-1)
	debug.SetGCPercent(prevPercent)
	t.Cleanup(func() { debug.SetMemoryLimit(prevLimit); debug.SetGCPercent(prevPercent) })

	if _, _, err := ConfigureGOGC(0, 100); err != nil {
		t.Fatal(err)
	}
	if got := debug.SetMemoryLimit(-1); got != math.MaxInt64 {
		t.Errorf("Go memory limit = %d, want %d (no limit)", got, int64(math.MaxInt64))
	}
}

// A limit too large to scale by 600/1000 in an int64 means no Go memory limit.
func TestConfigureGOGCHugeCgroupLimit(t *testing.T) {
	cgrouptest.FakeTree(t, map[string]string{"eve/services/pillar/memory.max": "18446744073709550000\n"})
	prevLimit, prevPercent := debug.SetMemoryLimit(-1), debug.SetGCPercent(-1)
	debug.SetGCPercent(prevPercent)
	t.Cleanup(func() { debug.SetMemoryLimit(prevLimit); debug.SetGCPercent(prevPercent) })

	if _, _, err := ConfigureGOGC(0, 100); err != nil {
		t.Fatal(err)
	}
	if got := debug.SetMemoryLimit(-1); got != math.MaxInt64 {
		t.Errorf("Go memory limit = %d, want %d (no limit)", got, int64(math.MaxInt64))
	}
}

func TestConfigureGOGCFromCgroupLimit(t *testing.T) {
	cgrouptest.FakeTree(t, map[string]string{"eve/services/pillar/memory.max": "1000000000\n"})
	prevLimit, prevPercent := debug.SetMemoryLimit(-1), debug.SetGCPercent(-1)
	debug.SetGCPercent(prevPercent)
	t.Cleanup(func() { debug.SetMemoryLimit(prevLimit); debug.SetGCPercent(prevPercent) })

	if _, _, err := ConfigureGOGC(0, 100); err != nil {
		t.Fatal(err)
	}
	if got := debug.SetMemoryLimit(-1); got != 600000000 {
		t.Errorf("Go memory limit = %d, want 600000000 (0.6 of memory.max)", got)
	}
}
