// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"math"
	"testing"

	v2stats "github.com/containerd/cgroups/v3/cgroup2/stats"
)

func TestDomainMetricFromV2Stats(t *testing.T) {
	got := domainMetric(&v2stats.Metrics{
		Memory: &v2stats.MemoryStat{Usage: 300 << 20, MaxUsage: 400 << 20, UsageLimit: 1024 << 20},
		CPU:    &v2stats.CPUStat{UsageUsec: 2_500_000},
	})
	if got.UsedMemory != 300 || got.MaxUsedMemory != 400 || got.AllocatedMB != 1024 || got.AvailableMemory != 724 {
		t.Errorf("memory: %+v", got)
	}
	if got.CPUTotalNs != 2_500_000_000 || got.CPUScaled != 1 {
		t.Errorf("CPU: total %d ns, scaled %d; want 2500000000, 1", got.CPUTotalNs, got.CPUScaled)
	}
}

// "max" in memory.max arrives as MaxUint64.
func TestDomainMetricUnlimitedMemory(t *testing.T) {
	got := domainMetric(&v2stats.Metrics{Memory: &v2stats.MemoryStat{Usage: 10 << 20, UsageLimit: math.MaxUint64}})
	if got.AllocatedMB != 0 || got.AvailableMemory != 0 || got.UsedMemoryPercent != 0 || got.UsedMemory != 10 {
		t.Errorf("unlimited task: %+v", got)
	}
}

func TestDomainMetricWithoutStats(t *testing.T) {
	got := domainMetric(&v2stats.Metrics{})
	if got.UsedMemory != 0 || got.CPUTotalNs != 0 || got.CPUScaled != 1 {
		t.Errorf("empty metrics: %+v", got)
	}
}
