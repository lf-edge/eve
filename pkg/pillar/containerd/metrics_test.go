// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"testing"

	v2stats "github.com/containerd/cgroups/v3/cgroup2/stats"
	"github.com/containerd/typeurl/v2"
)

// The shim marshals its cgroup v2 stats with typeurl; decodeMetrics must take
// exactly that encoding.
func TestDecodeMetrics(t *testing.T) {
	sent := &v2stats.Metrics{
		Memory: &v2stats.MemoryStat{Usage: 42, MaxUsage: 64, UsageLimit: 128},
		CPU:    &v2stats.CPUStat{UsageUsec: 7},
	}
	a, err := typeurl.MarshalAny(sent)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeMetrics(a.GetTypeUrl(), a.GetValue())
	if err != nil {
		t.Fatal(err)
	}
	if got.Memory.Usage != 42 || got.Memory.MaxUsage != 64 || got.Memory.UsageLimit != 128 || got.CPU.UsageUsec != 7 {
		t.Errorf("decoded %+v", got)
	}
}

func TestDecodeMetricsRejectsOtherMessages(t *testing.T) {
	a, err := typeurl.MarshalAny(&v2stats.PSIStats{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeMetrics(a.GetTypeUrl(), a.GetValue()); err == nil {
		t.Error("a message other than Metrics must be refused")
	}
}
