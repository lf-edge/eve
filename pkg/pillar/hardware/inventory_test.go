// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
)

// The assertions below run against the real /sys of whatever host the test runs
// on, so they are written as properties that hold on any Linux machine rather
// than against this machine's topology: one entry per online logical CPU, ids
// that agree with sysfs, and cache domains that name real CPUs. Reporting the
// wrong socket/NUMA/L3 id, or a core id where a schedulable CPU id belongs, is
// exactly the kind of mistake that makes a placement decision taken from this
// inventory land on the wrong CPUs.
func TestCreateInventory(t *testing.T) {
	_, log := agentlog.Init("someAgent")

	inventory, err := GetInventoryInfo(log)
	// often the tests do not run as root, do not fail in this case
	if inventory == nil || (err != nil && !errors.Is(err, os.ErrPermission)) {
		t.Fatalf("creating inventory failed: %v", err)
	}

	bytes, err := json.MarshalIndent(inventory, "\t", "\t")
	if err != nil {
		t.Fatalf("could not create json: %v", err)
	}
	t.Log(string(bytes))

	// The kernel isolation facts are a node-level answer that is always
	// available: empty sets mean "the kernel isolates nothing", which a
	// controller must be able to tell from "this build does not report it".
	if inventory.NodeCapabilities == nil {
		t.Error("NodeCapabilities is nil, so a controller cannot tell an " +
			"un-isolated node from an EVE that does not report isolation")
	}
	if inventory.CpuInfo == nil {
		t.Fatal("CpuInfo is nil")
	}

	online := onlineCPUsFromSysfs(t)
	if len(online) == 0 {
		t.Skip("cannot read the online CPU list from sysfs; " +
			"the per-CPU assertions below have nothing to compare against")
	}

	reported := map[uint32]*info.CPU{}
	for _, cpu := range inventory.CpuInfo.Cpus {
		if _, dup := reported[cpu.Id]; dup {
			t.Errorf("CPU %d reported twice", cpu.Id)
		}
		reported[cpu.Id] = cpu
	}
	// One entry per *logical* CPU. One entry per physical core instead would
	// hide the SMT structure and report core ids as if they were CPU ids.
	if len(reported) != len(online) {
		t.Errorf("reported %d CPUs, want %d online logical CPUs (%v)",
			len(reported), len(online), online)
	}
	for _, cpu := range online {
		got, ok := reported[cpu]
		if !ok {
			t.Errorf("online cpu%d is missing from the inventory", cpu)
			continue
		}
		if want, ok := sysfsCPUUint(t, cpu, "topology/core_id"); ok && got.CoreId != want {
			t.Errorf("cpu%d core_id reported as %d, sysfs says %d",
				cpu, got.CoreId, want)
		}
		// Absent on single-socket systems, where socket 0 is the right answer.
		want, present := sysfsCPUUint(t, cpu, "topology/physical_package_id")
		if !present {
			want = 0
		}
		if got.SocketId != want {
			t.Errorf("cpu%d socket reported as %d, sysfs says %d",
				cpu, got.SocketId, want)
		}
		// A NUMA node id no node directory corresponds to is fabricated
		// locality, which a single-NUMA-node placement request would trust.
		nodeDir := filepath.Join("/sys/devices/system/node",
			"node"+strconv.FormatUint(uint64(got.NumaNode), 10))
		if _, err := os.Stat("/sys/devices/system/node"); err == nil {
			if _, err := os.Stat(nodeDir); err != nil {
				t.Errorf("cpu%d reported on NUMA node %d, but %s does not exist",
					cpu, got.NumaNode, nodeDir)
			}
		} else if got.NumaNode != 0 {
			t.Errorf("cpu%d reported on NUMA node %d on a kernel that exposes "+
				"no NUMA information", cpu, got.NumaNode)
		}
	}

	for _, cache := range inventory.CpuInfo.Caches {
		switch cache.Level {
		case info.CacheLevel_CACHE_LEVEL_L2, info.CacheLevel_CACHE_LEVEL_L3:
		default:
			t.Errorf("cache domain %d reported at level %v; only the levels "+
				"workloads contend over are meant to be reported",
				cache.Id, cache.Level)
		}
		if len(cache.CpuIds) == 0 {
			t.Errorf("cache domain %d (%v) lists no CPUs, so nothing can be "+
				"said about which workloads share it", cache.Id, cache.Level)
		}
		for _, id := range cache.CpuIds {
			dir := filepath.Join("/sys/devices/system/cpu",
				"cpu"+strconv.FormatUint(uint64(id), 10))
			if _, err := os.Stat(dir); err != nil {
				t.Errorf("cache domain %d (%v) lists cpu%d, which does not "+
					"exist: these must be logical CPU ids, not core ids",
					cache.Id, cache.Level, id)
			}
		}
	}
	if sysfsHasSharedCache(online[0]) && len(inventory.CpuInfo.Caches) == 0 {
		t.Errorf("no cache domains reported although sysfs exposes an L2/L3 "+
			"cache for cpu%d", online[0])
	}
}

// onlineCPUsFromSysfs reads the kernel's own list of online logical CPUs, which
// is the independent answer the inventory is checked against. It returns nil if
// sysfs does not expose it.
func onlineCPUsFromSysfs(t *testing.T) []uint32 {
	t.Helper()
	data, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return nil
	}
	var cpus []uint32
	for _, part := range strings.Split(strings.TrimSpace(string(data)), ",") {
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := strconv.ParseUint(lo, 10, 32)
		if err != nil {
			t.Fatalf("unparseable cpu range %q: %v", part, err)
		}
		last := first
		if isRange {
			last, err = strconv.ParseUint(hi, 10, 32)
			if err != nil {
				t.Fatalf("unparseable cpu range %q: %v", part, err)
			}
		}
		for cpu := first; cpu <= last; cpu++ {
			cpus = append(cpus, uint32(cpu))
		}
	}
	return cpus
}

// sysfsCPUUint reads a per-CPU sysfs attribute, reporting whether it exists.
func sysfsCPUUint(t *testing.T, cpu uint32, attr string) (uint32, bool) {
	t.Helper()
	path := filepath.Join("/sys/devices/system/cpu",
		"cpu"+strconv.FormatUint(uint64(cpu), 10), attr)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(value), true
}

// sysfsHasSharedCache reports whether sysfs describes an L2 or L3 cache for the
// given CPU, i.e. whether the inventory is expected to report cache domains at
// all on this host.
func sysfsHasSharedCache(cpu uint32) bool {
	indexes, err := filepath.Glob(filepath.Join("/sys/devices/system/cpu",
		"cpu"+strconv.FormatUint(uint64(cpu), 10), "cache", "index[0-9]*"))
	if err != nil {
		return false
	}
	for _, index := range indexes {
		data, err := os.ReadFile(filepath.Join(index, "level"))
		if err != nil {
			continue
		}
		switch strings.TrimSpace(string(data)) {
		case "2", "3":
			return true
		}
	}
	return false
}
