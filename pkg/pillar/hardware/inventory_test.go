// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/zededa/ghw/pkg/cpu"
	"github.com/zededa/ghw/pkg/memory"
	"github.com/zededa/ghw/pkg/util"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

// The inventory of the host the test runs on, checked against sysfs with
// properties that hold on any Linux host.
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

	if inventory.KernelCpuIsolation == nil {
		t.Error("KernelCpuIsolation is unset although the kernel's sets are readable")
	}
	online, err := util.ReadCPUList("/sys/devices/system/cpu/online")
	if err != nil || len(online) == 0 {
		t.Skipf("no online CPU list to check the CPUs against: %v", err)
	}
	checkCPUInfo(t, inventory.CpuInfo, online)
}

func checkCPUInfo(t *testing.T, cpus *info.CPUInfo, online []int) {
	t.Helper()
	var ids []int
	byCore := map[[2]uint32][]int{}
	for _, c := range cpus.Cpus {
		ids = append(ids, int(c.Id))
		if c.SocketId != nil {
			key := [2]uint32{c.GetSocketId(), c.GetCoreId()}
			byCore[key] = append(byCore[key], int(c.Id))
		}
	}
	if !slices.Equal(ids, online) {
		t.Fatalf("reported CPUs %v, want the online CPUs %v", ids, online)
	}
	if len(byCore) == 0 {
		if len(cpus.Caches) != 0 {
			t.Error("caches reported for a topology without coordinates")
		}
		return
	}

	type cpuAtLevel struct {
		level info.CacheLevel
		cpu   uint32
	}
	inCache := map[cpuAtLevel]uint32{}
	for _, cache := range cpus.Caches {
		if len(cache.CpuIds) == 0 {
			t.Errorf("%v cache %d lists no CPUs", cache.Level, cache.Id)
		}
		for _, id := range cache.CpuIds {
			if !slices.Contains(online, int(id)) {
				t.Errorf("%v cache %d lists CPU %d, which is not online", cache.Level, cache.Id, id)
			}
			inCache[cpuAtLevel{cache.Level, id}] = cache.Id
		}
	}

	_, numaErr := os.Stat("/sys/devices/system/node")
	for _, c := range cpus.Cpus {
		if c.SocketId == nil || c.CoreId == nil || c.NumaNode == nil {
			t.Errorf("CPU %d: coordinates %v/%v/%v, want all set or none", c.Id, c.SocketId, c.CoreId, c.NumaNode)
			continue
		}
		if siblings, err := util.ReadCPUList(fmt.Sprintf(
			"/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", c.Id)); err == nil {
			siblings = slices.DeleteFunc(siblings, func(id int) bool { return !slices.Contains(online, id) })
			if got := byCore[[2]uint32{c.GetSocketId(), c.GetCoreId()}]; !slices.Equal(got, siblings) {
				t.Errorf("CPU %d shares socket and core with %v, sysfs lists siblings %v", c.Id, got, siblings)
			}
		}
		if numaErr != nil {
			if c.GetNumaNode() != 0 {
				t.Errorf("CPU %d reported on NUMA node %d by a kernel without NUMA", c.Id, c.GetNumaNode())
			}
		} else if node, err := util.ReadCPUList(fmt.Sprintf(
			"/sys/devices/system/node/node%d/cpulist", c.GetNumaNode())); err != nil || !slices.Contains(node, int(c.Id)) {
			t.Errorf("CPU %d reported on NUMA node %d, which does not list it", c.Id, c.GetNumaNode())
		}
		for level, got := range map[info.CacheLevel]*uint32{
			info.CacheLevel_CACHE_LEVEL_L2: c.L2Id, info.CacheLevel_CACHE_LEVEL_L3: c.L3Id,
		} {
			want, listed := inCache[cpuAtLevel{level, c.Id}]
			if (got != nil) != listed || (listed && *got != want) {
				t.Errorf("CPU %d: %v id %v, but the %v cache listing it is %d (listed %v)",
					c.Id, level, got, level, want, listed)
			}
		}
	}
}

// Two packages of one two-thread core each, CPUs 0 and 2 on package 0 and
// 1 and 3 on package 1. The L2s have kernel ids; only package 1 has an L3,
// without a kernel id.
func twoPackageHost() *cpu.Info {
	perf := cpu.LogicalProcessor{ProcessorID: 0, CoreType: cpu.CoreTypePerformance,
		BaseFrequencyKHz: 2000000, MaxFrequencyKHz: 3500000}
	plain := cpu.LogicalProcessor{ProcessorID: 1, NodeID: 1}
	lp := func(id int, tmpl cpu.LogicalProcessor) *cpu.LogicalProcessor {
		tmpl.ID = id
		return &tmpl
	}
	return &cpu.Info{
		Processors: []*cpu.Processor{
			{ID: 0, Model: "Model A", Vendor: "GenuineIntel"},
			{ID: 1, Model: "Model B", Vendor: "GenuineIntel"},
		},
		LogicalProcessors: []*cpu.LogicalProcessor{lp(0, perf), lp(1, plain), lp(2, perf), lp(3, plain)},
		Caches: []*memory.Cache{
			{Level: 1, Type: memory.CacheTypeData, ID: 0, SizeBytes: 48 << 10, LogicalProcessors: []uint32{0, 2}},
			{Level: 1, Type: memory.CacheTypeInstruction, ID: 0, SizeBytes: 32 << 10, LogicalProcessors: []uint32{0, 2}},
			{Level: 2, Type: memory.CacheTypeUnified, ID: 7, LogicalProcessors: []uint32{0, 2}},
			{Level: 2, Type: memory.CacheTypeUnified, ID: 9, SizeBytes: 2 << 20, LogicalProcessors: []uint32{1, 3}},
			{Level: 3, Type: memory.CacheTypeUnified, ID: -1, LogicalProcessors: []uint32{1, 3}},
			{Level: 4, Type: memory.CacheTypeUnified, ID: 0, LogicalProcessors: []uint32{0, 1, 2, 3}},
		},
	}
}

// The CPUs of twoPackageHost as reported without coordinates.
func twoPackageCPUs() (a, b *info.CPU) {
	return &info.CPU{Model: "Model A", Vendor: "GenuineIntel", CoreClass: info.CoreClass_CORE_CLASS_PERFORMANCE,
			BaseFreqKhz: proto.Uint64(2000000), MaxFreqKhz: proto.Uint64(3500000)},
		&info.CPU{Model: "Model B", Vendor: "GenuineIntel"}
}

func withID(c *info.CPU, id uint32) *info.CPU {
	c = proto.Clone(c).(*info.CPU)
	c.Id = id
	return c
}

func TestCPUInfo(t *testing.T) {
	topo, err := cputopology.FromInfo(twoPackageHost())
	if err != nil {
		t.Fatal(err)
	}
	a, b := twoPackageCPUs()
	a.SocketId, a.CoreId, a.NumaNode, a.L2Id = proto.Uint32(0), proto.Uint32(0), proto.Uint32(0), proto.Uint32(7)
	b.SocketId, b.CoreId, b.NumaNode, b.L2Id, b.L3Id = proto.Uint32(1), proto.Uint32(0), proto.Uint32(1),
		proto.Uint32(9), proto.Uint32(1)
	want := &info.CPUInfo{
		Cpus: []*info.CPU{withID(a, 0), withID(b, 1), withID(a, 2), withID(b, 3)},
		Caches: []*info.CacheDomain{
			{Level: info.CacheLevel_CACHE_LEVEL_L1D, Id: 0, SizeBytes: proto.Uint64(48 << 10), CpuIds: []uint32{0, 2}},
			{Level: info.CacheLevel_CACHE_LEVEL_L1I, Id: 0, SizeBytes: proto.Uint64(32 << 10), CpuIds: []uint32{0, 2}},
			{Level: info.CacheLevel_CACHE_LEVEL_L2, Id: 7, CpuIds: []uint32{0, 2}},
			{Level: info.CacheLevel_CACHE_LEVEL_L2, Id: 9, SizeBytes: proto.Uint64(2 << 20), CpuIds: []uint32{1, 3}},
			{Level: info.CacheLevel_CACHE_LEVEL_L3, Id: 1, CpuIds: []uint32{1, 3}},
		},
	}
	if got := cpuInfo(topo); !proto.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", prototext.Format(got), prototext.Format(want))
	}
}

// A degraded topology withholds the coordinates and caches but keeps what
// ghw read about each CPU.
func TestCPUInfo_Degraded(t *testing.T) {
	hw := twoPackageHost()
	hw.LogicalProcessors[3].NodeID = -1
	topo, err := cputopology.FromInfo(hw)
	if err == nil || !topo.Degraded {
		t.Fatalf("err %v, degraded %v: want a degraded topology", err, topo.Degraded)
	}
	a, b := twoPackageCPUs()
	want := &info.CPUInfo{Cpus: []*info.CPU{withID(a, 0), withID(b, 1), withID(a, 2), withID(b, 3)}}
	if got := cpuInfo(topo); !proto.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", prototext.Format(got), prototext.Format(want))
	}
}

// Without ghw's facts only the CPU ids are known.
func TestCPUInfo_NoFacts(t *testing.T) {
	topo, err := cputopology.FromInfo(nil)
	if err == nil || topo.HW != nil {
		t.Fatalf("err %v, HW %v: want an error and no facts", err, topo.HW)
	}
	want := &info.CPUInfo{}
	for id := range runtime.NumCPU() {
		want.Cpus = append(want.Cpus, &info.CPU{Id: uint32(id)})
	}
	if got := cpuInfo(topo); !proto.Equal(got, want) {
		t.Errorf("got %s, want %s", prototext.Format(got), prototext.Format(want))
	}
}

func TestCacheLevel(t *testing.T) {
	for _, tc := range []struct {
		level uint8
		typ   memory.CacheType
		want  info.CacheLevel
	}{
		{1, memory.CacheTypeData, info.CacheLevel_CACHE_LEVEL_L1D},
		{1, memory.CacheTypeInstruction, info.CacheLevel_CACHE_LEVEL_L1I},
		{1, memory.CacheTypeUnified, info.CacheLevel_CACHE_LEVEL_UNSPECIFIED},
		{2, memory.CacheTypeUnified, info.CacheLevel_CACHE_LEVEL_L2},
		{2, memory.CacheTypeData, info.CacheLevel_CACHE_LEVEL_L2},
		{2, memory.CacheTypeInstruction, info.CacheLevel_CACHE_LEVEL_UNSPECIFIED},
		{3, memory.CacheTypeUnified, info.CacheLevel_CACHE_LEVEL_L3},
		{4, memory.CacheTypeUnified, info.CacheLevel_CACHE_LEVEL_UNSPECIFIED},
	} {
		if got := cacheLevel(&memory.Cache{Level: tc.level, Type: tc.typ}); got != tc.want {
			t.Errorf("level %d %v: %v, want %v", tc.level, tc.typ, got, tc.want)
		}
	}
}
