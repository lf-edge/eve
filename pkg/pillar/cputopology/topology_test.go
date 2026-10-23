// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cputopology

import (
	"reflect"
	"testing"

	"github.com/zededa/ghw/pkg/memory"
)

func TestBuild_GroupsSiblingsByCore(t *testing.T) {
	l3 := CacheID{ID: 0, Known: true}
	topo := Build([]CPU{
		{ID: 3, Socket: 0, Core: 1, L3: l3},
		{ID: 0, Socket: 0, Core: 0, L3: l3},
		{ID: 2, Socket: 0, Core: 0, L3: l3},
		{ID: 1, Socket: 0, Core: 1, L3: l3},
		{ID: 1, Socket: 0, Core: 1, L3: l3},
	})
	want := []Core{
		{Socket: 0, ID: 0, Siblings: []LCPU{0, 2}, L3: l3},
		{Socket: 0, ID: 1, Siblings: []LCPU{1, 3}, L3: l3},
	}
	if !reflect.DeepEqual(topo.Cores, want) {
		t.Fatalf("cores %+v, want %+v", topo.Cores, want)
	}
	if topo.NumCPUs() != 4 {
		t.Errorf("NumCPUs %d, want 4: a CPU listed twice counts once", topo.NumCPUs())
	}
	if core := topo.CoreOf(3); core == nil || core.ID != 1 {
		t.Errorf("CoreOf(3) = %+v, want core 1", core)
	}
	if topo.CoreOf(9) != nil {
		t.Error("CoreOf a CPU that is not online must be nil")
	}
}

// The four cores of an Intel E-core module share one L2 but are four cores:
// grouping by cache would make them one four-thread core.
func TestBuild_SharedL2NeverMergesCores(t *testing.T) {
	l2 := CacheID{ID: 4, Known: true}
	var cpus []CPU
	for i := 8; i < 12; i++ {
		cpus = append(cpus, CPU{ID: LCPU(i), Core: uint(i), L2: l2})
	}
	topo := Build(cpus)
	if len(topo.Cores) != 4 {
		t.Fatalf("%d cores, want 4 single-thread cores sharing an L2", len(topo.Cores))
	}
	for _, core := range topo.Cores {
		if len(core.Siblings) != 1 || core.L2 != l2 {
			t.Errorf("core %+v: want one thread and the shared L2", core)
		}
	}
}

// Kernel ids are used only when every instance of a level and type has one;
// otherwise every instance of it is named by its lowest CPU.
func TestCacheIDs(t *testing.T) {
	l1d := &memory.Cache{Level: 1, Type: memory.CacheTypeData, ID: 0, LogicalProcessors: []uint32{0}}
	l1i := &memory.Cache{Level: 1, Type: memory.CacheTypeInstruction, ID: 0, LogicalProcessors: []uint32{0}}
	l2a := &memory.Cache{Level: 2, Type: memory.CacheTypeUnified, ID: 7, LogicalProcessors: []uint32{2, 3}}
	l2b := &memory.Cache{Level: 2, Type: memory.CacheTypeUnified, ID: -1, LogicalProcessors: []uint32{5, 4}}
	ids := cacheIDs([]*memory.Cache{l1d, l1i, l2a, l2b})
	want := map[*memory.Cache]uint32{l1d: 0, l1i: 0, l2a: 2, l2b: 4}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("ids %v, want %v", ids, want)
	}
}
