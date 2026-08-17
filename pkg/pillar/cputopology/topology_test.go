// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cputopology

import "testing"

func TestBuildTopology_SiblingsByCoreID(t *testing.T) {
	infos := []CoreInfo{
		{LCore: 0, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 4, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 1, Socket: 0, CoreID: 1, NUMA: 0, L3ID: 0},
		{LCore: 5, Socket: 0, CoreID: 1, NUMA: 0, L3ID: 0},
	}

	topo := BuildTopology(infos)

	if len(topo.Cores) != 2 {
		t.Fatalf("expected 2 physical cores, got %d", len(topo.Cores))
	}

	pc0, ok := topo.ByLCPU[0]
	if !ok {
		t.Fatalf("expected ByLCPU to contain entry for LCPU 0")
	}
	if len(pc0.Siblings) != 2 || pc0.Siblings[0] != LCPU(0) || pc0.Siblings[1] != LCPU(4) {
		t.Fatalf("expected siblings {0,4} for LCPU 0's core, got %v", pc0.Siblings)
	}
}

// TestBuildTopology_DuplicateCoreInfo asserts a repeated logical CPU neither
// inflates NumLCPUs nor appears twice as an SMT sibling: NumLCPUs is a count
// of distinct logical CPUs, not of input records.
func TestBuildTopology_DuplicateCoreInfo(t *testing.T) {
	infos := []CoreInfo{
		{LCore: 0, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 4, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 0, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
	}

	topo := BuildTopology(infos)

	if topo.NumLCPUs != 2 {
		t.Fatalf("expected NumLCPUs == 2 for 2 distinct logical CPUs, got %d", topo.NumLCPUs)
	}
	if len(topo.Cores) != 1 {
		t.Fatalf("expected 1 physical core, got %d", len(topo.Cores))
	}
	if got := topo.Cores[0].Siblings; len(got) != 2 || got[0] != LCPU(0) || got[1] != LCPU(4) {
		t.Fatalf("expected siblings {0,4}, got %v", got)
	}
}

func TestBuildTopology_SharedL2NotSiblings(t *testing.T) {
	// Represents an E-core module: 4 distinct physical cores (CoreID 0..3)
	// that happen to share the same socket/NUMA/L3 (as an E-core module
	// would share an L2 cache). CoreInfo has no L2 field on purpose: SMT
	// siblings must be grouped by (Socket, CoreID) only, never by any
	// cache/L2 id.
	infos := []CoreInfo{
		{LCore: 0, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 1, Socket: 0, CoreID: 1, NUMA: 0, L3ID: 0},
		{LCore: 2, Socket: 0, CoreID: 2, NUMA: 0, L3ID: 0},
		{LCore: 3, Socket: 0, CoreID: 3, NUMA: 0, L3ID: 0},
	}

	topo := BuildTopology(infos)

	if len(topo.Cores) != 4 {
		t.Fatalf("expected 4 physical cores, got %d", len(topo.Cores))
	}
	for _, pc := range topo.Cores {
		if len(pc.Siblings) != 1 {
			t.Fatalf("expected exactly 1 sibling per core, got %d for core %+v", len(pc.Siblings), pc)
		}
	}
}
