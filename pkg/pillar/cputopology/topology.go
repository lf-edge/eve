// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package cputopology discovers native CPU topology (sockets, physical
// cores, SMT siblings, NUMA nodes, L3 cache domains) from Linux sysfs.
//
// It is intentionally dependency-light: pure Go, no CGO, stdlib only, and
// no dependency on any CPU allocator. It is meant to be imported by the
// CPU allocator, by the eve-k operator, and by the hardware-inventory
// (ZInfoMsg) path in zedagent.
package cputopology

import "sort"

// LCPU is a logical CPU id as the host kernel numbers it.
type LCPU uint32

// CoreInfo is one logical CPU's topology coordinates (sysfs reader output).
type CoreInfo struct {
	LCore  uint
	Socket uint
	CoreID uint
	NUMA   uint
	L3ID   uint
	// L3Unknown is true when the platform does not expose an L3 cache id for
	// this logical CPU (no level-3 cache index, or a cache index without an
	// "id" file - common on ARM64). L3ID is then meaningless and must not be
	// read as "L3 domain 0": that would make every core look like it shares
	// one L3 domain.
	L3Unknown bool
}

// PhysicalCore is one physical core and its SMT sibling logical CPUs.
type PhysicalCore struct {
	Socket    uint
	CoreID    uint
	NUMA      uint
	L3ID      uint
	L3Unknown bool   // see CoreInfo.L3Unknown; true if unknown for any sibling
	Siblings  []LCPU // all logical CPUs on this physical core, sorted ascending
}

// Topology is the discovered CPU topology, indexed for allocation.
type Topology struct {
	Cores     []PhysicalCore
	ByLCPU    map[LCPU]*PhysicalCore
	NUMACores map[uint][]*PhysicalCore
	L3Cores   map[uint][]*PhysicalCore
	NumLCPUs  uint32
	// Degraded is true when the model was synthesized rather than read from
	// sysfs. Such a model is fine for reporting but MUST NOT drive CPU
	// placement: it invents CPU ids and claims every logical CPU is its own
	// single-sibling core, so one-per-core placement would park nothing and
	// hand real SMT siblings to two different workloads.
	Degraded bool
}

// coreKey groups logical CPUs into a physical core. SMT siblings are
// defined as logical CPUs sharing the same (Socket, CoreID) pair. This
// must NEVER be a cache/L2 id: Intel E-core modules share one L2 across
// four distinct physical cores, so grouping by L2 would wrongly merge
// unrelated cores into one.
type coreKey struct {
	socket uint
	coreID uint
}

// BuildTopology groups logical CPU topology coordinates into physical
// cores and builds the lookup indices used by allocators. Repeated entries
// for the same logical CPU are ignored: a duplicate would otherwise show up
// as an extra SMT sibling and inflate the logical CPU count.
func BuildTopology(infos []CoreInfo) *Topology {
	grouped := map[coreKey]*PhysicalCore{}
	seen := map[uint]bool{}
	for _, ci := range infos {
		if seen[ci.LCore] {
			continue
		}
		seen[ci.LCore] = true
		k := coreKey{ci.Socket, ci.CoreID}
		pc, ok := grouped[k]
		if !ok {
			pc = &PhysicalCore{Socket: ci.Socket, CoreID: ci.CoreID, NUMA: ci.NUMA,
				L3ID: ci.L3ID, L3Unknown: ci.L3Unknown}
			grouped[k] = pc
		}
		if ci.L3Unknown {
			pc.L3Unknown = true
		}
		pc.Siblings = append(pc.Siblings, LCPU(ci.LCore))
	}

	topo := &Topology{
		ByLCPU:    map[LCPU]*PhysicalCore{},
		NUMACores: map[uint][]*PhysicalCore{},
		L3Cores:   map[uint][]*PhysicalCore{},
	}
	keys := make([]coreKey, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].socket != keys[j].socket {
			return keys[i].socket < keys[j].socket
		}
		return keys[i].coreID < keys[j].coreID
	})
	for _, k := range keys {
		pc := grouped[k]
		sort.Slice(pc.Siblings, func(i, j int) bool { return pc.Siblings[i] < pc.Siblings[j] })
		topo.Cores = append(topo.Cores, *pc)
	}
	for i := range topo.Cores {
		pc := &topo.Cores[i]
		for _, s := range pc.Siblings {
			topo.ByLCPU[s] = pc
		}
		topo.NUMACores[pc.NUMA] = append(topo.NUMACores[pc.NUMA], pc)
		topo.L3Cores[pc.L3ID] = append(topo.L3Cores[pc.L3ID], pc)
	}
	topo.NumLCPUs = uint32(len(topo.ByLCPU))
	return topo
}
