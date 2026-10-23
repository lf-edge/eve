// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package cputopology is EVE's model of the host's CPUs for workload
// placement: the physical cores, the SMT siblings of each, and the NUMA node
// and caches they share. It is built from the facts ghw reads from sysfs and
// adds what placement needs on top: a core identity, cache instances named
// consistently, and a flat model, marked degraded, when the facts are not
// enough to place on.
package cputopology

import (
	"cmp"
	"slices"

	"github.com/zededa/ghw/pkg/cpu"
	"github.com/zededa/ghw/pkg/memory"
)

// LCPU is a logical CPU (hardware thread) id, as the kernel and CPU
// affinities number it.
type LCPU uint32

// CacheID names the cache instance a CPU uses at one level; see
// Topology.CacheIDOf.
type CacheID struct {
	ID uint32
	// Known is false when no cache of that level is known to serve the CPU.
	Known bool
}

// CPU is one online logical CPU and where it sits: the input to Build.
type CPU struct {
	ID     LCPU
	Socket uint
	Core   uint
	NUMA   uint
	L2, L3 CacheID
}

// Core is one physical core.
type Core struct {
	Socket uint
	// ID is unique within the socket. Cores sharing an L2, such as the four
	// cores of an Intel E-core module, are still separate cores.
	ID   uint
	NUMA uint
	// Siblings are the logical CPUs of the core, ascending.
	Siblings []LCPU
	L2, L3   CacheID
}

// Topology is the host's CPUs as placement sees them.
type Topology struct {
	// Cores are ordered by socket, then core id.
	Cores []Core
	// Degraded marks a synthesized model: each online CPU its own core, with
	// no NUMA or cache information. Workloads must not be placed on it.
	Degraded bool
	// HW is what ghw read, for reporting. It is nil only when ghw could not
	// list the CPUs.
	HW *cpu.Info

	coreOf   map[LCPU]int
	cacheIDs map[*memory.Cache]uint32
}

// Build groups CPUs into cores by socket and core id. A CPU listed twice
// counts once. A core's NUMA node and caches are those of its lowest CPU.
func Build(cpus []CPU) *Topology {
	sorted := slices.Clone(cpus)
	slices.SortFunc(sorted, func(a, b CPU) int { return cmp.Compare(a.ID, b.ID) })
	sorted = slices.CompactFunc(sorted, func(a, b CPU) bool { return a.ID == b.ID })
	slices.SortStableFunc(sorted, func(a, b CPU) int {
		return cmp.Or(cmp.Compare(a.Socket, b.Socket), cmp.Compare(a.Core, b.Core))
	})

	t := &Topology{coreOf: make(map[LCPU]int, len(sorted))}
	for _, c := range sorted {
		n := len(t.Cores)
		if n == 0 || t.Cores[n-1].Socket != c.Socket || t.Cores[n-1].ID != c.Core {
			t.Cores = append(t.Cores, Core{Socket: c.Socket, ID: c.Core, NUMA: c.NUMA, L2: c.L2, L3: c.L3})
			n++
		}
		t.Cores[n-1].Siblings = append(t.Cores[n-1].Siblings, c.ID)
		t.coreOf[c.ID] = n - 1
	}
	return t
}

// CoreOf returns the core a logical CPU belongs to, nil for a CPU that is
// not online.
func (t *Topology) CoreOf(c LCPU) *Core {
	i, ok := t.coreOf[c]
	if !ok {
		return nil
	}
	return &t.Cores[i]
}

// NumCPUs is the number of online logical CPUs.
func (t *Topology) NumCPUs() int {
	return len(t.coreOf)
}

// CacheIDOf is the id of a cache instance of HW, the one the cores' L2 and L3
// use: the kernel's id when every instance of its level and type has one,
// otherwise the lowest CPU sharing it, so the two kinds of id never mix and
// caches an ARM device tree does not number are still told apart. False for
// an instance without one, and for every instance of a degraded topology.
func (t *Topology) CacheIDOf(c *memory.Cache) (uint32, bool) {
	id, ok := t.cacheIDs[c]
	return id, ok
}

// StandsForLevel reports whether a cache instance is the one a core's L2 or
// L3 names at its level: a unified cache, or the data cache of a level split
// into data and instruction caches.
func StandsForLevel(c *memory.Cache) bool {
	return c.Type != memory.CacheTypeInstruction
}
