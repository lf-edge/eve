// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cputopology

import (
	"errors"
	"fmt"
	"runtime"
	"slices"

	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/zededa/ghw"
	"github.com/zededa/ghw/pkg/cpu"
	"github.com/zededa/ghw/pkg/memory"
)

// Discover reads the host's CPUs through ghw and builds the topology with
// FromInfo; args are ghw options, such as ghw.WithChroot for a fixture tree.
func Discover(args ...any) (*Topology, error) {
	hw, err := ghw.CPU(args...)
	if err != nil {
		return flat(hostCPUs()), fmt.Errorf("CPU topology: %w", err)
	}
	return FromInfo(hw)
}

// FromInfo builds the topology from ghw's facts.
//
// When the facts list no online CPU, or an online CPU's socket, core or NUMA
// node is unknown, it returns a degraded topology and the error: each online
// CPU its own core, which can be reported but must not be placed on. HW keeps
// the facts whenever they list the CPUs; when they do not, the CPUs are those
// runtime.NumCPU counts.
func FromInfo(hw *cpu.Info) (*Topology, error) {
	if hw == nil || len(hw.LogicalProcessors) == 0 {
		return flat(hostCPUs()), errors.New("CPU topology: no online CPU listed")
	}

	ids := cacheIDs(hw.Caches)
	l2, l3 := cacheOfCPU(hw.Caches, ids, 2), cacheOfCPU(hw.Caches, ids, 3)
	var cpus []CPU
	var online, unknown []LCPU
	for _, lp := range hw.LogicalProcessors {
		id := LCPU(lp.ID)
		online = append(online, id)
		if lp.ProcessorID < 0 || lp.CoreID < 0 || lp.NodeID < 0 {
			unknown = append(unknown, id)
			continue
		}
		cpus = append(cpus, CPU{ID: id, Socket: uint(lp.ProcessorID),
			Core: uint(lp.CoreID), NUMA: uint(lp.NodeID), L2: l2[id], L3: l3[id]})
	}
	if len(unknown) > 0 {
		t := flat(online)
		t.HW = hw
		return t, fmt.Errorf("CPU topology: the socket, core or NUMA node of CPUs %v is unknown", unknown)
	}
	t := Build(cpus)
	t.HW, t.cacheIDs = hw, ids
	return t, nil
}

// cacheIDs names each cache instance; see Topology.CacheIDOf.
func cacheIDs(caches []*memory.Cache) map[*memory.Cache]uint32 {
	type kind struct {
		level uint8
		typ   memory.CacheType
	}
	unnumbered := map[kind]bool{}
	for _, c := range caches {
		if c.ID < 0 {
			unnumbered[kind{c.Level, c.Type}] = true
		}
	}
	ids := make(map[*memory.Cache]uint32, len(caches))
	for _, c := range caches {
		switch {
		case !unnumbered[kind{c.Level, c.Type}]:
			ids[c] = uint32(c.ID)
		case len(c.LogicalProcessors) > 0:
			ids[c] = slices.Min(c.LogicalProcessors)
		}
	}
	return ids
}

// cacheOfCPU is, for each CPU, the cache that stands for one level.
func cacheOfCPU(caches []*memory.Cache, ids map[*memory.Cache]uint32, level uint8) map[LCPU]CacheID {
	out := map[LCPU]CacheID{}
	for _, c := range caches {
		id, named := ids[c]
		if c.Level != level || !StandsForLevel(c) || !named {
			continue
		}
		for _, cpu := range c.LogicalProcessors {
			out[LCPU(cpu)] = CacheID{ID: id, Known: true}
		}
	}
	return out
}

// flat is the degraded model: each CPU its own core on socket 0, NUMA node 0,
// with no caches.
func flat(cpus []LCPU) *Topology {
	t := Build(generics.MapList(cpus, func(c LCPU) CPU { return CPU{ID: c, Core: uint(c)} }))
	t.Degraded = true
	return t
}

// hostCPUs are the CPUs runtime.NumCPU counts. ghw lists none only when
// /sys/devices/system/cpu cannot be read, and then neither can cpu/online.
func hostCPUs() []LCPU {
	cpus := make([]LCPU, runtime.NumCPU())
	for i := range cpus {
		cpus[i] = LCPU(i)
	}
	return cpus
}
