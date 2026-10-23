// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cputopology

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/zededa/ghw"
)

// hostCPU describes one CPU of a fixture host.
type hostCPU struct {
	socket, core, node int
	siblings           string
	l2, l3             cacheFixture
	offline            bool
}

type cacheFixture struct {
	id     string // "" leaves the id file out, as ARM device trees do
	shared string
}

// writeTree writes files, keyed by their slash-separated path under the root,
// to a new root and returns it.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	fsys := fstest.MapFS{}
	for path, content := range files {
		fsys[path] = &fstest.MapFile{Data: []byte(content + "\n")}
	}
	root := t.TempDir()
	if err := os.CopyFS(root, fsys); err != nil {
		t.Fatal(err)
	}
	return root
}

// writeHost writes the sysfs files ghw reads for these CPUs and returns the
// root.
func writeHost(t *testing.T, cpus []hostCPU, numaNodes map[int]string) string {
	t.Helper()
	files := map[string]string{}
	for i, c := range cpus {
		dir := fmt.Sprintf("sys/devices/system/cpu/cpu%d/", i)
		files[dir+"online"] = map[bool]string{true: "0", false: "1"}[c.offline]
		if c.offline {
			continue
		}
		files[dir+"topology/physical_package_id"] = fmt.Sprint(c.socket)
		files[dir+"topology/core_id"] = fmt.Sprint(c.core)
		files[dir+"topology/thread_siblings_list"] = c.siblings
		for i, cache := range []struct {
			level int
			c     cacheFixture
		}{{2, c.l2}, {3, c.l3}} {
			idx := fmt.Sprintf("%scache/index%d/", dir, i)
			files[idx+"level"] = fmt.Sprint(cache.level)
			files[idx+"type"] = "Unified"
			files[idx+"size"] = "1024K"
			files[idx+"shared_cpu_list"] = cache.c.shared
			if cache.c.id != "" {
				files[idx+"id"] = cache.c.id
			}
		}
	}
	for node, list := range numaNodes {
		files[fmt.Sprintf("sys/devices/system/node/node%d/cpulist", node)] = list
	}
	return writeTree(t, files)
}

// The shape of the test node: two sockets with an L3 each, two NUMA nodes,
// two-thread cores with an L2 each.
func TestDiscover_SMTHost(t *testing.T) {
	sockets := map[int]string{0: "0-1,4-5", 1: "2-3,6-7"}
	var cpus []hostCPU
	for i := 0; i < 8; i++ {
		core := i % 4
		socket := core / 2
		cpus = append(cpus, hostCPU{socket: socket, core: core % 2,
			siblings: fmt.Sprintf("%d,%d", core, core+4),
			l2:       cacheFixture{fmt.Sprint(core), fmt.Sprintf("%d,%d", core, core+4)},
			l3:       cacheFixture{fmt.Sprint(socket), sockets[socket]}})
	}
	root := writeHost(t, cpus, sockets)

	topo, err := Discover(ghw.WithChroot(root), ghw.WithDisableWarnings())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if topo.Degraded || topo.HW == nil {
		t.Fatalf("degraded %v, HW %v: want a usable topology with the facts", topo.Degraded, topo.HW)
	}
	want := []Core{
		{Socket: 0, ID: 0, NUMA: 0, Siblings: []LCPU{0, 4}, L2: CacheID{0, true}, L3: CacheID{0, true}},
		{Socket: 0, ID: 1, NUMA: 0, Siblings: []LCPU{1, 5}, L2: CacheID{1, true}, L3: CacheID{0, true}},
		{Socket: 1, ID: 0, NUMA: 1, Siblings: []LCPU{2, 6}, L2: CacheID{2, true}, L3: CacheID{1, true}},
		{Socket: 1, ID: 1, NUMA: 1, Siblings: []LCPU{3, 7}, L2: CacheID{3, true}, L3: CacheID{1, true}},
	}
	if !reflect.DeepEqual(topo.Cores, want) {
		t.Errorf("cores\n%+v\nwant\n%+v", topo.Cores, want)
	}
}

// An ARM device tree restarts core_id in each cluster and numbers no caches:
// the cores stay apart, and each cache instance is named by its lowest CPU.
func TestDiscover_ClustersWithoutCacheIDs(t *testing.T) {
	var cpus []hostCPU
	for i := 0; i < 4; i++ {
		cluster := i / 2
		cpus = append(cpus, hostCPU{core: i % 2, siblings: fmt.Sprint(i),
			l2: cacheFixture{"", fmt.Sprintf("%d-%d", cluster*2, cluster*2+1)},
			l3: cacheFixture{"", "0-3"}})
	}
	root := writeHost(t, cpus, map[int]string{0: "0-3"})

	topo, err := Discover(ghw.WithChroot(root), ghw.WithDisableWarnings())
	if err != nil || topo.Degraded {
		t.Fatalf("Discover: %v, degraded %v", err, topo.Degraded)
	}
	if len(topo.Cores) != 4 {
		t.Fatalf("%d cores, want 4: a core_id repeated across clusters is not one core", len(topo.Cores))
	}
	for _, c := range []struct {
		cpu LCPU
		l2  uint32
	}{{0, 0}, {1, 0}, {2, 2}, {3, 2}} {
		core := topo.CoreOf(c.cpu)
		if core.L2 != (CacheID{c.l2, true}) || core.L3 != (CacheID{0, true}) {
			t.Errorf("CPU %d: L2 %+v L3 %+v, want L2 %d and L3 0 named by their lowest CPU",
				c.cpu, core.L2, core.L3, c.l2)
		}
	}
}

// A CPU no NUMA node lists has an unknown node: the topology is degraded and
// says why, and keeps what ghw read for the report.
func TestDiscover_UnknownNUMANodeDegrades(t *testing.T) {
	var cpus []hostCPU
	for i := 0; i < 4; i++ {
		cpus = append(cpus, hostCPU{core: i, siblings: fmt.Sprint(i),
			l2: cacheFixture{fmt.Sprint(i), fmt.Sprint(i)}, l3: cacheFixture{"0", "0-3"}})
	}
	root := writeHost(t, cpus, map[int]string{0: "0-2"})

	topo, err := Discover(ghw.WithChroot(root), ghw.WithDisableWarnings())
	if err == nil || !topo.Degraded {
		t.Fatalf("err %v, degraded %v: want a degraded topology and an error", err, topo.Degraded)
	}
	if topo.HW == nil || topo.NumCPUs() != 4 {
		t.Errorf("HW %v, %d CPUs: want the facts kept and every online CPU", topo.HW, topo.NumCPUs())
	}
	for _, core := range topo.Cores {
		if len(core.Siblings) != 1 || core.L2.Known || core.L3.Known {
			t.Errorf("core %+v: the degraded model has one CPU per core and no caches", core)
		}
	}
	if _, named := topo.CacheIDOf(topo.HW.Caches[0]); named {
		t.Error("a degraded topology names no cache")
	}
}

// When ghw lists no CPU, the CPUs are those runtime.NumCPU counts.
func TestDiscover_NoCPUsListed(t *testing.T) {
	topo, err := Discover(ghw.WithChroot(t.TempDir()), ghw.WithDisableWarnings())
	if err == nil || !topo.Degraded || topo.HW != nil {
		t.Fatalf("err %v, degraded %v, HW %v: want degraded, no facts", err, topo.Degraded, topo.HW)
	}
	if topo.NumCPUs() != runtime.NumCPU() {
		t.Errorf("%d CPUs, want the %d runtime.NumCPU counts", topo.NumCPUs(), runtime.NumCPU())
	}
}

func TestDiscover_OfflineCPUsAreNotPlaced(t *testing.T) {
	cpus := []hostCPU{
		{core: 0, siblings: "0", l2: cacheFixture{"0", "0"}, l3: cacheFixture{"0", "0,2"}},
		{offline: true},
		{core: 2, siblings: "2", l2: cacheFixture{"2", "2"}, l3: cacheFixture{"0", "0,2"}},
	}
	root := writeHost(t, cpus, map[int]string{0: "0,2"})

	topo, err := Discover(ghw.WithChroot(root), ghw.WithDisableWarnings())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if topo.CoreOf(1) != nil || topo.NumCPUs() != 2 {
		t.Errorf("CoreOf(1) %v, %d CPUs: want offline CPU 1 left out", topo.CoreOf(1), topo.NumCPUs())
	}
}

func TestKernelIsolation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		files      map[string]string
		iso, nohz  []LCPU
		wantsError bool
	}{
		{name: "no files"},
		{name: "isolated, empty nohz_full", files: map[string]string{"isolated": "2-3", "nohz_full": ""},
			iso: []LCPU{2, 3}},
		{name: "malformed", files: map[string]string{"isolated": "3-2"}, wantsError: true},
	} {
		files := map[string]string{}
		for name, content := range tc.files {
			files["sys/devices/system/cpu/"+name] = content
		}
		ctx := ghw.WithChroot(writeTree(t, files))(ghw.ContextFromEnv())
		iso, nohz, err := KernelIsolation(ctx)
		if (err != nil) != tc.wantsError || !slices.Equal(iso, tc.iso) || !slices.Equal(nohz, tc.nohz) {
			t.Errorf("%s: isolated %v, nohz_full %v, err %v; want %v, %v, error %v",
				tc.name, iso, nohz, err, tc.iso, tc.nohz, tc.wantsError)
		}
	}
}
