// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cputopology

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeFile creates parent directories as needed and writes content to path.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

// buildFixtureTree builds a fake sysfs tree under dir mimicking a
// 2-physical-core, SMT2, single-socket, single-NUMA box: cpu0 & cpu1 share
// core_id 0; cpu2 & cpu3 share core_id 1. All four logical CPUs share L3
// index3/id=0 and NUMA node0.
func buildFixtureTree(t *testing.T, dir string) {
	t.Helper()

	writeFile(t, filepath.Join(dir, "cpu", "online"), "0-3\n")

	coreIDs := map[int]int{0: 0, 1: 0, 2: 1, 3: 1}
	for cpu, coreID := range coreIDs {
		base := filepath.Join(dir, "cpu", "cpu"+itoa(cpu))
		writeFile(t, filepath.Join(base, "topology", "physical_package_id"), "0\n")
		writeFile(t, filepath.Join(base, "topology", "core_id"), itoa(coreID)+"\n")
		writeFile(t, filepath.Join(base, "cache", "index3", "level"), "3\n")
		writeFile(t, filepath.Join(base, "cache", "index3", "id"), "0\n")
	}

	writeFile(t, filepath.Join(dir, "node", "node0", "cpulist"), "0-3\n")
}

// itoa avoids pulling in strconv just for test fixture path building.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	if neg {
		digits = "-" + digits
	}
	return digits
}

func TestReadSysfsCoreInfos(t *testing.T) {
	dir := t.TempDir()
	buildFixtureTree(t, dir)

	infos, err := readSysfsCoreInfos(dir)
	if err != nil {
		t.Fatalf("readSysfsCoreInfos: %v", err)
	}

	topo := BuildTopology(infos)

	if len(topo.Cores) != 2 {
		t.Fatalf("expected 2 physical cores, got %d", len(topo.Cores))
	}
	if topo.NumLCPUs != 4 {
		t.Fatalf("expected NumLCPUs == 4, got %d", topo.NumLCPUs)
	}

	var core0, core1 *PhysicalCore
	for i := range topo.Cores {
		switch topo.Cores[i].CoreID {
		case 0:
			core0 = &topo.Cores[i]
		case 1:
			core1 = &topo.Cores[i]
		}
	}
	if core0 == nil || core1 == nil {
		t.Fatalf("expected cores with CoreID 0 and 1, got %+v", topo.Cores)
	}
	if len(core0.Siblings) != 2 || core0.Siblings[0] != LCPU(0) || core0.Siblings[1] != LCPU(1) {
		t.Fatalf("expected CoreID 0 siblings {0,1}, got %v", core0.Siblings)
	}
	if len(core1.Siblings) != 2 || core1.Siblings[0] != LCPU(2) || core1.Siblings[1] != LCPU(3) {
		t.Fatalf("expected CoreID 1 siblings {2,3}, got %v", core1.Siblings)
	}

	if len(topo.L3Cores[0]) != 2 {
		t.Fatalf("expected L3Cores[0] to have 2 cores, got %d", len(topo.L3Cores[0]))
	}
	if len(topo.NUMACores[0]) != 2 {
		t.Fatalf("expected NUMACores[0] to have 2 cores, got %d", len(topo.NUMACores[0]))
	}
	for _, ci := range infos {
		if ci.L3Unknown {
			t.Fatalf("cpu%d should have a known L3 id, the fixture exposes cache/index3/id", ci.LCore)
		}
	}
	if topo.Degraded {
		t.Fatalf("topology read from sysfs must not be marked degraded")
	}
	for i := range topo.Cores {
		if topo.Cores[i].L3Unknown {
			t.Fatalf("core %+v should have a known L3 id", topo.Cores[i])
		}
	}
}

// TestReadSysfsCoreInfos_NoOnlineFile verifies that when <cpuRoot>/online is
// missing, readOnlineCPUs falls back to enumerating cpu/cpuN directories and
// all CPUs are still discovered.
func TestReadSysfsCoreInfos_NoOnlineFile(t *testing.T) {
	dir := t.TempDir()
	buildFixtureTree(t, dir)

	// Remove the online file to force the cpuN directory enumeration
	// fallback path in readOnlineCPUs.
	if err := os.Remove(filepath.Join(dir, "cpu", "online")); err != nil {
		t.Fatalf("Remove(online): %v", err)
	}

	infos, err := readSysfsCoreInfos(dir)
	if err != nil {
		t.Fatalf("readSysfsCoreInfos: %v", err)
	}

	if len(infos) != 4 {
		t.Fatalf("expected 4 CPUs discovered via directory fallback, got %d", len(infos))
	}
	seen := map[uint]bool{}
	for _, ci := range infos {
		seen[ci.LCore] = true
	}
	for cpu := uint(0); cpu < 4; cpu++ {
		if !seen[cpu] {
			t.Fatalf("expected cpu%d to be discovered, got infos %+v", cpu, infos)
		}
	}
}

// TestReadSysfsCoreInfos_SocketDefault verifies that a missing or literal
// "-1" physical_package_id both fall back to Socket 0.
func TestReadSysfsCoreInfos_SocketDefault(t *testing.T) {
	cases := []struct {
		name          string
		writePkgIDFn  func(t *testing.T, path string)
		wantSocketVal uint
	}{
		{
			name: "missing physical_package_id file",
			writePkgIDFn: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatalf("Remove(%s): %v", path, err)
				}
			},
			wantSocketVal: 0,
		},
		{
			name: "physical_package_id is -1",
			writePkgIDFn: func(t *testing.T, path string) {
				t.Helper()
				writeFile(t, path, "-1\n")
			},
			wantSocketVal: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			buildFixtureTree(t, dir)

			pkgIDPath := filepath.Join(dir, "cpu", "cpu0", "topology", "physical_package_id")
			tc.writePkgIDFn(t, pkgIDPath)

			infos, err := readSysfsCoreInfos(dir)
			if err != nil {
				t.Fatalf("readSysfsCoreInfos: %v", err)
			}

			var found bool
			for _, ci := range infos {
				if ci.LCore == 0 {
					found = true
					if ci.Socket != tc.wantSocketVal {
						t.Fatalf("expected cpu0 Socket == %d, got %d", tc.wantSocketVal, ci.Socket)
					}
				}
			}
			if !found {
				t.Fatalf("expected cpu0 in infos, got %+v", infos)
			}
		})
	}
}

// TestReadSysfsCoreInfos_L3Unknown verifies that every way sysfs can fail to
// name a CPU's L3 cache is reported as "unknown" rather than as L3 id 0,
// which is a real id on most machines.
func TestReadSysfsCoreInfos_L3Unknown(t *testing.T) {
	cases := []struct {
		name    string
		breakFn func(t *testing.T, cacheDir string)
	}{
		{
			name: "no cache directory at all",
			breakFn: func(t *testing.T, cacheDir string) {
				t.Helper()
				if err := os.RemoveAll(cacheDir); err != nil {
					t.Fatalf("RemoveAll(%s): %v", cacheDir, err)
				}
			},
		},
		{
			name: "no index with level 3",
			breakFn: func(t *testing.T, cacheDir string) {
				t.Helper()
				if err := os.RemoveAll(cacheDir); err != nil {
					t.Fatalf("RemoveAll(%s): %v", cacheDir, err)
				}
				writeFile(t, filepath.Join(cacheDir, "index2", "level"), "2\n")
				writeFile(t, filepath.Join(cacheDir, "index2", "id"), "5\n")
			},
		},
		{
			// Typical on ARM64: the cache index exists but carries no id.
			name: "level 3 index without an id file",
			breakFn: func(t *testing.T, cacheDir string) {
				t.Helper()
				if err := os.Remove(filepath.Join(cacheDir, "index3", "id")); err != nil {
					t.Fatalf("Remove(id): %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			buildFixtureTree(t, dir)
			tc.breakFn(t, filepath.Join(dir, "cpu", "cpu0", "cache"))

			infos, err := readSysfsCoreInfos(dir)
			if err != nil {
				t.Fatalf("readSysfsCoreInfos: %v", err)
			}

			var found bool
			for _, ci := range infos {
				if ci.LCore != 0 {
					continue
				}
				found = true
				if !ci.L3Unknown {
					t.Fatalf("expected cpu0 to report an unknown L3 id, got L3ID %d", ci.L3ID)
				}
			}
			if !found {
				t.Fatalf("expected cpu0 in infos, got %+v", infos)
			}

			// The unknown must survive into the physical core: cpu0's core
			// has one sibling (cpu1) that still reports an L3 id.
			topo := BuildTopology(infos)
			if pc := topo.ByLCPU[LCPU(0)]; pc == nil || !pc.L3Unknown {
				t.Fatalf("expected cpu0's core to report an unknown L3 id, got %+v", pc)
			}
		})
	}
}

// TestReadSysfsCoreInfos_NoNodeDir verifies that when the sysfs root has no
// node directory at all, every CPU falls back to NUMA node 0.
func TestReadSysfsCoreInfos_NoNodeDir(t *testing.T) {
	dir := t.TempDir()
	buildFixtureTree(t, dir)

	nodeDir := filepath.Join(dir, "node")
	if err := os.RemoveAll(nodeDir); err != nil {
		t.Fatalf("RemoveAll(%s): %v", nodeDir, err)
	}

	infos, err := readSysfsCoreInfos(dir)
	if err != nil {
		t.Fatalf("readSysfsCoreInfos: %v", err)
	}

	for _, ci := range infos {
		if ci.NUMA != 0 {
			t.Fatalf("expected NUMA == 0 for cpu%d when node dir is absent, got %d", ci.LCore, ci.NUMA)
		}
	}
}

// TestReadSysfsCoreInfos_NUMAErrors verifies that a node directory which
// exists but does not yield a usable CPU-to-node mapping is an error. Falling
// back to node 0 would let a single-NUMA-node placement request be satisfied
// with cores from two sockets and still be reported as optimal.
func TestReadSysfsCoreInfos_NUMAErrors(t *testing.T) {
	cases := []struct {
		name    string
		breakFn func(t *testing.T, dir string)
	}{
		{
			name: "unparsable cpulist",
			breakFn: func(t *testing.T, dir string) {
				t.Helper()
				writeFile(t, filepath.Join(dir, "node", "node0", "cpulist"), "zero-three\n")
			},
		},
		{
			name: "unreadable cpulist",
			breakFn: func(t *testing.T, dir string) {
				t.Helper()
				if os.Geteuid() == 0 {
					t.Skip("root bypasses file permissions")
				}
				path := filepath.Join(dir, "node", "node0", "cpulist")
				if err := os.Chmod(path, 0o000); err != nil {
					t.Fatalf("Chmod(%s): %v", path, err)
				}
			},
		},
		{
			name: "online CPU covered by no node",
			breakFn: func(t *testing.T, dir string) {
				t.Helper()
				writeFile(t, filepath.Join(dir, "node", "node0", "cpulist"), "0-2\n")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			buildFixtureTree(t, dir)
			tc.breakFn(t, dir)

			if _, err := readSysfsCoreInfos(dir); err == nil {
				t.Fatalf("expected an error, got nil")
			}
		})
	}
}

// TestReadSysfsCoreInfos_MissingCoreID verifies that a missing core_id file
// on an online CPU is treated as a hard error.
func TestReadSysfsCoreInfos_MissingCoreID(t *testing.T) {
	dir := t.TempDir()
	buildFixtureTree(t, dir)

	coreIDPath := filepath.Join(dir, "cpu", "cpu0", "topology", "core_id")
	if err := os.Remove(coreIDPath); err != nil {
		t.Fatalf("Remove(%s): %v", coreIDPath, err)
	}

	_, err := readSysfsCoreInfos(dir)
	if err == nil {
		t.Fatalf("expected readSysfsCoreInfos to return an error when core_id is missing, got nil")
	}
}

// TestParseCPURangeList verifies multi-range parsing, e.g. "0-3,7" expands
// to [0 1 2 3 7]. This is exercised both directly (the helper is in-package
// and exported to the test via the shared package) and indirectly through
// a cpu/online fixture.
func TestParseCPURangeList(t *testing.T) {
	got, err := parseCPURangeList("0-3,7")
	if err != nil {
		t.Fatalf("parseCPURangeList: %v", err)
	}
	want := []uint{0, 1, 2, 3, 7}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

// TestReadSysfsCoreInfos_MultiRangeOnline exercises the "0-3,7" range list
// via the cpu/online fixture file, confirming readOnlineCPUs (and therefore
// parseCPURangeList) is applied correctly end-to-end.
func TestReadSysfsCoreInfos_MultiRangeOnline(t *testing.T) {
	dir := t.TempDir()
	buildFixtureTree(t, dir)

	writeFile(t, filepath.Join(dir, "cpu", "online"), "0-3,7\n")
	// cpu7 needs its own topology/cache files and a NUMA node covering it
	// since buildFixtureTree only wires up cpu0-cpu3.
	writeFile(t, filepath.Join(dir, "node", "node0", "cpulist"), "0-3,7\n")
	base := filepath.Join(dir, "cpu", "cpu7")
	writeFile(t, filepath.Join(base, "topology", "physical_package_id"), "0\n")
	writeFile(t, filepath.Join(base, "topology", "core_id"), "2\n")
	writeFile(t, filepath.Join(base, "cache", "index3", "level"), "3\n")
	writeFile(t, filepath.Join(base, "cache", "index3", "id"), "0\n")

	infos, err := readSysfsCoreInfos(dir)
	if err != nil {
		t.Fatalf("readSysfsCoreInfos: %v", err)
	}

	got := make([]uint, 0, len(infos))
	for _, ci := range infos {
		got = append(got, ci.LCore)
	}
	want := []uint{0, 1, 2, 3, 7}
	if len(got) != len(want) {
		t.Fatalf("expected LCores %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected LCores %v, got %v", want, got)
		}
	}
}

// TestReadOnlineCPUs_Sorted verifies the ascending-order postcondition even
// when the online file lists ranges out of order: sibling selection uses
// Siblings[0] and must not inherit the file's ordering.
func TestReadOnlineCPUs_Sorted(t *testing.T) {
	dir := t.TempDir()
	buildFixtureTree(t, dir)
	writeFile(t, filepath.Join(dir, "cpu", "online"), "2-3,0-1\n")

	cpus, err := readOnlineCPUs(filepath.Join(dir, "cpu"))
	if err != nil {
		t.Fatalf("readOnlineCPUs: %v", err)
	}
	want := []uint{0, 1, 2, 3}
	if len(cpus) != len(want) {
		t.Fatalf("expected %v, got %v", want, cpus)
	}
	for i := range want {
		if cpus[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, cpus)
		}
	}
}

// TestFlatTopology asserts the degraded fallback topology has the requested
// number of single-thread physical cores and logical CPUs, and that it is
// labelled degraded so placement code refuses it.
func TestFlatTopology(t *testing.T) {
	topo := flatTopology(4)
	if topo == nil {
		t.Fatal("flatTopology returned nil")
	}
	if len(topo.Cores) != 4 {
		t.Fatalf("expected 4 cores, got %d", len(topo.Cores))
	}
	if topo.NumLCPUs != 4 {
		t.Fatalf("expected 4 LCPUs, got %d", topo.NumLCPUs)
	}
	if !topo.Degraded {
		t.Fatal("expected the synthesized topology to be marked degraded")
	}
	for _, pc := range topo.Cores {
		if len(pc.Siblings) != 1 {
			t.Fatalf("expected single-thread core, got siblings %v", pc.Siblings)
		}
		if !pc.L3Unknown {
			t.Fatalf("synthesized core must not claim a known L3 id, got %+v", pc)
		}
	}
}

// TestFlatTopology_MinimumOne guards against a non-positive core count.
func TestFlatTopology_MinimumOne(t *testing.T) {
	topo := flatTopology(0)
	if topo == nil || len(topo.Cores) != 1 {
		t.Fatalf("expected 1 core fallback, got %+v", topo)
	}
}

// TestDiscoverTopology_DegradesLoudly confirms the documented contract: the
// topology is never nil, and every fallback also reports an error and sets
// Degraded, so a placement caller can refuse it instead of silently pinning
// against an invented model.
func TestDiscoverTopology_DegradesLoudly(t *testing.T) {
	cases := []struct {
		name    string
		rootFn  func(t *testing.T) string
		wantErr error // nil: any non-nil error accepted
	}{
		{
			name: "sysfs root does not exist",
			rootFn: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "does-not-exist")
			},
		},
		{
			// The interesting case: nothing failed to read, sysfs simply
			// described no CPUs.
			name: "empty online file",
			rootFn: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				writeFile(t, filepath.Join(dir, "cpu", "online"), "\n")
				return dir
			},
			wantErr: ErrNoCPUTopology,
		},
		{
			name: "no cpuN directories",
			rootFn: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				if err := os.MkdirAll(filepath.Join(dir, "cpu"), 0o755); err != nil {
					t.Fatalf("MkdirAll: %v", err)
				}
				return dir
			},
			wantErr: ErrNoCPUTopology,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			saved := defaultSysfsRoot
			defaultSysfsRoot = tc.rootFn(t)
			defer func() { defaultSysfsRoot = saved }()

			topo, err := DiscoverTopology()
			if topo == nil {
				t.Fatalf("DiscoverTopology returned nil topology (err=%v)", err)
			}
			if err == nil {
				t.Fatalf("expected an error reporting the degraded model, got nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
			if !topo.Degraded {
				t.Fatal("expected Degraded to be set on the fallback topology")
			}
			if topo.NumLCPUs == 0 {
				t.Fatalf("expected NumLCPUs>0, got 0")
			}
		})
	}
}
