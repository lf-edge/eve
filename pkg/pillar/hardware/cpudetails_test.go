// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// writeFile creates path with content, making parent directories as needed.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// fakeSysfs builds a 4-CPU machine: two physical cores with two SMT threads
// each. Each core has its own L1d, L1i and L2; both share one L3 -- the layout
// that makes cache sharing worth reporting at all. As on a real host, the L1
// data and instruction caches of a core carry the same level and the same id
// and differ only in their type file.
func fakeSysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	cpuRoot := filepath.Join(root, "cpu")

	type spec struct {
		cpu    int
		coreID string // id of this core's private (L1, L2) caches
		shared string // CPUs sharing them, i.e. the core's SMT threads
	}
	specs := []spec{
		{0, "0", "0-1"},
		{1, "0", "0-1"},
		{2, "1", "2-3"},
		{3, "1", "2-3"},
	}
	for _, s := range specs {
		dir := filepath.Join(cpuRoot, "cpu"+itoa(s.cpu))
		// L1 data and L1 instruction: per core, same level and same id.
		writeFile(t, filepath.Join(dir, "cache/index0/level"), "1\n")
		writeFile(t, filepath.Join(dir, "cache/index0/type"), "Data\n")
		writeFile(t, filepath.Join(dir, "cache/index0/id"), s.coreID+"\n")
		writeFile(t, filepath.Join(dir, "cache/index0/size"), "48K\n")
		writeFile(t, filepath.Join(dir, "cache/index0/shared_cpu_list"), s.shared+"\n")
		writeFile(t, filepath.Join(dir, "cache/index1/level"), "1\n")
		writeFile(t, filepath.Join(dir, "cache/index1/type"), "Instruction\n")
		writeFile(t, filepath.Join(dir, "cache/index1/id"), s.coreID+"\n")
		writeFile(t, filepath.Join(dir, "cache/index1/size"), "32K\n")
		writeFile(t, filepath.Join(dir, "cache/index1/shared_cpu_list"), s.shared+"\n")
		// L2: per core.
		writeFile(t, filepath.Join(dir, "cache/index2/level"), "2\n")
		writeFile(t, filepath.Join(dir, "cache/index2/type"), "Unified\n")
		writeFile(t, filepath.Join(dir, "cache/index2/id"), s.coreID+"\n")
		writeFile(t, filepath.Join(dir, "cache/index2/size"), "1024K\n")
		writeFile(t, filepath.Join(dir, "cache/index2/shared_cpu_list"), s.shared+"\n")
		// L3: shared by all.
		writeFile(t, filepath.Join(dir, "cache/index3/level"), "3\n")
		writeFile(t, filepath.Join(dir, "cache/index3/type"), "Unified\n")
		writeFile(t, filepath.Join(dir, "cache/index3/id"), "0\n")
		writeFile(t, filepath.Join(dir, "cache/index3/size"), "8M\n")
		writeFile(t, filepath.Join(dir, "cache/index3/shared_cpu_list"), "0-3\n")
		// Frequency.
		writeFile(t, filepath.Join(dir, "cpufreq/base_frequency"), "2400000\n")
		writeFile(t, filepath.Join(dir, "cpufreq/cpuinfo_max_freq"), "4800000\n")
	}
	writeFile(t, filepath.Join(cpuRoot, "isolated"), "2-3\n")
	writeFile(t, filepath.Join(cpuRoot, "nohz_full"), "2,3\n")
	return root
}

func itoa(i int) string {
	return string(rune('0' + i))
}

func TestReadCacheDomains(t *testing.T) {
	old := sysfsRoot
	sysfsRoot = fakeSysfs(t)
	defer func() { sysfsRoot = old }()

	domains := readCacheDomains()

	// Per-CPU views of the same cache must collapse into one entry each, and
	// no further: an L1d and an L1i sharing a level and an id are two caches
	// of different sizes, not one cache listing every CPU twice.
	want := []cacheDomain{
		{Level: 1, Type: "Data", ID: 0, SizeBytes: 48 * 1024, CPUs: []uint32{0, 1}},
		{Level: 1, Type: "Instruction", ID: 0, SizeBytes: 32 * 1024, CPUs: []uint32{0, 1}},
		{Level: 1, Type: "Data", ID: 1, SizeBytes: 48 * 1024, CPUs: []uint32{2, 3}},
		{Level: 1, Type: "Instruction", ID: 1, SizeBytes: 32 * 1024, CPUs: []uint32{2, 3}},
		{Level: 2, Type: "Unified", ID: 0, SizeBytes: 1024 * 1024, CPUs: []uint32{0, 1}},
		{Level: 2, Type: "Unified", ID: 1, SizeBytes: 1024 * 1024, CPUs: []uint32{2, 3}},
		{Level: 3, Type: "Unified", ID: 0, SizeBytes: 8 * 1024 * 1024, CPUs: []uint32{0, 1, 2, 3}},
	}
	if len(domains) != len(want) {
		t.Fatalf("want %d cache domains (4x L1, 2x L2, 1x L3), got %d: %+v",
			len(want), len(domains), domains)
	}
	for _, w := range want {
		var got *cacheDomain
		for i := range domains {
			if domains[i].Level == w.Level && domains[i].Type == w.Type && domains[i].ID == w.ID {
				if got != nil {
					t.Fatalf("L%d %s id %d reported twice", w.Level, w.Type, w.ID)
				}
				got = &domains[i]
			}
		}
		if got == nil {
			t.Errorf("no L%d %s id %d domain reported, got %+v", w.Level, w.Type, w.ID, domains)
			continue
		}
		if !reflect.DeepEqual(got.CPUs, w.CPUs) {
			t.Errorf("L%d %s id %d CPUs = %v, want %v", w.Level, w.Type, w.ID, got.CPUs, w.CPUs)
		}
		if got.SizeBytes != w.SizeBytes {
			t.Errorf("L%d %s id %d size = %d, want %d",
				w.Level, w.Type, w.ID, got.SizeBytes, w.SizeBytes)
		}
	}
}

// TestReadCacheDomains_NoTypeFile covers a platform whose cache indexes carry
// no type file: the caches must still collapse per (level, id) rather than
// disappearing or splitting per CPU.
func TestReadCacheDomains_NoTypeFile(t *testing.T) {
	old := sysfsRoot
	sysfsRoot = fakeSysfs(t)
	defer func() { sysfsRoot = old }()

	typeFiles, err := filepath.Glob(filepath.Join(sysfsRoot, "cpu", "cpu*", "cache", "index*", "type"))
	if err != nil || len(typeFiles) == 0 {
		t.Fatalf("Glob(type files) = %d files, err %v", len(typeFiles), err)
	}
	for _, path := range typeFiles {
		if err := os.Remove(path); err != nil {
			t.Fatalf("Remove(%s): %v", path, err)
		}
	}

	// Without a type file the L1d and L1i of a core are indistinguishable and
	// do merge -- unavoidably, and visibly as a doubled CPU list.
	for _, domain := range readCacheDomains() {
		if domain.Type != "" {
			t.Errorf("L%d id %d Type = %q, want empty", domain.Level, domain.ID, domain.Type)
		}
		if domain.Level >= 2 && !reflect.DeepEqual(domain.CPUs, expectedCPUs(domain)) {
			t.Errorf("L%d id %d CPUs = %v, want %v",
				domain.Level, domain.ID, domain.CPUs, expectedCPUs(domain))
		}
	}
}

// expectedCPUs returns the CPUs the fixture's L2/L3 caches are shared by.
func expectedCPUs(domain cacheDomain) []uint32 {
	if domain.Level == 3 {
		return []uint32{0, 1, 2, 3}
	}
	return []uint32{domain.ID * 2, domain.ID*2 + 1}
}

func TestCPUFrequencies(t *testing.T) {
	old := sysfsRoot
	sysfsRoot = fakeSysfs(t)
	defer func() { sysfsRoot = old }()

	base, max := cpuFrequencies(0)
	if base != 2400000 || max != 4800000 {
		t.Errorf("frequencies = %d/%d kHz, want 2400000/4800000", base, max)
	}

	// A platform without cpufreq must report zeros rather than failing: the
	// rest of the inventory is still worth sending.
	base, max = cpuFrequencies(99)
	if base != 0 || max != 0 {
		t.Errorf("missing cpufreq should report 0/0, got %d/%d", base, max)
	}
}

func TestIsolatedCPUSets(t *testing.T) {
	old := sysfsRoot
	sysfsRoot = fakeSysfs(t)
	defer func() { sysfsRoot = old }()

	isolated, nohzFull, rcuNocbs := IsolatedCPUSets()
	if !reflect.DeepEqual(isolated, []uint32{2, 3}) {
		t.Errorf("isolated = %v, want [2 3]", isolated)
	}
	if !reflect.DeepEqual(nohzFull, []uint32{2, 3}) {
		t.Errorf("nohz_full = %v, want [2 3]", nohzFull)
	}
	// rcu_nocbs is absent from the fixture, as it is on a stock kernel.
	if len(rcuNocbs) != 0 {
		t.Errorf("rcu_nocbs = %v, want empty when the file is absent", rcuNocbs)
	}
}

func TestParseCPUList(t *testing.T) {
	tests := []struct {
		in   string
		want []uint32
	}{
		{"", nil},
		{"\n", nil},
		{"3", []uint32{3}},
		{"0-3", []uint32{0, 1, 2, 3}},
		{"0-2,5", []uint32{0, 1, 2, 5}},
		{"2,3\n", []uint32{2, 3}},
		{"1-2,7-8", []uint32{1, 2, 7, 8}},
	}
	for _, tt := range tests {
		if got := parseCPUList(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseCPUList(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestReadCacheSize(t *testing.T) {
	dir := t.TempDir()
	for _, tt := range []struct {
		content string
		want    uint64
	}{
		{"32K", 32 * 1024},
		{"8M", 8 * 1024 * 1024},
		{"512", 512},
	} {
		path := filepath.Join(dir, "size")
		writeFile(t, path, tt.content)
		got, ok := readCacheSize(path)
		if !ok || got != tt.want {
			t.Errorf("readCacheSize(%q) = %d (ok=%v), want %d", tt.content, got, ok, tt.want)
		}
	}
}
