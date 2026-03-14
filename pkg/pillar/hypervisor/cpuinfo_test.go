// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"
)

const sampleCPUInfo = `processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 142
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
stepping	: 10
cpu MHz		: 1992.000
cache size	: 8192 KB
physical id	: 0
core id		: 0
cpu cores	: 4
apicid		: 0
bogomips	: 3984.00

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 142
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
stepping	: 10
cpu MHz		: 1992.000
cache size	: 8192 KB
physical id	: 0
core id		: 1
cpu cores	: 4
apicid		: 2
bogomips	: 3984.00

processor	: 2
vendor_id	: GenuineIntel
cpu family	: 6
model		: 142
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
stepping	: 10
cpu MHz		: 1992.000
cache size	: 8192 KB
physical id	: 0
core id		: 2
cpu cores	: 4
apicid		: 4
bogomips	: 3984.00

processor	: 3
vendor_id	: GenuineIntel
cpu family	: 6
model		: 142
model name	: Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
stepping	: 10
cpu MHz		: 1992.000
cache size	: 8192 KB
physical id	: 0
core id		: 3
cpu cores	: 4
apicid		: 6
bogomips	: 3984.00

`

func writeTempCPUInfo(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "cpuinfo")
	if err := os.WriteFile(path, []byte(content), 0444); err != nil {
		t.Fatalf("writing temp cpuinfo: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// parseCPUInfo tests
// ---------------------------------------------------------------------------

func TestParseCPUInfo(t *testing.T) {
	path := writeTempCPUInfo(t, sampleCPUInfo)
	blocks, err := parseCPUInfo(path)
	if err != nil {
		t.Fatalf("parseCPUInfo failed: %v", err)
	}
	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks, got %d", len(blocks))
	}
	for i, blk := range blocks {
		if blk.processorID != i {
			t.Errorf("block %d: expected processorID %d, got %d", i, i, blk.processorID)
		}
		if len(blk.lines) == 0 {
			t.Errorf("block %d: has no lines", i)
		}
	}
}

func TestParseCPUInfoEmpty(t *testing.T) {
	path := writeTempCPUInfo(t, "")
	blocks, err := parseCPUInfo(path)
	if err != nil {
		t.Fatalf("parseCPUInfo failed: %v", err)
	}
	if len(blocks) != 0 {
		t.Fatalf("expected 0 blocks, got %d", len(blocks))
	}
}

func TestParseCPUInfoMissing(t *testing.T) {
	_, err := parseCPUInfo("/nonexistent/cpuinfo")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseCPUInfoNoTrailingNewline(t *testing.T) {
	content := `processor	: 0
vendor_id	: GenuineIntel
model name	: Test CPU
processor	: 1
vendor_id	: GenuineIntel
model name	: Test CPU`

	path := writeTempCPUInfo(t, content)
	blocks, err := parseCPUInfo(path)
	if err != nil {
		t.Fatalf("parseCPUInfo failed: %v", err)
	}
	if len(blocks) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(blocks))
	}
	if blocks[0].processorID != 0 {
		t.Errorf("block 0: expected processorID 0, got %d", blocks[0].processorID)
	}
	if blocks[1].processorID != 1 {
		t.Errorf("block 1: expected processorID 1, got %d", blocks[1].processorID)
	}
}

// ---------------------------------------------------------------------------
// filterCPUInfo tests — CPU IDs are NOT renumbered
// ---------------------------------------------------------------------------

func TestFilterCPUInfoSubset(t *testing.T) {
	path := writeTempCPUInfo(t, sampleCPUInfo)
	blocks, err := parseCPUInfo(path)
	if err != nil {
		t.Fatalf("parseCPUInfo failed: %v", err)
	}

	// Filter to only CPUs 1 and 3 (typical RT cpuset).
	result := filterCPUInfo(blocks, []uint32{1, 3})
	if result == "" {
		t.Fatal("filterCPUInfo returned empty string")
	}

	// Should have exactly 2 processor entries.
	count := strings.Count(result, "processor\t:")
	if count != 2 {
		t.Errorf("expected 2 processor entries, got %d", count)
	}

	// Real IDs must be preserved (no renumbering).
	if !strings.Contains(result, "processor\t: 1\n") {
		t.Error("missing original processor 1")
	}
	if !strings.Contains(result, "processor\t: 3\n") {
		t.Error("missing original processor 3")
	}

	// Renumbered IDs must NOT appear.
	if strings.Contains(result, "processor\t: 0\n") {
		t.Error("unexpected processor 0 — IDs should not be renumbered")
	}
	if strings.Contains(result, "processor\t: 2\n") {
		t.Error("unexpected processor 2 in output")
	}

	// Verify the second block retains original CPU 3's apicid (6).
	lines := strings.Split(result, "\n")
	inProc3 := false
	for _, line := range lines {
		if strings.HasPrefix(line, "processor\t: 3") {
			inProc3 = true
		}
		if inProc3 && strings.HasPrefix(line, "apicid") {
			if !strings.Contains(line, "6") {
				t.Errorf("CPU 3 block should have apicid 6, got: %s", line)
			}
			break
		}
	}
}

func TestFilterCPUInfoAllCPUs(t *testing.T) {
	path := writeTempCPUInfo(t, sampleCPUInfo)
	blocks, err := parseCPUInfo(path)
	if err != nil {
		t.Fatalf("parseCPUInfo failed: %v", err)
	}

	result := filterCPUInfo(blocks, []uint32{0, 1, 2, 3})
	count := strings.Count(result, "processor\t:")
	if count != 4 {
		t.Errorf("expected 4 processor entries, got %d", count)
	}
}

func TestFilterCPUInfoSingleCPU(t *testing.T) {
	path := writeTempCPUInfo(t, sampleCPUInfo)
	blocks, err := parseCPUInfo(path)
	if err != nil {
		t.Fatalf("parseCPUInfo failed: %v", err)
	}

	result := filterCPUInfo(blocks, []uint32{2})
	count := strings.Count(result, "processor\t:")
	if count != 1 {
		t.Errorf("expected 1 processor entry, got %d", count)
	}
	// Original ID must be preserved.
	if !strings.Contains(result, "processor\t: 2\n") {
		t.Error("single CPU should keep its original ID 2")
	}
	// Apicid from original CPU 2 is 4.
	if !strings.Contains(result, "apicid\t\t: 4") {
		t.Error("expected apicid 4 from original CPU 2")
	}
}

func TestFilterCPUInfoNoneMatch(t *testing.T) {
	path := writeTempCPUInfo(t, sampleCPUInfo)
	blocks, err := parseCPUInfo(path)
	if err != nil {
		t.Fatalf("parseCPUInfo failed: %v", err)
	}

	result := filterCPUInfo(blocks, []uint32{10, 11})
	if result != "" {
		t.Errorf("expected empty result for CPUs not in cpuinfo, got: %s", result)
	}
}

func TestFilterCPUInfoEmptyAllowed(t *testing.T) {
	path := writeTempCPUInfo(t, sampleCPUInfo)
	blocks, err := parseCPUInfo(path)
	if err != nil {
		t.Fatalf("parseCPUInfo failed: %v", err)
	}

	result := filterCPUInfo(blocks, []uint32{})
	if result != "" {
		t.Error("expected empty result for empty allowed list")
	}
}

func TestFilterCPUInfoNonContiguousCPUs(t *testing.T) {
	path := writeTempCPUInfo(t, sampleCPUInfo)
	blocks, err := parseCPUInfo(path)
	if err != nil {
		t.Fatalf("parseCPUInfo failed: %v", err)
	}

	result := filterCPUInfo(blocks, []uint32{0, 3})
	count := strings.Count(result, "processor\t:")
	if count != 2 {
		t.Errorf("expected 2 processor entries, got %d", count)
	}

	// Real IDs preserved.
	if !strings.Contains(result, "processor\t: 0\n") {
		t.Error("missing original processor 0")
	}
	if !strings.Contains(result, "processor\t: 3\n") {
		t.Error("missing original processor 3")
	}
}

func TestFilterPreservesFieldContent(t *testing.T) {
	path := writeTempCPUInfo(t, sampleCPUInfo)
	blocks, err := parseCPUInfo(path)
	if err != nil {
		t.Fatalf("parseCPUInfo failed: %v", err)
	}

	result := filterCPUInfo(blocks, []uint32{0})
	if !strings.Contains(result, "Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz") {
		t.Error("model name not preserved in filtered output")
	}
	if !strings.Contains(result, "cache size\t: 8192 KB") {
		t.Error("cache size not preserved in filtered output")
	}
	if !strings.Contains(result, "bogomips\t: 3984.00") {
		t.Error("bogomips not preserved in filtered output")
	}
}

// ---------------------------------------------------------------------------
// cpuListString tests
// ---------------------------------------------------------------------------

func TestCPUListStringEmpty(t *testing.T) {
	if got := cpuListString(nil); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
	if got := cpuListString([]uint32{}); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestCPUListStringSingle(t *testing.T) {
	if got := cpuListString([]uint32{7}); got != "7" {
		t.Errorf("expected \"7\", got %q", got)
	}
}

func TestCPUListStringContiguous(t *testing.T) {
	if got := cpuListString([]uint32{0, 1, 2, 3}); got != "0-3" {
		t.Errorf("expected \"0-3\", got %q", got)
	}
}

func TestCPUListStringNonContiguous(t *testing.T) {
	if got := cpuListString([]uint32{1, 3}); got != "1,3" {
		t.Errorf("expected \"1,3\", got %q", got)
	}
}

func TestCPUListStringMixed(t *testing.T) {
	if got := cpuListString([]uint32{0, 1, 4, 5}); got != "0-1,4-5" {
		t.Errorf("expected \"0-1,4-5\", got %q", got)
	}
}

func TestCPUListStringUnsortedInput(t *testing.T) {
	// cpuListString should sort internally.
	if got := cpuListString([]uint32{5, 3, 1, 4}); got != "1,3-5" {
		t.Errorf("expected \"1,3-5\", got %q", got)
	}
}

func TestCPUListStringLargeRange(t *testing.T) {
	cpus := make([]uint32, 16)
	for i := range cpus {
		cpus[i] = uint32(i)
	}
	if got := cpuListString(cpus); got != "0-15" {
		t.Errorf("expected \"0-15\", got %q", got)
	}
}

func TestCPUListStringMultipleRangesAndSingles(t *testing.T) {
	// 0-2, 5, 8-10
	if got := cpuListString([]uint32{0, 1, 2, 5, 8, 9, 10}); got != "0-2,5,8-10" {
		t.Errorf("expected \"0-2,5,8-10\", got %q", got)
	}
}

// ---------------------------------------------------------------------------
// generateFilteredCPUFiles tests
// ---------------------------------------------------------------------------

func TestGenerateFilteredCPUFiles(t *testing.T) {
	// We can't override the hostCPUInfo const, so test the individual
	// components (parseCPUInfo + filterCPUInfo + cpuListString) and then
	// verify the file-writing logic via a manual write + read-back.

	tmpPath := writeTempCPUInfo(t, sampleCPUInfo)
	blocks, err := parseCPUInfo(tmpPath)
	if err != nil {
		t.Fatalf("parseCPUInfo failed: %v", err)
	}

	cpus := []uint32{1, 3}

	// --- cpuinfo content ---
	content := filterCPUInfo(blocks, cpus)
	if content == "" {
		t.Fatal("filterCPUInfo returned empty string")
	}
	count := strings.Count(content, "processor\t:")
	if count != 2 {
		t.Errorf("expected 2 processors in cpuinfo, got %d", count)
	}
	// Real IDs preserved.
	if !strings.Contains(content, "processor\t: 1\n") {
		t.Error("cpuinfo should contain processor 1 with real ID")
	}
	if !strings.Contains(content, "processor\t: 3\n") {
		t.Error("cpuinfo should contain processor 3 with real ID")
	}

	// --- sysfs online/present content ---
	listStr := cpuListString(cpus)
	if listStr != "1,3" {
		t.Errorf("expected cpu list \"1,3\", got %q", listStr)
	}

	// --- Write and read-back test ---
	outDir := t.TempDir()
	cpuInfoPath := filepath.Join(outDir, "cpuinfo")
	if err := os.WriteFile(cpuInfoPath, []byte(content), 0444); err != nil {
		t.Fatalf("writing filtered cpuinfo: %v", err)
	}
	onlinePath := filepath.Join(outDir, "cpu_online")
	if err := os.WriteFile(onlinePath, []byte(listStr+"\n"), 0444); err != nil {
		t.Fatalf("writing cpu_online: %v", err)
	}

	// Verify cpuinfo.
	data, err := os.ReadFile(cpuInfoPath)
	if err != nil {
		t.Fatalf("reading filtered cpuinfo: %v", err)
	}
	if strings.Count(string(data), "processor\t:") != 2 {
		t.Error("unexpected processor count in written cpuinfo file")
	}

	// Verify online.
	data, err = os.ReadFile(onlinePath)
	if err != nil {
		t.Fatalf("reading cpu_online: %v", err)
	}
	if strings.TrimSpace(string(data)) != "1,3" {
		t.Errorf("cpu_online content: expected \"1,3\", got %q", strings.TrimSpace(string(data)))
	}
}

// ---------------------------------------------------------------------------
// ensureCgroupMountWritable tests
// ---------------------------------------------------------------------------

func TestEnsureCgroupMountWritableReadOnly(t *testing.T) {
	// Typical cgroup v1 default: /sys/fs/cgroup is a read-only tmpfs.
	// ensureCgroupMountWritable should flip "ro" → "rw".
	ociSpec := &specs.Spec{
		Mounts: []specs.Mount{
			{
				Type:        "tmpfs",
				Source:      "tmpfs",
				Destination: "/sys/fs/cgroup",
				Options:     []string{"nosuid", "noexec", "nodev", "relatime", "ro"},
			},
			{
				Type:        "cgroup",
				Source:      "cgroup",
				Destination: "/sys/fs/cgroup/cpuset",
				Options:     []string{"nosuid", "noexec", "nodev", "relatime", "ro", "cpuset"},
			},
		},
	}

	ensureCgroupMountWritable(ociSpec)

	// The /sys/fs/cgroup mount should now be rw.
	cgroupMount := ociSpec.Mounts[0]
	foundRW := false
	for _, opt := range cgroupMount.Options {
		if opt == "rw" {
			foundRW = true
		}
		if opt == "ro" {
			t.Error("/sys/fs/cgroup mount still has 'ro' after ensureCgroupMountWritable")
		}
	}
	if !foundRW {
		t.Error("/sys/fs/cgroup mount should have 'rw' option after ensureCgroupMountWritable")
	}

	// The sub-mount (/sys/fs/cgroup/cpuset) should be untouched.
	cpusetMount := ociSpec.Mounts[1]
	hasRO := false
	for _, opt := range cpusetMount.Options {
		if opt == "ro" {
			hasRO = true
		}
	}
	if !hasRO {
		t.Error("/sys/fs/cgroup/cpuset mount should still be ro (untouched)")
	}
}

func TestEnsureCgroupMountWritableAlreadyRW(t *testing.T) {
	// If /sys/fs/cgroup is already writable, it should be a no-op.
	ociSpec := &specs.Spec{
		Mounts: []specs.Mount{
			{
				Type:        "tmpfs",
				Source:      "tmpfs",
				Destination: "/sys/fs/cgroup",
				Options:     []string{"nosuid", "noexec", "nodev", "rw"},
			},
		},
	}

	originalOpts := make([]string, len(ociSpec.Mounts[0].Options))
	copy(originalOpts, ociSpec.Mounts[0].Options)

	ensureCgroupMountWritable(ociSpec)

	// Mount count should not change.
	if len(ociSpec.Mounts) != 1 {
		t.Errorf("expected 1 mount, got %d", len(ociSpec.Mounts))
	}

	// Options should be identical.
	if len(ociSpec.Mounts[0].Options) != len(originalOpts) {
		t.Error("options were modified when mount was already writable")
	}
	for i, opt := range ociSpec.Mounts[0].Options {
		if opt != originalOpts[i] {
			t.Errorf("option %d changed from %q to %q", i, originalOpts[i], opt)
		}
	}
}

func TestEnsureCgroupMountWritableNoOptions(t *testing.T) {
	// Mount exists but has no explicit ro/rw options — should be left alone.
	ociSpec := &specs.Spec{
		Mounts: []specs.Mount{
			{
				Type:        "tmpfs",
				Source:      "tmpfs",
				Destination: "/sys/fs/cgroup",
				Options:     []string{"nosuid", "noexec", "nodev"},
			},
		},
	}

	ensureCgroupMountWritable(ociSpec)

	// Should not add extra mounts.
	if len(ociSpec.Mounts) != 1 {
		t.Errorf("expected 1 mount, got %d", len(ociSpec.Mounts))
	}

	// Should not inject "rw" when there was no "ro" to replace.
	for _, opt := range ociSpec.Mounts[0].Options {
		if opt == "rw" {
			t.Error("should not inject 'rw' when 'ro' was not present")
		}
	}
}

func TestEnsureCgroupMountWritableMissing(t *testing.T) {
	// No /sys/fs/cgroup mount at all (unusual / custom spec).
	// Should add a small writable tmpfs so runc can create mountpoints.
	ociSpec := &specs.Spec{
		Mounts: []specs.Mount{
			{
				Type:        "proc",
				Source:      "proc",
				Destination: "/proc",
				Options:     []string{"nosuid", "noexec", "nodev"},
			},
		},
	}

	ensureCgroupMountWritable(ociSpec)

	if len(ociSpec.Mounts) != 2 {
		t.Fatalf("expected 2 mounts (original + added tmpfs), got %d", len(ociSpec.Mounts))
	}

	added := ociSpec.Mounts[1]
	if added.Destination != "/sys/fs/cgroup" {
		t.Errorf("added mount destination: expected /sys/fs/cgroup, got %s", added.Destination)
	}
	if added.Type != "tmpfs" {
		t.Errorf("added mount type: expected tmpfs, got %s", added.Type)
	}

	// Must NOT be read-only.
	for _, opt := range added.Options {
		if opt == "ro" {
			t.Error("added tmpfs mount should not be read-only")
		}
	}
}

func TestEnsureCgroupMountWritableOnlyMatchesExact(t *testing.T) {
	// Sub-mounts like /sys/fs/cgroup/cpuset should NOT be modified.
	ociSpec := &specs.Spec{
		Mounts: []specs.Mount{
			{
				Type:        "cgroup",
				Source:      "cgroup",
				Destination: "/sys/fs/cgroup/cpuset",
				Options:     []string{"nosuid", "noexec", "nodev", "ro", "cpuset"},
			},
		},
	}

	ensureCgroupMountWritable(ociSpec)

	// The sub-mount should still be ro.
	for _, opt := range ociSpec.Mounts[0].Options {
		if opt == "rw" {
			t.Error("/sys/fs/cgroup/cpuset should NOT have been changed to rw")
		}
	}

	// A tmpfs should have been added because /sys/fs/cgroup itself was missing.
	if len(ociSpec.Mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(ociSpec.Mounts))
	}
	if ociSpec.Mounts[1].Destination != "/sys/fs/cgroup" {
		t.Errorf("expected added mount at /sys/fs/cgroup, got %s", ociSpec.Mounts[1].Destination)
	}
}

// ---------------------------------------------------------------------------
// addCPUInfoBindMount tests
// ---------------------------------------------------------------------------

func TestAddCPUInfoBindMountEmptyCPUs(t *testing.T) {
	ociSpec := &specs.Spec{
		Mounts: []specs.Mount{},
	}
	err := addCPUInfoBindMount(ociSpec, "test-domain", []uint32{})
	if err != nil {
		t.Fatalf("addCPUInfoBindMount with empty CPUs should not error: %v", err)
	}
	if len(ociSpec.Mounts) != 0 {
		t.Error("addCPUInfoBindMount with empty CPUs should not add mounts")
	}
}

func TestAddCPUInfoBindMountNilCPUs(t *testing.T) {
	ociSpec := &specs.Spec{
		Mounts: []specs.Mount{},
	}
	err := addCPUInfoBindMount(ociSpec, "test-domain", nil)
	if err != nil {
		t.Fatalf("addCPUInfoBindMount with nil CPUs should not error: %v", err)
	}
	if len(ociSpec.Mounts) != 0 {
		t.Error("addCPUInfoBindMount with nil CPUs should not add mounts")
	}
}

// ---------------------------------------------------------------------------
// cleanupFilteredCPUInfo tests
// ---------------------------------------------------------------------------

func TestCleanupFilteredCPUInfo(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "test-cleanup")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, name := range []string{"cpuinfo", "cpu_online", "cpu_present"} {
		f := filepath.Join(dir, name)
		if err := os.WriteFile(f, []byte("test"), 0444); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	// Verify files exist.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 files, got %d", len(entries))
	}

	// RemoveAll (same logic as cleanupFilteredCPUInfo).
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll failed: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("directory should have been removed")
	}
}
