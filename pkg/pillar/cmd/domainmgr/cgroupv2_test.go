// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup/cgrouptest"
	uuid "github.com/satori/go.uuid"
)

func testDomain() *types.DomainConfig {
	return &types.DomainConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: uuid.FromStringOrNil("4f1a7c3e-2b9d-4e8a-9c21-7d4e5f6a8b90"), Version: "1"},
		AppNum:         1,
		DisplayName:    "app",
	}
}

func TestSetCgroupCpusetWritesTheTaskCgroup(t *testing.T) {
	config := testDomain()
	file := filepath.Join("eve-user-apps", config.GetTaskName(), "cpuset.cpus")
	root := cgrouptest.FakeTree(t, map[string]string{file: "0-7"})
	status := &types.DomainStatus{}
	status.VmConfig.CPUs = []uint32{2, 3}

	if err := setCgroupCpuset(config, status); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, file))
	if string(b) != "2,3" {
		t.Errorf("cpuset.cpus = %q, want \"2,3\"", b)
	}
}

func TestSetCgroupCpusetWithoutCgroupIsNotAnError(t *testing.T) {
	cgrouptest.FakeTree(t, nil)
	status := &types.DomainStatus{}
	status.VmConfig.CPUs = []uint32{1}
	if err := setCgroupCpuset(testDomain(), status); err != nil {
		t.Errorf("missing cgroup: err = %v, want nil", err)
	}
}

func TestCompressorAvailMemTakesTheTightestCgroup(t *testing.T) {
	cgrouptest.FakeTree(t, map[string]string{
		"eve/memory.max":                     "800000000",
		"eve/memory.current":                 "500000000",
		"eve/services/memory.max":            "650000000",
		"eve/services/memory.current":        "600000000",
		"eve/services/pillar/memory.max":     "650000000",
		"eve/services/pillar/memory.current": "640000000",
	})
	if got := compressorAvailMem(); got != 10000000 {
		t.Errorf("compressorAvailMem() = %d, want 10000000 (pillar's headroom)", got)
	}
}

// An unlimited cgroup does not bind, so its memory.current is not even read.
func TestCompressorAvailMemUnlimitedFallsBackToSystemRAM(t *testing.T) {
	cgrouptest.FakeTree(t, map[string]string{
		"eve/memory.max":                 "max",
		"eve/services/memory.max":        "max",
		"eve/services/pillar/memory.max": "max",
	})
	// MemAvailable moves between reads, so allow 10% drift.
	before := sysMemAvailableBytes()
	got := compressorAvailMem()
	diff := got - before
	if before > got {
		diff = before - got
	}
	if got == 0 || diff > before/10 {
		t.Errorf("compressorAvailMem() = %d, want within 10%% of MemAvailable %d", got, before)
	}
}

func TestCompressorAvailMemUnreadableCgroupUsesMinimumWindow(t *testing.T) {
	cgrouptest.FakeTree(t, map[string]string{"eve/memory.max": "800000000"})
	if got := compressorAvailMem(); got != 0 {
		t.Errorf("compressorAvailMem() = %d, want 0 (minimum window)", got)
	}
}
