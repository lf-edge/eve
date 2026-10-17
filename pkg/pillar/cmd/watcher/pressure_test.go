// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup/cgrouptest"
)

func TestMemoryPressureNotifierArmsPSI(t *testing.T) {
	root := cgrouptest.FakeTree(t, map[string]string{
		"eve/services/pillar/memory.pressure": "",
		"eve/services/pillar/memory.events":   "",
	})
	n, err := memoryPressureNotifier()
	if err != nil {
		t.Fatal(err)
	}
	n.Close()
	b, _ := os.ReadFile(filepath.Join(root, "eve/services/pillar/memory.pressure"))
	if string(b) != "some 150000 1000000" {
		t.Errorf("trigger = %q, want \"some 150000 1000000\"", b)
	}
}

// A kernel without PSI (NVIDIA jp7 today) has no memory.pressure. That the
// memory.events notifier waits for a change is tested in utils/cgroup, on a
// real kernfs file.
func TestMemoryPressureNotifierFallsBackToMemoryEvents(t *testing.T) {
	cgrouptest.FakeTree(t, map[string]string{"eve/services/pillar/memory.events": ""})
	n, err := memoryPressureNotifier()
	if err != nil {
		t.Fatalf("without PSI: %v, want a memory.events notifier", err)
	}
	n.Close()
}

func TestMemoryPressureNotifierWithoutCgroupFails(t *testing.T) {
	cgrouptest.FakeTree(t, nil)
	if _, err := memoryPressureNotifier(); err == nil {
		t.Error("no memory.pressure and no memory.events: want an error")
	}
}
