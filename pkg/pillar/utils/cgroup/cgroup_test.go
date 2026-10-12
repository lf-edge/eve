// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cgroup_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup"
	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup/cgrouptest"
)

func TestReadUint(t *testing.T) {
	cgrouptest.FakeTree(t, map[string]string{
		"eve/memory.max":                 "838860800\n",
		"eve/memory.current":             "123\n",
		"eve/services/pillar/memory.max": "max\n",
		"eve/bad":                        "twelve\n",
	})
	cases := []struct {
		group, file string
		want        uint64
	}{
		{"eve", "memory.max", 838860800},
		{"eve", "memory.current", 123},
		{"eve/services/pillar", "memory.max", cgroup.Unlimited},
	}
	for _, c := range cases {
		got, err := cgroup.ReadUint(c.group, c.file)
		if err != nil || got != c.want {
			t.Errorf("ReadUint(%q, %q) = %d, %v; want %d", c.group, c.file, got, err, c.want)
		}
	}
	if _, err := cgroup.ReadUint("eve", "memory.peak"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: err = %v, want os.ErrNotExist", err)
	}
	if _, err := cgroup.ReadUint("eve", "bad"); err == nil {
		t.Error("non-numeric file: want an error")
	}
}

func TestMemoryStat(t *testing.T) {
	cgrouptest.FakeTree(t, map[string]string{
		"eve/memory.stat": "anon 100\nfile 200\nkernel 300\nfile_mapped 7\nbroken\n",
	})
	stat, err := cgroup.MemoryStat("eve")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint64{"anon": 100, "file": 200, "kernel": 300, "file_mapped": 7}
	for k, v := range want {
		if stat[k] != v {
			t.Errorf("stat[%q] = %d, want %d", k, stat[k], v)
		}
	}
	if _, ok := stat["broken"]; ok {
		t.Error("a line without a value must be skipped")
	}
}

func TestFormatCPUs(t *testing.T) {
	for _, c := range []struct {
		cpus []uint32
		want string
	}{
		{nil, ""},
		{[]uint32{0}, "0"},
		{[]uint32{1, 3, 5}, "1,3,5"},
		{[]uint32{2, 3}, "2,3"},
	} {
		if got := cgroup.FormatCPUs(c.cpus); got != c.want {
			t.Errorf("FormatCPUs(%v) = %q, want %q", c.cpus, got, c.want)
		}
	}
}

func TestWriteCPUs(t *testing.T) {
	root := cgrouptest.FakeTree(t, map[string]string{"eve-user-apps/app.1.1/cpuset.cpus": "0-7\n"})
	if err := cgroup.WriteCPUs("eve-user-apps/app.1.1", []uint32{1, 3, 5}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, "eve-user-apps/app.1.1/cpuset.cpus"))
	if string(b) != "1,3,5" {
		t.Errorf("cpuset.cpus = %q, want \"1,3,5\"", b)
	}
}

// On cgroup v2 an empty cpuset.cpus means "inherit the parent's", i.e. every
// CPU, so an empty list must not reach the kernel.
func TestWriteCPUsRefusesEmpty(t *testing.T) {
	root := cgrouptest.FakeTree(t, map[string]string{"eve-user-apps/app.1.1/cpuset.cpus": "2-3"})
	if err := cgroup.WriteCPUs("eve-user-apps/app.1.1", nil); err == nil {
		t.Fatal("WriteCPUs(nil) must fail")
	}
	b, _ := os.ReadFile(filepath.Join(root, "eve-user-apps/app.1.1/cpuset.cpus"))
	if string(b) != "2-3" {
		t.Errorf("cpuset.cpus = %q after a refused write, want \"2-3\"", b)
	}
}

func TestNewPressureTriggerArms(t *testing.T) {
	root := cgrouptest.FakeTree(t, map[string]string{"eve/services/pillar/memory.pressure": ""})
	n, err := cgroup.NewPressureTrigger("eve/services/pillar", "memory", "some", 150*time.Millisecond, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	b, _ := os.ReadFile(filepath.Join(root, "eve/services/pillar/memory.pressure"))
	if string(b) != "some 150000 1000000" {
		t.Errorf("trigger written = %q, want \"some 150000 1000000\"", b)
	}
	if _, err := cgroup.NewPressureTrigger("eve/services/pillar", "memory", "most", time.Second, time.Second); err == nil {
		t.Error("kind \"most\" must be refused")
	}
	if _, err := cgroup.NewPressureTrigger("eve/missing", "memory", "some", time.Second, time.Second); err == nil {
		t.Error("a cgroup without memory.pressure (kernel without PSI) must return an error")
	}
}
