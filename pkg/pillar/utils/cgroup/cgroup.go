// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package cgroup reads and writes the host's cgroup v2 tree, which pillar sees
// read-write at /sys/fs/cgroup (bound in pkg/pillar/build*.yml). Groups are named
// relative to the root, e.g. "eve/services/pillar".
package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Root is the cgroup v2 mount point; tests point it at a temporary tree.
var Root = "/sys/fs/cgroup"

// Unlimited is what ReadUint returns for a file that reads "max".
const Unlimited = uint64(math.MaxUint64)

// Path returns the path of file in group.
func Path(group, file string) string {
	return filepath.Join(Root, group, file)
}

// ReadUint reads a cgroup file holding one number, such as memory.max or
// memory.current; "max" reads as Unlimited. A file the kernel does not provide
// (memory.peak before 5.19) returns an error matching os.ErrNotExist.
func ReadUint(group, file string) (uint64, error) {
	b, err := os.ReadFile(Path(group, file))
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	if s == "max" {
		return Unlimited, nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", Path(group, file), err)
	}
	return v, nil
}

// MemoryStat parses group's memory.stat. Keys the kernel does not report (the
// "kernel" line before 5.18) are absent from the map.
func MemoryStat(group string) (map[string]uint64, error) {
	f, err := os.Open(Path(group, "memory.stat"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	stat := make(map[string]uint64)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			continue
		}
		if v, err := strconv.ParseUint(val, 10, 64); err == nil {
			stat[key] = v
		}
	}
	return stat, sc.Err()
}

// FormatCPUs formats a CPU list the way cpuset.cpus takes it: "1,3,5".
func FormatCPUs(cpus []uint32) string {
	list := make([]string, len(cpus))
	for i, c := range cpus {
		list[i] = strconv.FormatUint(uint64(c), 10)
	}
	return strings.Join(list, ",")
}

// WriteCPUs sets group's cpuset.cpus. An empty list is refused: cgroup v2
// reads an empty cpuset.cpus as "inherit the parent's CPUs".
func WriteCPUs(group string, cpus []uint32) error {
	if len(cpus) == 0 {
		return errors.New("refusing an empty CPU list: on cgroup v2 it means every CPU of the parent")
	}
	return os.WriteFile(Path(group, "cpuset.cpus"), []byte(FormatCPUs(cpus)), 0)
}
