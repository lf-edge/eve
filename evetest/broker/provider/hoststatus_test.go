// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLocalHostStatus(t *testing.T) {
	procDir := t.TempDir()
	meminfo := "MemTotal:       65834320 kB\nMemFree:        18284404 kB\n" +
		"MemAvailable:   19681864 kB\nSwapTotal:       8388604 kB\nSwapFree:        6259152 kB\n" +
		"HugePages_Total:       0\n"
	if err := os.WriteFile(filepath.Join(procDir, "meminfo"), []byte(meminfo), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "loadavg"),
		[]byte("7.79 8.67 8.76 3/2817 1234567\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EVETEST_CLIENT_HOSTNAME", "workstation-1")
	st, err := localHostStatus(procDir)
	if err != nil {
		t.Fatalf("localHostStatus failed: %v", err)
	}
	if st.Name != "workstation-1" {
		t.Errorf("got host name %q, want EVETEST_CLIENT_HOSTNAME", st.Name)
	}
	if st.MemoryTotalBytes != 65834320*1024 || st.MemoryAvailableBytes != 19681864*1024 {
		t.Errorf("got memory total %d, available %d", st.MemoryTotalBytes, st.MemoryAvailableBytes)
	}
	if st.SwapTotalBytes != 8388604*1024 || st.SwapUsedBytes != (8388604-6259152)*1024 {
		t.Errorf("got swap total %d, used %d", st.SwapTotalBytes, st.SwapUsedBytes)
	}
	if !slices.Equal(st.LoadAverage, []float64{7.79, 8.67, 8.76}) {
		t.Errorf("got load average %v", st.LoadAverage)
	}
	if st.Cpus == 0 || st.CpuUsage != nil {
		t.Errorf("got %d CPUs, usage %v; want CPUs and no usage", st.Cpus, st.CpuUsage)
	}
}

func TestLocalHostStatusOnThisHost(t *testing.T) {
	if _, err := os.Stat("/proc/meminfo"); err != nil {
		t.Skip("no /proc/meminfo")
	}
	st, err := localHostStatus("/proc")
	if err != nil {
		t.Fatalf("localHostStatus failed: %v", err)
	}
	if st.MemoryTotalBytes == 0 || st.MemoryAvailableBytes == 0 ||
		st.MemoryAvailableBytes > st.MemoryTotalBytes || len(st.LoadAverage) != 3 {
		t.Errorf("implausible host status: %v", st)
	}
}
