// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"os"
	"testing"
	"time"

	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The percentages getProcessMetric derives from one read of the process's
// times and memory must be the ones gopsutil computes.
func TestGetProcessMetricMatchesGopsutil(t *testing.T) {
	memory, err := mem.VirtualMemory()
	require.NoError(t, err)
	// As gatherProcessMetricList builds it.
	got, err := getProcessMetric(&process.Process{Pid: int32(os.Getpid())}, memory.Total)
	require.NoError(t, err)

	p, err := process.NewProcess(int32(os.Getpid()))
	require.NoError(t, err)

	name, err := p.Name()
	require.NoError(t, err)
	ct, err := p.CreateTime()
	require.NoError(t, err)
	cpuPercent, err := p.CPUPercent()
	require.NoError(t, err)
	memoryPercent, err := p.MemoryPercent()
	require.NoError(t, err)

	assert.Equal(t, p.Pid, got.Pid)
	assert.Equal(t, name, got.Name)
	assert.True(t, got.UserProcess)
	assert.Equal(t, time.UnixMilli(ct), got.CreateTime)
	assert.Positive(t, got.NumThreads)
	assert.Positive(t, got.NumFDs)
	assert.Positive(t, got.RssBytes)
	assert.Positive(t, got.UserTime+got.SystemTime)
	// gopsutil reads the times again, a moment later.
	assert.InDelta(t, cpuPercent, got.CPUPercent, 5)
	assert.InDelta(t, memoryPercent, got.MemoryPercent, 0.5)
}
