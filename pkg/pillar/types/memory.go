// Copyright (c) 2018,2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"math"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/utils/cgroup"
)

// EveCgroup and PillarCgroup name EVE's cgroup and pillar's, relative to the
// cgroup v2 root (see pkg/dom0-ztools/rootfs/etc/init.d/010-eve-cgroup).
const (
	EveCgroup    = "eve"
	PillarCgroup = "eve/services/pillar"
)

// GetPillarHardMemoryLimitInBytes returns pillar's cgroup memory.max;
// cgroup.Unlimited when it has none.
func GetPillarHardMemoryLimitInBytes() (uint64, error) {
	return cgroup.ReadUint(PillarCgroup, "memory.max")
}

// GetEveMemoryLimitInBytes returns EVE's cgroup memory.max.
func GetEveMemoryLimitInBytes() (uint64, error) {
	return cgroup.ReadUint(EveCgroup, "memory.max")
}

// GetEveMemoryUsageInBytes returns the memory charged to EVE's cgroup, kernel
// memory included.
func GetEveMemoryUsageInBytes() (uint64, error) {
	return cgroup.ReadUint(EveCgroup, "memory.current")
}

// GetEveKmemUsageInBytes returns the kernel memory charged to EVE's cgroup,
// already part of GetEveMemoryUsageInBytes; 0 on kernels before 5.18, whose
// memory.stat has no "kernel" line.
func GetEveKmemUsageInBytes() (uint64, error) {
	stat, err := cgroup.MemoryStat(EveCgroup)
	if err != nil {
		return 0, err
	}
	return stat["kernel"], nil
}

// GetZFSArcMaxSizeInBytes returns memory limit
// reserved for zfs arc
func GetZFSArcMaxSizeInBytes() (uint64, error) {
	return readUint64File(ZFSArcMaxSizeFile)
}

func readUint64File(filename string) (uint64, error) {
	dataBytes, err := os.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	dataString := strings.TrimSpace(string(dataBytes))
	dataUint64, err := strconv.ParseUint(dataString, 10, 64)
	return dataUint64, err
}

// ConfigureGOGC sets two main configuration parameters for the
// garbage collector (GOGC): memory limit and percentage (see
// explanation here: https://tip.golang.org/doc/gc-guide).
// If limit is 0, create GOGC limit from the pillar cgroups hard
// memory limit.
func ConfigureGOGC(limit int64, percent int) (int64, int, error) {
	if limit == 0 {
		// Fallback to value from cgroups if no limit in the configuration
		ulimit, err := GetPillarHardMemoryLimitInBytes()
		if err != nil {
			err := fmt.Errorf("can't receive pillar memory hard limit: '%w'", err)
			return -1, -1, err
		}
		// Reduce actual memory limit to 0.6 of cgroup limit. The logic behind
		// the constant is simple: cgroup limit is a hard limit for the whole
		// pillar cgroup, meaning when reached, we are killed by OOM. In turn
		// GOGC memory limit is a soft limit, so the difference must be
		// significant to ensure that after the soft limit is reached, there
		// will be enough memory for the GOGC to do its job and, fortunately,
		// not to hit the hard limit.
		if ulimit == cgroup.Unlimited || ulimit > math.MaxInt64/600 {
			// No cgroup limit (or one too large to scale), so no Go memory limit either.
			limit = math.MaxInt64
		} else {
			limit = int64(ulimit) * 600 / 1000
		}
	}
	if percent == 0 {
		// Disable GC
		percent = -1
	}
	// Set new and retrieve previous values
	limit = debug.SetMemoryLimit(limit)
	percent = debug.SetGCPercent(percent)

	return limit, percent, nil
}
