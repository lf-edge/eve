// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cputopology

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"

	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/zededa/ghw/pkg/linuxpath"
	"github.com/zededa/ghw/pkg/util"
)

// KernelIsolation returns the CPUs the running kernel keeps away from the
// scheduler's load balancing (isolcpus) and runs without the periodic tick
// (nohz_full), as sysfs reports what the kernel does rather than what its
// command line asked for. It is how the kernel was booted, not what the CPUs
// are, so it is not part of Topology. ctx is a ghw context, which sets the
// sysfs root as it does for Discover: ghw.ContextFromEnv(), or
// ghw.WithChroot(root) applied to it for a fixture tree.
//
// A missing file is an empty list: the kernel has no nohz_full file without
// NO_HZ_FULL. An unreadable or malformed one is an error.
func KernelIsolation(ctx context.Context) (isolated, nohzFull []LCPU, err error) {
	dir := linuxpath.New(ctx).SysDevicesSystemCPU
	if isolated, err = readOptionalCPUList(filepath.Join(dir, "isolated")); err != nil {
		return nil, nil, err
	}
	if nohzFull, err = readOptionalCPUList(filepath.Join(dir, "nohz_full")); err != nil {
		return nil, nil, err
	}
	return isolated, nohzFull, nil
}

func readOptionalCPUList(path string) ([]LCPU, error) {
	ids, err := util.ReadCPUList(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return generics.MapList(ids, func(id int) LCPU { return LCPU(id) }), nil
}
