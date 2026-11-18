// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

// localHostStatus describes the Linux host the broker runs on, for providers
// that run devices locally. procDir is normally "/proc". Inside a container,
// /proc/meminfo and /proc/loadavg still describe the host, but the hostname
// is the container's own, so the host name set by "make evetest" is preferred:
// the qemu provider runs in the evetest container.
func localHostStatus(procDir string) (*api.HostStatus, error) {
	st := &api.HostStatus{Cpus: uint32(runtime.NumCPU())}
	st.Name = os.Getenv(constants.EnvPrefix + constants.ClientHostnameEnv)
	if st.Name == "" {
		st.Name, _ = os.Hostname()
	}

	meminfo, err := readMeminfo(procDir + "/meminfo")
	if err != nil {
		return nil, err
	}
	st.MemoryTotalBytes = meminfo["MemTotal"]
	st.MemoryAvailableBytes = meminfo["MemAvailable"]
	st.SwapTotalBytes = meminfo["SwapTotal"]
	st.SwapUsedBytes = meminfo["SwapTotal"] - min(meminfo["SwapFree"], meminfo["SwapTotal"])

	loadavg, err := os.ReadFile(procDir + "/loadavg")
	if err != nil {
		return nil, fmt.Errorf("failed to read load average: %w", err)
	}
	if st.LoadAverage, err = parseLoadAverage(strings.Fields(string(loadavg))); err != nil {
		return nil, err
	}
	return st, nil
}

// readMeminfo returns the byte values of /proc/meminfo, keyed by name.
func readMeminfo(path string) (map[string]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read memory info: %w", err)
	}
	defer func() { _ = f.Close() }()
	values := make(map[string]uint64)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// e.g. "MemAvailable:   19681864 kB"
		name, rest, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && fields[1] == "kB" {
			v *= 1024
		}
		values[name] = v
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read memory info: %w", err)
	}
	return values, nil
}

// parseLoadAverage parses the 1, 5 and 15 minute load averages, the first
// three of the given fields.
func parseLoadAverage(fields []string) ([]float64, error) {
	if len(fields) < 3 {
		return nil, fmt.Errorf("unexpected load average %q", strings.Join(fields, " "))
	}
	loads := make([]float64, 3)
	for i := range loads {
		v, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return nil, fmt.Errorf("unexpected load average %q: %w", fields[i], err)
		}
		loads[i] = v
	}
	return loads, nil
}
