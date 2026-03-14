// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// cpuinfo.go provides helpers for generating filtered /proc/cpuinfo and
// /sys/devices/system/cpu/{online,present} files that only expose the CPUs
// present in a container's cpuset.
//
// Linux does not namespace /proc/cpuinfo or the sysfs CPU topology files —
// every container sees all host CPUs regardless of cgroup cpuset
// restrictions.  Industrial runtimes such as CODESYS use multiple methods
// to discover the number of available cores:
//
//  1. /sys/fs/cgroup/cpuset.cpus.effective (cgroup v2) — preferred by CODESYS V3.5.21+
//  2. /proc/stat — count "cpuN" lines (fallback when #1 is absent)
//  3. /proc/cpuinfo — count "processor" entries
//  4. sysconf(_SC_NPROCESSORS_ONLN) — glibc reads /sys/devices/system/cpu/online
//  5. sysconf(_SC_NPROCESSORS_CONF) — glibc reads /sys/devices/system/cpu/present
//
// CODESYS then creates per-CPU threads (SchedProcessorL*) and pins them
// via sched_setaffinity().  When the cpuset is a strict subset of the host
// CPUs, affinity calls for CPUs outside the cpuset fail with EINVAL,
// causing "Binding of task … to group System failed" errors.
//
// Critically, CODESYS V3.5.21.30 checks /sys/fs/cgroup/cpuset.cpus.effective
// first.  On cgroup v2 hosts this file exists natively, but on cgroup v1
// it does not.  When absent, CODESYS falls back to /proc/stat which shows
// ALL host CPUs (not namespaced), leading to the failures above.  We
// synthesize this file so CODESYS detects only the assigned CPUs regardless
// of cgroup version.
//
// IMPORTANT: We do NOT renumber CPU IDs.  The kernel's sched_setaffinity()
// always uses real (host) CPU numbers, and the cpuset cgroup enforces real
// CPU IDs.  If we renumbered processor 3 → 1 in /proc/cpuinfo, the
// application would call sched_setaffinity(CPU 1) instead of the correct
// sched_setaffinity(CPU 3), potentially hitting a CPU outside the cpuset.
// By preserving real IDs, applications that read /proc/cpuinfo or parse
// /sys/devices/system/cpu/online will use the correct CPU numbers for
// affinity calls.

package hypervisor

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

const (
	// hostCPUInfo is the host's cpuinfo path.
	hostCPUInfo = "/proc/cpuinfo"

	// cpuInfoDir is the base directory for generated per-container
	// cpuinfo and sysfs override files.
	cpuInfoDir = "/run/tasks/proc"
)

// processorLineRe matches "processor\t: <N>" lines in /proc/cpuinfo.
var processorLineRe = regexp.MustCompile(`^processor\s*:\s*(\d+)\s*$`)

// cpuInfoBlock represents a single processor entry from /proc/cpuinfo.
type cpuInfoBlock struct {
	processorID int
	lines       []string
}

// parseCPUInfo reads /proc/cpuinfo and splits it into per-processor blocks.
// Each block starts with a "processor : N" line and ends at the next blank
// line (or EOF).
func parseCPUInfo(path string) ([]cpuInfoBlock, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var blocks []cpuInfoBlock
	var current *cpuInfoBlock

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Check if this is a "processor : N" line.
		if m := processorLineRe.FindStringSubmatch(line); m != nil {
			id, _ := strconv.Atoi(m[1])
			blocks = append(blocks, cpuInfoBlock{processorID: id})
			current = &blocks[len(blocks)-1]
			current.lines = append(current.lines, line)
			continue
		}

		if current != nil {
			current.lines = append(current.lines, line)
			// A blank line ends the current block on most architectures.
			if strings.TrimSpace(line) == "" {
				current = nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	return blocks, nil
}

// filterCPUInfo returns a filtered cpuinfo string containing only the
// blocks for the given allowedCPUs.  Processor IDs are preserved (NOT
// renumbered) so that sched_setaffinity() calls using these IDs will
// reference the correct host CPUs that are in the cpuset.
func filterCPUInfo(blocks []cpuInfoBlock, allowedCPUs []uint32) string {
	allowed := make(map[int]bool, len(allowedCPUs))
	for _, cpu := range allowedCPUs {
		allowed[int(cpu)] = true
	}

	var sb strings.Builder
	for _, blk := range blocks {
		if !allowed[blk.processorID] {
			continue
		}
		for _, line := range blk.lines {
			sb.WriteString(line)
			sb.WriteByte('\n')
		}
		// Ensure each block ends with a blank line separator.
		if len(blk.lines) > 0 && strings.TrimSpace(blk.lines[len(blk.lines)-1]) != "" {
			sb.WriteByte('\n')
		}
	}

	return sb.String()
}

// cpuListString formats a sorted list of CPU IDs into the compact range
// notation used by /sys/devices/system/cpu/online and similar files.
// Examples:
//
//	{1, 3}       → "1,3"
//	{0, 1, 2, 3} → "0-3"
//	{0, 1, 4, 5} → "0-1,4-5"
//	{7}          → "7"
func cpuListString(cpus []uint32) string {
	if len(cpus) == 0 {
		return ""
	}
	sorted := make([]uint32, len(cpus))
	copy(sorted, cpus)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var parts []string
	start := sorted[0]
	end := sorted[0]

	for i := 1; i < len(sorted); i++ {
		if sorted[i] == end+1 {
			end = sorted[i]
		} else {
			parts = append(parts, formatRange(start, end))
			start = sorted[i]
			end = sorted[i]
		}
	}
	parts = append(parts, formatRange(start, end))
	return strings.Join(parts, ",")
}

func formatRange(start, end uint32) string {
	if start == end {
		return strconv.FormatUint(uint64(start), 10)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

// generateFilteredCPUFiles creates the following files for the given domain
// under cpuInfoDir/<domainName>/:
//
//   - cpuinfo                  — filtered /proc/cpuinfo (only allowed CPUs, real IDs)
//   - cpu_online               — e.g. "1,3\n"  (for /sys/devices/system/cpu/online)
//   - cpu_present              — same content   (for /sys/devices/system/cpu/present)
//   - cpuset.cpus.effective    — e.g. "1,3\n"  (for /sys/fs/cgroup/cpuset.cpus.effective)
//
// The cpuset.cpus.effective file is the cgroup v2 interface that CODESYS
// V3.5.21+ reads to discover available cores.  On cgroup v1 hosts this
// file does not exist natively; providing it as a bind mount ensures
// CODESYS detects only the assigned CPUs and avoids falling back to
// /proc/stat (which exposes all host CPUs).
//
// Returns a map of container destination path → host source path.
func generateFilteredCPUFiles(domainName string, cpus []uint32) (map[string]string, error) {
	if len(cpus) == 0 {
		return nil, fmt.Errorf("no CPUs specified for domain %s", domainName)
	}

	sorted := make([]uint32, len(cpus))
	copy(sorted, cpus)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	dir := filepath.Join(cpuInfoDir, domainName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	result := make(map[string]string)

	// --- /proc/cpuinfo ---
	blocks, err := parseCPUInfo(hostCPUInfo)
	if err != nil {
		return nil, fmt.Errorf("parsing host cpuinfo: %w", err)
	}
	cpuInfoContent := filterCPUInfo(blocks, sorted)
	if cpuInfoContent == "" {
		return nil, fmt.Errorf("no cpuinfo blocks matched CPUs %v for domain %s", sorted, domainName)
	}
	cpuInfoPath := filepath.Join(dir, "cpuinfo")
	if err := os.WriteFile(cpuInfoPath, []byte(cpuInfoContent), 0444); err != nil {
		return nil, fmt.Errorf("writing %s: %w", cpuInfoPath, err)
	}
	result["/proc/cpuinfo"] = cpuInfoPath

	// --- /sys/devices/system/cpu/online ---
	cpuList := cpuListString(sorted) + "\n"
	onlinePath := filepath.Join(dir, "cpu_online")
	if err := os.WriteFile(onlinePath, []byte(cpuList), 0444); err != nil {
		return nil, fmt.Errorf("writing %s: %w", onlinePath, err)
	}
	result["/sys/devices/system/cpu/online"] = onlinePath

	// --- /sys/devices/system/cpu/present ---
	presentPath := filepath.Join(dir, "cpu_present")
	if err := os.WriteFile(presentPath, []byte(cpuList), 0444); err != nil {
		return nil, fmt.Errorf("writing %s: %w", presentPath, err)
	}
	result["/sys/devices/system/cpu/present"] = presentPath

	// --- /sys/fs/cgroup/cpuset.cpus.effective ---
	// CODESYS V3.5.21+ reads this cgroup v2 file first to determine
	// available cores (logs: "OpenCpusetCpusEffective: using core(s) ...").
	// On cgroup v1 hosts the file doesn't exist, causing CODESYS to fall
	// back to /proc/stat which shows all host CPUs.  Providing this file
	// ensures correct core detection on both cgroup v1 and v2.
	cpusetEffPath := filepath.Join(dir, "cpuset.cpus.effective")
	if err := os.WriteFile(cpusetEffPath, []byte(cpuList), 0444); err != nil {
		return nil, fmt.Errorf("writing %s: %w", cpusetEffPath, err)
	}
	result["/sys/fs/cgroup/cpuset.cpus.effective"] = cpusetEffPath

	return result, nil
}

// cleanupFilteredCPUInfo removes the generated files and directory for the
// given domain.
func cleanupFilteredCPUInfo(domainName string) {
	dir := filepath.Join(cpuInfoDir, domainName)
	if err := os.RemoveAll(dir); err != nil {
		logrus.Warnf("cleanupFilteredCPUInfo(%s): %v", domainName, err)
	}
}

// ensureCgroupMountWritable finds the /sys/fs/cgroup mount in the OCI spec
// and ensures it is writable.  On cgroup v1 hosts, containerd's default
// spec creates this mount as a read-only tmpfs.  When we later bind-mount
// our synthetic cpuset.cpus.effective into /sys/fs/cgroup/, runc needs to
// create the mountpoint file inside that tmpfs — which fails if it is
// read-only ("make mountpoint: no such file or directory").
//
// Making the tmpfs writable does NOT weaken isolation: the actual cgroup
// controller mounts underneath (/sys/fs/cgroup/cpuset, /sys/fs/cgroup/cpu,
// etc.) carry their own permissions, and cgroup writes are governed by
// kernel ownership checks — not by the tmpfs mount options.
//
// On cgroup v2 hosts the file exists natively and runc does not need to
// create a mountpoint, so this function is a harmless no-op.
func ensureCgroupMountWritable(spec *specs.Spec) {
	for i, m := range spec.Mounts {
		if m.Destination != "/sys/fs/cgroup" {
			continue
		}
		for j, opt := range m.Options {
			if opt == "ro" {
				spec.Mounts[i].Options[j] = "rw"
				logrus.Infof("ensureCgroupMountWritable: changed /sys/fs/cgroup mount from ro to rw")
				return
			}
		}
		// Mount exists but has no explicit "ro" — already writable.
		return
	}
	// No /sys/fs/cgroup mount found at all.  This is unusual but can
	// happen with custom OCI specs.  Add a small writable tmpfs so that
	// runc can create the cpuset.cpus.effective mountpoint.
	logrus.Warnf("ensureCgroupMountWritable: no /sys/fs/cgroup mount found, adding writable tmpfs")
	spec.Mounts = append(spec.Mounts, specs.Mount{
		Type:        "tmpfs",
		Source:      "tmpfs",
		Destination: "/sys/fs/cgroup",
		Options:     []string{"nosuid", "noexec", "nodev", "mode=755", "size=4k"},
	})
}

// addCPUInfoBindMount generates filtered /proc/cpuinfo and sysfs CPU
// topology files for the container and appends the necessary bind mounts
// to the OCI spec.  This ensures the container sees only the CPUs in its
// cpuset, preventing applications from creating threads for CPUs they
// cannot use.
//
// Four files are bind-mounted (read-only) into the container:
//
//   - /proc/cpuinfo                          — only entries for allowed CPUs
//   - /sys/devices/system/cpu/online         — e.g. "1,3" instead of "0-15"
//   - /sys/devices/system/cpu/present        — same
//   - /sys/fs/cgroup/cpuset.cpus.effective   — e.g. "1,3" (for CODESYS cgroup v2 compat)
//
// CPU IDs are preserved (not renumbered) so that sched_setaffinity() calls
// reference the correct host CPUs.
//
// On cgroup v1 hosts, the /sys/fs/cgroup tmpfs is normally read-only,
// which prevents runc from creating a mountpoint file for our
// cpuset.cpus.effective bind mount.  We make it writable before appending
// our mounts (see ensureCgroupMountWritable).
//
// This is a no-op when the CPU list is empty (non-pinned containers).
func addCPUInfoBindMount(spec *specs.Spec, domainName string, cpus []uint32) error {
	if len(cpus) == 0 {
		return nil
	}

	mounts, err := generateFilteredCPUFiles(domainName, cpus)
	if err != nil {
		return fmt.Errorf("generating filtered CPU files for %s: %w", domainName, err)
	}

	// Ensure /sys/fs/cgroup is writable so runc can create the
	// mountpoint file for cpuset.cpus.effective on cgroup v1 hosts.
	ensureCgroupMountWritable(spec)

	logrus.Infof("addCPUInfoBindMount(%s): exposing %d CPUs %v",
		domainName, len(cpus), cpus)

	for dest, src := range mounts {
		logrus.Infof("  bind-mount %s -> %s", src, dest)
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Type:        "bind",
			Source:      src,
			Destination: dest,
			Options:     []string{"bind", "ro"},
		})
	}

	return nil
}
