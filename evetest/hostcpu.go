// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"

	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// This file exposes the device's CPU reality: how its CPUs are laid out, which
// of them the kernel has been told to treat specially, and where a workload's
// threads have actually ended up.
//
// It exists so that tests about CPU placement and isolation assert against
// typed values rather than each growing its own shell script. Everything here
// reads standard Linux interfaces (/sys/devices/system/cpu, /proc) or the
// hypervisor's own monitor, never EVE-internal state, so these helpers stay
// valid across EVE versions and remain independent of the code under test --
// which is what makes them usable as evidence.

const sysfsCPURoot = "/sys/devices/system/cpu"

// hostQueryTimeout bounds each of the small shell reads below.
const hostQueryTimeout = 30 * time.Second

// HostCPU is one logical CPU of the device and its position in the CPU
// topology. The identifiers are opaque grouping keys: equal values mean "same
// domain", and nothing more should be read into them -- they are not guaranteed
// contiguous or zero-based.
type HostCPU struct {
	// ID is the logical CPU number the kernel schedules on and that CPU
	// affinities are expressed in.
	ID uint32
	// Socket is the physical package.
	Socket uint32
	// Core identifies the physical core within the socket. Logical CPUs that
	// share a (Socket, Core) pair are SMT siblings of one physical core.
	Core uint32
	// Siblings are all logical CPUs on this CPU's physical core, including
	// itself. A single entry means SMT is off or unavailable for this core.
	Siblings []uint32
}

// HostTopology is the device's CPU topology, indexed by logical CPU.
type HostTopology struct {
	CPUs map[uint32]HostCPU
}

// SameCore reports whether two logical CPUs are SMT siblings on one physical
// core. Unknown CPUs are reported as not sharing a core.
//
// This is the question a whole-core placement test actually needs answered: an
// allocation that hands a workload two CPUs is only correct for
// full_pcpus_only + threads_per_core=1 if those CPUs are on *different* cores,
// and only correct for threads_per_core=2 if the pairs are on the *same* core.
func (t HostTopology) SameCore(a, b uint32) bool {
	ca, okA := t.CPUs[a]
	cb, okB := t.CPUs[b]
	if !okA || !okB {
		return false
	}
	return ca.Socket == cb.Socket && ca.Core == cb.Core
}

// SiblingsOf returns the logical CPUs sharing a physical core with the given
// CPU, including itself, or nil if the CPU is unknown.
func (t HostTopology) SiblingsOf(cpu uint32) []uint32 {
	return t.CPUs[cpu].Siblings
}

// IDs returns every known logical CPU id, ascending.
func (t HostTopology) IDs() []uint32 {
	ids := make([]uint32, 0, len(t.CPUs))
	for id := range t.CPUs {
		ids = append(ids, id)
	}
	sortCPUs(ids)
	return ids
}

// HostCPUTopology reads the device's CPU topology from sysfs.
func (d *EdgeDevice) HostCPUTopology() (HostTopology, error) {
	script := fmt.Sprintf(`for dir in %s/cpu[0-9]*; do
  id=${dir#%s/cpu}
  echo "$id $(cat "$dir/topology/physical_package_id" 2>/dev/null) $(cat "$dir/topology/core_id" 2>/dev/null) $(cat "$dir/topology/thread_siblings_list" 2>/dev/null)"
done`, sysfsCPURoot, sysfsCPURoot)

	stdout, stderr, err := d.RunShellScript(script, hostQueryTimeout, 0)
	if err != nil {
		return HostTopology{}, fmt.Errorf("failed to read CPU topology: %w (stderr: %s)",
			err, stderr)
	}

	topo := HostTopology{CPUs: map[uint32]HostCPU{}}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		id, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			continue
		}
		// A hypervisor may report no package id at all; treat that as a single
		// socket rather than discarding the CPU.
		socket, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			socket = 0
		}
		core, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		topo.CPUs[uint32(id)] = HostCPU{
			ID:       uint32(id),
			Socket:   uint32(socket),
			Core:     uint32(core),
			Siblings: ParseCPUList(fields[3]),
		}
	}
	if len(topo.CPUs) == 0 {
		return topo, fmt.Errorf("no CPU topology found under %s", sysfsCPURoot)
	}
	return topo, nil
}

// OnlineCPUs returns the logical CPUs the kernel currently has online.
func (d *EdgeDevice) OnlineCPUs() ([]uint32, error) {
	return d.readCPUListFile(sysfsCPURoot + "/online")
}

// IsolatedCPUs returns the logical CPUs the running kernel is isolating from the
// scheduler, i.e. the effective result of the isolcpus boot parameter. It is
// empty on a node with no kernel-level isolation.
//
// This reads what the kernel is actually doing rather than parsing the command
// line, so it reflects reality even when the parameter was malformed, capped, or
// supplied by some other means.
func (d *EdgeDevice) IsolatedCPUs() ([]uint32, error) {
	return d.readCPUListFile(sysfsCPURoot + "/isolated")
}

// NohzFullCPUs returns the logical CPUs running without the scheduler tick, i.e.
// the effective result of the nohz_full boot parameter.
func (d *EdgeDevice) NohzFullCPUs() ([]uint32, error) {
	return d.readCPUListFile(sysfsCPURoot + "/nohz_full")
}

// KernelCmdline returns the device's kernel command line.
func (d *EdgeDevice) KernelCmdline() (string, error) {
	stdout, stderr, err := d.RunShellScript("cat /proc/cmdline", hostQueryTimeout, 0)
	if err != nil {
		return "", fmt.Errorf("failed to read kernel command line: %w (stderr: %s)",
			err, stderr)
	}
	return strings.TrimSpace(stdout), nil
}

// KernelCmdlineParam returns the value of a kernel command-line parameter and
// whether it is present. A parameter given without a value (a bare flag) is
// reported as present with an empty value.
func (d *EdgeDevice) KernelCmdlineParam(name string) (string, bool, error) {
	cmdline, err := d.KernelCmdline()
	if err != nil {
		return "", false, err
	}
	for _, field := range strings.Fields(cmdline) {
		key, value, hasValue := strings.Cut(field, "=")
		if key != name {
			continue
		}
		if !hasValue {
			return "", true, nil
		}
		return value, true, nil
	}
	return "", false, nil
}

// ThreadAffinity returns the logical CPUs a single host thread is allowed to run
// on, from /proc/<tid>/status. An empty result means the thread is gone.
func (d *EdgeDevice) ThreadAffinity(tid int) ([]uint32, error) {
	script := fmt.Sprintf(
		`awk '/Cpus_allowed_list/{print $2}' /proc/%d/status 2>/dev/null`, tid)
	stdout, stderr, err := d.RunShellScript(script, hostQueryTimeout, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read affinity of thread %d: %w (stderr: %s)",
			tid, err, stderr)
	}
	return ParseCPUList(stdout), nil
}

// AppDomainName returns the hypervisor domain name of a deployed application,
// which identifies it to the hypervisor and locates its monitor socket.
func (d *EdgeDevice) AppDomainName(appUUID uuid.UUID) (string, error) {
	var status pillartypes.DomainStatus
	if err := ReadPublication(d, "domainmgr", false, appUUID.String(), &status); err != nil {
		return "", fmt.Errorf("failed to read DomainStatus of %s: %w", appUUID, err)
	}
	if status.DomainName == "" {
		return "", fmt.Errorf("DomainStatus of %s carries no domain name yet", appUUID)
	}
	return status.DomainName, nil
}

// AppVCPUAffinities returns, per guest vCPU index, the host CPUs that vCPU is
// allowed to run on.
//
// The guest-vCPU-to-host-thread mapping comes from the hypervisor over QMP
// because it cannot be recovered from the outside: QEMU does not name its vCPU
// threads unless started with debug-threads=on, and a domain's thread group also
// contains vhost_task helper threads that are indistinguishable from vCPU
// threads by name or by flags. Scanning /proc can therefore show that some
// thread is pinned, but not which vCPU it serves.
func (d *EdgeDevice) AppVCPUAffinities(appUUID uuid.UUID) (map[int][]uint32, error) {
	domainName, err := d.AppDomainName(appUUID)
	if err != nil {
		return nil, err
	}
	vcpus, err := d.QueryVCPUs(domainName)
	if err != nil {
		return nil, err
	}
	affinities := make(map[int][]uint32, len(vcpus))
	for _, vcpu := range vcpus {
		allowed, err := d.ThreadAffinity(vcpu.ThreadID)
		if err != nil {
			return nil, err
		}
		affinities[vcpu.CPUIndex] = allowed
	}
	return affinities, nil
}

// AppCPUSet returns the logical CPUs of the cpuset an application is confined
// to, which bounds every thread of the workload including ones spawned later.
// A pinned workload's vCPU threads are additionally pinned individually within
// this set.
func (d *EdgeDevice) AppCPUSet(appUUID uuid.UUID) ([]uint32, error) {
	domainName, err := d.AppDomainName(appUUID)
	if err != nil {
		return nil, err
	}
	// cgroup v1 and v2 place the file differently, and EVE has used both, so
	// search rather than hard-code a layout.
	script := fmt.Sprintf(
		`find /sys/fs/cgroup -path '*%s*' -name 'cpuset.cpus' 2>/dev/null | while read -r f; do cat "$f"; break; done`,
		domainName)
	stdout, stderr, err := d.RunShellScript(script, hostQueryTimeout, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read cpuset of %s: %w (stderr: %s)",
			domainName, err, stderr)
	}
	cpus := ParseCPUList(stdout)
	if len(cpus) == 0 {
		return nil, fmt.Errorf("no cpuset found for domain %s", domainName)
	}
	return cpus, nil
}

// readCPUListFile reads a sysfs file holding a kernel CPU list. A missing file
// yields an empty list rather than an error: the kernel omits some of these
// entirely when the corresponding feature is not in use.
func (d *EdgeDevice) readCPUListFile(path string) ([]uint32, error) {
	script := fmt.Sprintf("cat %s 2>/dev/null || true", path)
	stdout, stderr, err := d.RunShellScript(script, hostQueryTimeout, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w (stderr: %s)", path, err, stderr)
	}
	return ParseCPUList(stdout), nil
}

// ParseCPUList expands a kernel CPU list such as "2", "0-3" or "0-2,5,7-8" into
// individual logical CPU ids. This is the format the kernel uses throughout
// sysfs and /proc for CPU sets.
func ParseCPUList(list string) []uint32 {
	var cpus []uint32
	for _, part := range strings.Split(strings.TrimSpace(list), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		loField, hiField, isRange := strings.Cut(part, "-")
		lo, err := strconv.ParseUint(strings.TrimSpace(loField), 10, 32)
		if err != nil {
			continue
		}
		hi := lo
		if isRange {
			parsed, err := strconv.ParseUint(strings.TrimSpace(hiField), 10, 32)
			if err != nil {
				continue
			}
			hi = parsed
		}
		for cpu := lo; cpu <= hi; cpu++ {
			cpus = append(cpus, uint32(cpu))
		}
	}
	return cpus
}

func sortCPUs(cpus []uint32) {
	for i := 0; i < len(cpus); i++ {
		for j := i + 1; j < len(cpus); j++ {
			if cpus[j] < cpus[i] {
				cpus[i], cpus[j] = cpus[j], cpus[i]
			}
		}
	}
}
