// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"fmt"
	"path"
	"slices"
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
// typed values rather than each growing its own shell script. What they measure
// is read from standard Linux interfaces (/sys/devices/system/cpu, /proc, the
// cgroup cpuset) or the hypervisor's own monitor. EVE-internal state is read
// only to locate a workload -- its domain name (AppDomainName, from its
// DomainStatus) and its QEMU process (the pidfile beside its monitor socket) --
// never as evidence of where it runs, so these helpers stay independent of the
// code under test -- which is what makes them usable as evidence.

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
// core. A CPU the device does not have is an error, not a CPU on a core of its
// own: a check that two CPUs are on different cores would pass on it.
//
// This is the question a whole-core placement test actually needs answered: an
// allocation that hands a workload two CPUs is only correct for
// full_pcpus_only + threads_per_core=1 if those CPUs are on *different* cores,
// and only correct for threads_per_core=2 if the pairs are on the *same* core.
func (t HostTopology) SameCore(a, b uint32) (bool, error) {
	for _, cpu := range []uint32{a, b} {
		if _, ok := t.CPUs[cpu]; !ok {
			return false, fmt.Errorf("CPU %d is not in the device's CPU topology %v",
				cpu, t.IDs())
		}
	}
	ca, cb := t.CPUs[a], t.CPUs[b]
	return ca.Socket == cb.Socket && ca.Core == cb.Core, nil
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
	slices.Sort(ids)
	return ids
}

// HostCPUTopology reads the topology of the device's online CPUs from sysfs. A
// CPU whose core or siblings cannot be read is an error: left out, it would
// make every check that two CPUs are on different cores pass for it.
func (d *EdgeDevice) HostCPUTopology() (HostTopology, error) {
	script := fmt.Sprintf(`for dir in %s/cpu[0-9]*; do
  [ "$(cat "$dir/online" 2>/dev/null)" = 0 ] && continue
  id=${dir#%s/cpu}
  echo "$id:$(cat "$dir/topology/physical_package_id" 2>/dev/null):$(cat "$dir/topology/core_id" 2>/dev/null):$(cat "$dir/topology/thread_siblings_list" 2>/dev/null)"
done`, sysfsCPURoot, sysfsCPURoot)

	stdout, stderr, err := d.RunShellScript(script, hostQueryTimeout, 0)
	if err != nil {
		return HostTopology{}, fmt.Errorf("failed to read CPU topology: %w (stderr: %s)",
			err, stderr)
	}
	return parseHostTopology(stdout)
}

// parseHostTopology parses HostCPUTopology's lines, "id:package:core:siblings".
func parseHostTopology(stdout string) (HostTopology, error) {
	topo := HostTopology{CPUs: map[uint32]HostCPU{}}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) != 4 {
			return HostTopology{}, fmt.Errorf("unexpected CPU topology line %q", line)
		}
		id, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			return HostTopology{}, fmt.Errorf("CPU topology line %q: %w", line, err)
		}
		// A hypervisor may report no package id at all; treat that as a single
		// socket rather than discarding the CPU.
		socket, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			socket = 0
		}
		core, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return HostTopology{}, fmt.Errorf("CPU %d has no core id: %w", id, err)
		}
		siblings := ParseCPUList(fields[3])
		if !slices.Contains(siblings, uint32(id)) {
			return HostTopology{}, fmt.Errorf("CPU %d: thread siblings %q do not "+
				"include it", id, fields[3])
		}
		topo.CPUs[uint32(id)] = HostCPU{
			ID:       uint32(id),
			Socket:   uint32(socket),
			Core:     uint32(core),
			Siblings: siblings,
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

// AppCPUSet returns the logical CPUs of the cpuset an application is confined
// to, which bounds every thread of the workload including ones spawned later.
// A pinned workload's vCPU threads each have a group of one of these CPUs
// within it (AppThreadGroups).
func (d *EdgeDevice) AppCPUSet(appUUID uuid.UUID) ([]uint32, error) {
	domainName, err := d.AppDomainName(appUUID)
	if err != nil {
		return nil, err
	}
	// cgroup v1 and v2 place the domain's group differently, and EVE has used
	// both; the domain's own file, not one of its thread groups'.
	script := fmt.Sprintf(
		`for f in /sys/fs/cgroup/eve-user-apps/%[1]s/cpuset.cpus /sys/fs/cgroup/cpuset/eve-user-apps/%[1]s/cpuset.cpus; do [ -f "$f" ] && cat "$f" && break; done`,
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

// QEMUThread is one thread of a domain's QEMU process, as the host kernel sees
// it.
type QEMUThread struct {
	TID int
	// Comm is the thread's name. It may contain spaces: QEMU names its vCPU
	// threads "CPU <n>/KVM".
	Comm string
	// Group is the thread's cgroup relative to the domain's own: "" for the
	// domain's group itself, else one of the thread groups below it, such as
	// "emulator" or "vcpu0". A thread outside the domain's group keeps the
	// absolute path the kernel reports, which names none of them.
	Group string
	// AllowedCPUs is where the scheduler may run the thread
	// (Cpus_allowed_list): its affinity within its group's cpuset.
	AllowedCPUs []uint32
}

// qemuThreadsScript prints one line per thread of the QEMU process whose
// pidfile is @PIDFILE@: tid, allowed CPUs, cgroup v2 path and comm, tab
// separated, comm last so that the spaces in it cannot shift a field. A thread
// that exits during the walk is left out.
const qemuThreadsScript = `pid=$(cat '@PIDFILE@' 2>/dev/null)
if [ -z "$pid" ] || [ ! -d "/proc/$pid/task" ]; then
  echo "no running QEMU process (pidfile @PIDFILE@, pid '$pid')" >&2
  exit 1
fi
for t in /proc/"$pid"/task/[0-9]*; do
  cg=$(sed -n 's/^0:://p' "$t/cgroup" 2>/dev/null)
  allowed=$(awk '/^Cpus_allowed_list:/ {print $2}' "$t/status" 2>/dev/null)
  [ -n "$allowed" ] || continue
  printf '%s\t%s\t%s\t%s\n' "${t##*/}" "$allowed" "$cg" "$(cat "$t/comm" 2>/dev/null)"
done
exit 0
`

// AppThreadGroups lists every thread of an application's QEMU process with its
// thread group and the CPUs it may run on, read in one pass over
// /proc/<pid>/task. Which thread serves which guest vCPU only the hypervisor
// knows (QueryVCPUs).
//
// A domain's cgroup is a threaded subtree, as libvirt arranges it: the domain's
// group holds every CPU it uses, vcpu<i>/ holds vCPU i's thread and emulator/
// every other thread. A thread starts in the group of the thread that created
// it, so this also places helper threads QEMU or the kernel start later, such
// as io_uring and vhost workers.
func (d *EdgeDevice) AppThreadGroups(appUUID uuid.UUID) ([]QEMUThread, error) {
	domainName, err := d.AppDomainName(appUUID)
	if err != nil {
		return nil, err
	}
	script := strings.ReplaceAll(qemuThreadsScript, "@PIDFILE@",
		path.Join(kvmStateDir, domainName, "pid"))
	stdout, stderr, err := d.RunShellScript(script, hostQueryTimeout, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to list the QEMU threads of %s: %w (stderr: %s)",
			domainName, err, stderr)
	}
	var threads []QEMUThread
	for _, line := range strings.Split(stdout, "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 4)
		if len(fields) != 4 {
			return nil, fmt.Errorf("unexpected line %q listing the QEMU threads of %s",
				line, domainName)
		}
		tid, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, fmt.Errorf("unexpected tid in %q listing the QEMU threads of %s",
				line, domainName)
		}
		allowed := ParseCPUList(fields[1])
		if len(allowed) == 0 {
			return nil, fmt.Errorf("unparsable Cpus_allowed_list of thread %d of %s: %q",
				tid, domainName, fields[1])
		}
		if fields[2] == "" {
			return nil, fmt.Errorf("thread %d of %s is in no cgroup v2 group; thread "+
				"groups need the unified hierarchy", tid, domainName)
		}
		threads = append(threads, QEMUThread{
			TID:         tid,
			Comm:        fields[3],
			Group:       groupBelow(fields[2], domainName),
			AllowedCPUs: allowed,
		})
	}
	if len(threads) == 0 {
		return nil, fmt.Errorf("the QEMU process of %s has no threads left", domainName)
	}
	return threads, nil
}

// groupBelow returns a cgroup path relative to the domain's group, the path
// component named after the domain. The kernel reports the path relative to the
// reader's cgroup namespace, so it is found by that component rather than by a
// fixed prefix; a path without it is returned as it is.
func groupBelow(cgroupPath, domainName string) string {
	_, rest, found := strings.Cut(cgroupPath+"/", "/"+domainName+"/")
	if !found {
		return cgroupPath
	}
	return strings.TrimSuffix(rest, "/")
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
