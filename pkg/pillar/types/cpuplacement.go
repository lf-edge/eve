// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"slices"
	"time"

	uuid "github.com/satori/go.uuid"
)

// This file holds the per-app CPU placement *intent*: what the workload needs,
// expressed in the Kubernetes CPUManager / Topology Manager vocabulary that the
// controller API uses. It deliberately says nothing about which host CPUs are
// chosen -- that is the allocator's job (pkg/pillar/cpuallocator), and the two
// vocabularies are kept apart so the wire format never dictates the mechanism.

// CPUPolicy is the pool a workload's CPUs come from. Whether EVE pins each vCPU
// to one of them is a separate choice, CPUPlacementPolicy.Pinned.
type CPUPolicy uint8

const (
	// CPUPolicyUnspecified is what an app config with no policy parses to before
	// zedagent resolves the legacy pin_cpu rule; it behaves as housekeeping.
	CPUPolicyUnspecified CPUPolicy = iota
	// CPUPolicyHousekeeping runs the workload in the housekeeping pool, shared
	// with EVE and every other workload in that pool.
	CPUPolicyHousekeeping
	// CPUPolicyDedicated gives the workload host CPUs no other workload runs on.
	CPUPolicyDedicated
	// CPUPolicyIsolated gives the workload host CPUs of its own from the set the
	// running kernel isolates (isolcpus).
	CPUPolicyIsolated
)

// String implements fmt.Stringer.
func (p CPUPolicy) String() string {
	switch p {
	case CPUPolicyUnspecified:
		return "unspecified"
	case CPUPolicyHousekeeping:
		return "housekeeping"
	case CPUPolicyDedicated:
		return "dedicated"
	case CPUPolicyIsolated:
		return "isolated"
	}
	return fmt.Sprintf("unknown(%d)", uint8(p))
}

// CPUNUMAPolicy expresses how strictly a workload's CPUs must be confined to a
// single NUMA node.
type CPUNUMAPolicy uint8

const (
	// CPUNUMAPolicyUnspecified defaults to best-effort.
	CPUNUMAPolicyUnspecified CPUNUMAPolicy = iota
	// CPUNUMAPolicyNone expresses no NUMA preference.
	CPUNUMAPolicyNone
	// CPUNUMAPolicyBestEffort prefers one node but spans if it does not fit.
	CPUNUMAPolicyBestEffort
	// CPUNUMAPolicySingleNode requires one node; the workload fails to start
	// rather than span.
	CPUNUMAPolicySingleNode
)

// String implements fmt.Stringer.
func (p CPUNUMAPolicy) String() string {
	switch p {
	case CPUNUMAPolicyUnspecified:
		return "unspecified"
	case CPUNUMAPolicyNone:
		return "none"
	case CPUNUMAPolicyBestEffort:
		return "best-effort"
	case CPUNUMAPolicySingleNode:
		return "single-numa-node"
	}
	return fmt.Sprintf("unknown(%d)", uint8(p))
}

// CPUIOPlacement selects where a VM's non-vCPU QEMU threads run.
type CPUIOPlacement uint8

const (
	// CPUIOPlacementUnspecified defaults to dedicated.
	CPUIOPlacementUnspecified CPUIOPlacement = iota
	// CPUIOPlacementDedicated keeps emulator/IO threads in the workload's own
	// CPU set.
	CPUIOPlacementDedicated
	// CPUIOPlacementHousekeeping pins emulator/IO threads off the hot cores so
	// device emulation cannot steal cycles from busy vCPUs.
	CPUIOPlacementHousekeeping
)

// String implements fmt.Stringer.
func (p CPUIOPlacement) String() string {
	switch p {
	case CPUIOPlacementUnspecified:
		return "unspecified"
	case CPUIOPlacementDedicated:
		return "dedicated"
	case CPUIOPlacementHousekeeping:
		return "housekeeping"
	}
	return fmt.Sprintf("unknown(%d)", uint8(p))
}

// CPUPlacementPolicy is one workload's complete CPU placement intent: the pool
// its CPUs come from (Policy), whether EVE pins each vCPU (Pinned), and the
// fields refining a dedicated or isolated request. Each field means the same
// whatever the others say; a combination EVE does not serve is refused, never
// reinterpreted. The zero value is a shared workload.
type CPUPlacementPolicy struct {
	Policy CPUPolicy
	// Pinned is whether EVE pins each vCPU of a VM to its own CPU of the pool.
	Pinned        bool
	FullPCPUsOnly bool
	// ThreadsPerCore is how many SMT siblings of each core the workload uses.
	// 0 means unset; see EffectiveThreadsPerCore.
	ThreadsPerCore uint32
	NUMAPolicy     CPUNUMAPolicy
	IOPlacement    CPUIOPlacement
}

// ResolveLegacy applies the one rule in which a field's meaning depends on
// another. A controller that predates cpu_policy sends only pin_cpu, and for it
// pin_cpu=true means CPUs of the workload's own: a VM's vCPUs pinned, a
// container (which has no vCPUs) on its own CPUs.
//
// It applies only to such a request. A policy left unspecified next to any
// refining field is not legacy, just incomplete: it is taken as shared with its
// fields as sent, so they are refused rather than given a meaning they were
// never sent with. An explicit policy is returned unchanged.
func (p CPUPlacementPolicy) ResolveLegacy(pinCPU, container bool) CPUPlacementPolicy {
	if p.Policy != CPUPolicyUnspecified {
		return p
	}
	onlyPinCPU := !p.FullPCPUsOnly && p.ThreadsPerCore == 0 &&
		p.NUMAPolicy == CPUNUMAPolicyUnspecified &&
		p.IOPlacement == CPUIOPlacementUnspecified
	if pinCPU && onlyPinCPU {
		p.Policy = CPUPolicyDedicated
		p.Pinned = !container
		return p
	}
	p.Policy = CPUPolicyHousekeeping
	p.Pinned = pinCPU
	return p
}

// HasOwnCPUs reports whether the workload gets CPUs no other workload runs on,
// from the dedicated or the isolated pool.
func (p CPUPlacementPolicy) HasOwnCPUs() bool {
	return p.Policy == CPUPolicyDedicated || p.Policy == CPUPolicyIsolated
}

// NeedsKernelIsolation reports whether the workload's CPUs must come from the
// set the running kernel isolates. A node can only offer that if it was booted
// with isolcpus; EVE does not change the kernel command line.
func (p CPUPlacementPolicy) NeedsKernelIsolation() bool {
	return p.Policy == CPUPolicyIsolated
}

// IsTopologyAware reports whether the intent calls for whole-physical-core,
// SMT/NUMA-aware placement. CPUs of its own are not enough: without
// full-pcpus-only the workload is allocated one logical CPU at a time and may
// share a physical core with another workload.
func (p CPUPlacementPolicy) IsTopologyAware() bool {
	return p.HasOwnCPUs() && p.FullPCPUsOnly
}

// EffectiveThreadsPerCore resolves the unset case to 2, i.e. both SMT siblings
// become vCPUs. The API documents that default as applying on SMT hardware; EVE
// applies it unconditionally, so on a node without SMT a request that leaves
// threads_per_core unset cannot be satisfied and must set threads_per_core=1.
func (p CPUPlacementPolicy) EffectiveThreadsPerCore() uint32 {
	if p.ThreadsPerCore == 0 {
		return 2
	}
	return p.ThreadsPerCore
}

// CPUPlacementStatus is where a workload stands with its CPU request, which
// the controller acts on: zedagent reports a refusal as
// CPU_PLACEMENT_STATUS_FAILED with the ZInfoApp.cpu_placement_error of the
// same name, and any other value as the cpu_placement_status of that name.
type CPUPlacementStatus uint8

const (
	// CPUPlacementStatusUnspecified: no CPU request decided, as for a workload
	// of the housekeeping pool or one that is not active.
	CPUPlacementStatusUnspecified CPUPlacementStatus = iota
	// CPUPlacementStatusPlaced: running on the CPUs the plan gives it, or on
	// CPUs as good.
	CPUPlacementStatusPlaced
	// CPUPlacementStatusWaiting: not started yet, as workloads on their way off
	// its planned CPUs still hold them (CPUWait).
	CPUPlacementStatusWaiting
	// CPUPlacementStatusRepackAdvised: running, and part of a repack. Moving a
	// running workload means restarting it, so it is reported and left to the
	// controller rather than acted on: a better placement exists only by
	// moving workloads that run, or it holds CPUs the plan gives to another
	// workload (RepackFor).
	CPUPlacementStatusRepackAdvised
	// CPUPlacementStatusNeedsRepack: refused; the free CPUs cannot hold it, but
	// the plan places it once the workloads in a repack restart together.
	CPUPlacementStatusNeedsRepack
	// CPUPlacementStatusInsufficient: refused; the plan cannot place it, or
	// only by leaving out a running workload, so no repack makes room; or it
	// asked for io_placement=housekeeping on a node with no CPU to serve it.
	CPUPlacementStatusInsufficient
	// CPUPlacementStatusPolicyInvalid: refused; the placement policy carries a
	// field the request cannot carry, a value out of range, or a combination
	// this EVE does not implement.
	CPUPlacementStatusPolicyInvalid
	// CPUPlacementStatusOddVCPU: refused; whole-core SMT with an odd vCPU
	// count, which no arrangement of two-thread cores satisfies.
	CPUPlacementStatusOddVCPU
	// CPUPlacementStatusTopologyUnsupported: refused; the node cannot present
	// the request however many CPUs are free: its CPU topology is unknown, it
	// has no two-thread core for a both-threads request, or its hypervisor
	// cannot bind vCPUs to named host CPUs.
	CPUPlacementStatusTopologyUnsupported
	// CPUPlacementStatusIsolationUnavailable: refused; the isolated CPU policy
	// on a node whose kernel isolates no CPU.
	CPUPlacementStatusIsolationUnavailable
)

// String implements fmt.Stringer.
func (s CPUPlacementStatus) String() string {
	switch s {
	case CPUPlacementStatusUnspecified:
		return "unspecified"
	case CPUPlacementStatusPlaced:
		return "placed"
	case CPUPlacementStatusWaiting:
		return "waiting"
	case CPUPlacementStatusRepackAdvised:
		return "repack-advised"
	case CPUPlacementStatusNeedsRepack:
		return "needs-repack"
	case CPUPlacementStatusInsufficient:
		return "insufficient"
	case CPUPlacementStatusPolicyInvalid:
		return "policy-invalid"
	case CPUPlacementStatusOddVCPU:
		return "odd-vcpu"
	case CPUPlacementStatusTopologyUnsupported:
		return "topology-unsupported"
	case CPUPlacementStatusIsolationUnavailable:
		return "isolation-unavailable"
	}
	return fmt.Sprintf("unknown(%d)", uint8(s))
}

// CPUWait is a workload waiting for the CPUs the plan set aside for it, which
// workloads on their way off them still hold: stopping, or restarting together
// with it for a repack. It is not refused: it takes the CPUs as soon as they
// are released.
type CPUWait struct {
	// Holders names the workloads holding the CPUs.
	Holders []string
	// AppSet: the workload waits for zedmanager's complete CPUDemandSet, before
	// any CPUs are planned for it.
	AppSet bool
	// Since is when the wait began.
	Since time.Time
}

// Waiting reports whether the workload waits.
func (w CPUWait) Waiting() bool {
	return len(w.Holders) > 0 || w.AppSet
}

// ForHolders reports whether the workload waits for other workloads to release
// its planned CPUs: the wait the controller is told about. The wait for the
// application set is brief and comes before any placement, so it is not.
func (w CPUWait) ForHolders() bool {
	return len(w.Holders) > 0
}

// Equal reports whether two waits are for the same thing since the same time.
func (w CPUWait) Equal(o CPUWait) bool {
	return slices.Equal(w.Holders, o.Holders) && w.AppSet == o.AppSet &&
		w.Since.Equal(o.Since)
}

// CPUAssignment is the host CPUs a workload of the dedicated or isolated pool
// holds, as domainmgr placed it, for the app's info (ZInfoApp.assigned_cpus):
// the CPU counterpart of the adapters reported as assigned to it. Empty for a
// workload of the housekeeping pool and for one that holds no CPUs.
type CPUAssignment struct {
	// CPUs the workload runs on, in vCPU order: vCPU i runs only on CPUs[i].
	CPUs []uint32
	// ParkedCPUs are held for it and stay idle; see DomainStatus.ParkedCPUs.
	ParkedCPUs []uint32
	// IOCPUs is where a VM's non-vCPU threads run under
	// io_placement=housekeeping: shared CPUs, not held. See
	// DomainStatus.EmulatorCPUs.
	IOCPUs []uint32
}

// Equal reports whether two assignments name the same CPUs in the same order.
func (a CPUAssignment) Equal(b CPUAssignment) bool {
	return slices.Equal(a.CPUs, b.CPUs) && slices.Equal(a.ParkedCPUs, b.ParkedCPUs) &&
		slices.Equal(a.IOCPUs, b.IOCPUs)
}

// CPUAssignment is the host CPUs this workload holds, for reporting: none for a
// workload of the housekeeping pool, or one refused or released.
func (status DomainStatus) CPUAssignment() CPUAssignment {
	if len(status.OrderedCPUs) == 0 {
		return CPUAssignment{}
	}
	return CPUAssignment{
		CPUs:       slices.Clone(status.OrderedCPUs),
		ParkedCPUs: slices.Clone(status.ParkedCPUs),
		IOCPUs:     slices.Clone(status.EmulatorCPUs),
	}
}

// CPUPoolKind names one partition of the node's logical CPUs in the node-level
// CPU pool report. Mirrors the eve-api info.CPUPoolKind enum.
type CPUPoolKind uint8

const (
	// CPUPoolKindUnspecified is the unset zero value.
	CPUPoolKindUnspecified CPUPoolKind = iota
	// CPUPoolKindHousekeeping is EVE's own CPUs plus every CPU no workload
	// holds exclusively, which is where non-dedicated workloads run.
	CPUPoolKindHousekeeping
	// CPUPoolKindDedicated is the CPUs handed out exclusively to workloads with
	// a dedicated CPU policy, including siblings parked idle by a
	// one-thread-per-core request.
	CPUPoolKindDedicated
	// CPUPoolKindIsolated is the set the running kernel isolates (isolcpus),
	// free or held by isolated workloads.
	CPUPoolKindIsolated
)

// String implements fmt.Stringer.
func (k CPUPoolKind) String() string {
	switch k {
	case CPUPoolKindUnspecified:
		return "unspecified"
	case CPUPoolKindHousekeeping:
		return "housekeeping"
	case CPUPoolKindDedicated:
		return "dedicated"
	case CPUPoolKindIsolated:
		return "isolated"
	}
	return fmt.Sprintf("unknown(%d)", uint8(k))
}

// CPUPoolUtilization is one CPU pool's extent and how much of it is still
// available. The whole-core counts are reported alongside the thread counts
// because they are not derivable from each other: a free thread on a
// partially-taken core cannot satisfy a request for whole physical cores, so a
// single "free" number answers one of the two request shapes wrongly.
type CPUPoolUtilization struct {
	Kind CPUPoolKind
	// CPUs is every logical CPU in the pool, ascending.
	CPUs []uint32
	// FreeCPUs is the subset of CPUs that could still be given to a workload
	// asking for dedicated placement.
	FreeCPUs         []uint32
	TotalThreads     uint32
	AllocatedThreads uint32
	FreeThreads      uint32
	// TotalCores counts physical cores all of whose SMT siblings are in CPUs.
	TotalCores uint32
	// FreeWholeCores counts physical cores all of whose SMT siblings are free --
	// the number that bounds how many more whole-core workloads fit.
	FreeWholeCores uint32
	// Warnings are the mistakes in how the node defines the pool: in the
	// operator's isolcpus, on the isolated pool only.
	Warnings []CPUPoolWarning
}

// CPUPoolIssue is a mistake in how the node defines a CPU pool; the values
// match info.CPUPoolIssue in eve-api.
type CPUPoolIssue uint8

const (
	// CPUPoolIssueUnspecified is no issue.
	CPUPoolIssueUnspecified CPUPoolIssue = iota
	// CPUPoolIssueReservedCPUs: isolcpus covers CPUs reserved for EVE's own
	// services.
	CPUPoolIssueReservedCPUs
	// CPUPoolIssuePartialCore: isolcpus isolates some but not all threads of
	// a core, which then serves no workload.
	CPUPoolIssuePartialCore
)

// CPUPoolWarning is one CPUPoolIssue with the warning an operator reads.
type CPUPoolWarning struct {
	Issue CPUPoolIssue
	ErrorDescription
}

// AppCPUDemand is one application's CPU-relevant configuration, as the
// controller expressed it. It carries only what a placement decision needs --
// not the whole VmConfig -- so the demand set stays independent of everything
// else an app config describes.
type AppCPUDemand struct {
	UUID uuid.UUID
	// DisplayName is for logs and diagnostics only; nothing keys off it.
	DisplayName  string
	VCpus        int
	CPUPlacement CPUPlacementPolicy
	// VirtualizationMode tells a container (NOHYPER), which has no vCPUs to
	// pin, from a VM.
	VirtualizationMode VmMode
}

// CPUDemandSet is every application intended to run on this node, with its CPU
// intent -- the demand domainmgr plans CPU placement against.
//
// It exists because a DomainConfig is not published until an app's volumes and
// network are ready, so domainmgr's view of "the configured apps" is really
// "the apps that finished downloading first". Planning against that makes the
// layout depend on image download order: whichever app activates first is
// planned as if it were alone and takes CPUs the full plan would have given to
// another. zedmanager knows the whole intended set from the moment the config
// arrives, so it publishes it here.
//
// It is deliberately one aggregate object rather than one item per app: a
// per-app topic would only move the same "what has arrived so far" problem onto
// a faster topic. Receiving one object that IS the whole set makes
// set-completeness atomic -- the subscriber replaces its view wholesale.
type CPUDemandSet struct {
	// Apps is sorted by UUID, so an unchanged set is byte-identical between
	// publications and does not look like a change.
	Apps []AppCPUDemand
	// Complete: zedmanager has been given the whole configuration (its app
	// config subscription has restarted), so Apps is every app intended to run.
	// Until then Apps is the part processed so far, and a workload placed
	// against it could take CPUs the full plan gives to another.
	Complete bool
}

// Key returns the pubsub key. There is one demand set per node.
func (s CPUDemandSet) Key() string {
	return "global"
}

// CPUPoolStatus is the node's CPU pool report: how the logical CPUs are
// partitioned and how much of each partition is left.
//
// domainmgr owns the allocator, so it is the only agent that can compute this;
// zedagent subscribes and projects it onto ZInfoDevice.cpu_pools so a controller
// can answer "will this workload fit?" before a deploy and explain a placement
// failure after one. Republished whenever the dedicated set changes.
type CPUPoolStatus struct {
	Pools []CPUPoolUtilization
}

// Key returns the pubsub key. There is one report per node.
func (s CPUPoolStatus) Key() string {
	return "global"
}
