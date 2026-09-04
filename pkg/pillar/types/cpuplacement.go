// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"

	uuid "github.com/satori/go.uuid"
)

// This file holds the per-app CPU placement *intent*: what the workload needs,
// expressed in the Kubernetes CPUManager / Topology Manager vocabulary that the
// controller API uses. It deliberately says nothing about which host CPUs are
// chosen -- that is the allocator's job (pkg/pillar/cpuallocator), and the two
// vocabularies are kept apart so the wire format never dictates the mechanism.
//
// The intent reaches domainmgr from two independent sources -- the controller
// (config.VmConfig) and the operator-editable /persist override -- which both
// resolve into the single representation below.

// CPUPolicy expresses whether a workload gets host CPUs of its own.
type CPUPolicy uint8

const (
	// CPUPolicyUnspecified means the controller sent no policy; the legacy
	// pin_cpu flag decides, preserving pre-policy behavior.
	CPUPolicyUnspecified CPUPolicy = iota
	// CPUPolicyShared is best-effort placement in the shared pool.
	CPUPolicyShared
	// CPUPolicyDedicated gives the workload host CPUs no other workload runs on.
	CPUPolicyDedicated
)

// String implements fmt.Stringer.
func (p CPUPolicy) String() string {
	switch p {
	case CPUPolicyUnspecified:
		return "unspecified"
	case CPUPolicyShared:
		return "shared"
	case CPUPolicyDedicated:
		return "dedicated"
	}
	return fmt.Sprintf("unknown(%d)", uint8(p))
}

// CPUNUMAPolicy expresses how strictly a dedicated workload's CPUs must be
// confined to a single NUMA node.
type CPUNUMAPolicy uint8

const (
	// CPUNUMAPolicyUnspecified defaults to best-effort.
	CPUNUMAPolicyUnspecified CPUNUMAPolicy = iota
	// CPUNUMAPolicyNone expresses no NUMA preference.
	CPUNUMAPolicyNone
	// CPUNUMAPolicyBestEffort prefers one node but spans if it does not fit.
	CPUNUMAPolicyBestEffort
	// CPUNUMAPolicyRestricted behaves exactly like CPUNUMAPolicySingleNode
	// today: the workload gets one NUMA node or it does not start.
	//
	// Kubernetes distinguishes the two by scope -- "restricted" minimises the
	// nodes spanned across every resource aligned for the workload, while
	// "single-numa-node" demands exactly one. That distinction needs a second
	// resource to align against, and CPU placement currently considers only
	// CPUs, so there is nothing for "minimise" to trade off and the two
	// collapse. The value is kept in the vocabulary rather than rejected
	// because the distinction becomes real once placement accounts for a
	// workload's other assigned resources -- most immediately a passthrough
	// PCI device, whose cores should come from the device's own NUMA node.
	// That needs the per-device NUMA affinity the inventory can carry but does
	// not yet populate.
	CPUNUMAPolicyRestricted
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
	case CPUNUMAPolicyRestricted:
		return "restricted"
	case CPUNUMAPolicySingleNode:
		return "single-numa-node"
	}
	return fmt.Sprintf("unknown(%d)", uint8(p))
}

// CPUIOPlacement selects where the hypervisor's non-vCPU threads run.
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

// CPUIsolationTier expresses how strongly the workload's CPUs must be shielded
// from interference.
type CPUIsolationTier uint8

const (
	// CPUIsolationTierUnspecified defaults to soft for dedicated workloads.
	CPUIsolationTierUnspecified CPUIsolationTier = iota
	// CPUIsolationTierNone is best-effort shared scheduling.
	CPUIsolationTierNone
	// CPUIsolationTierSoft is cpuset pinning plus topology-aware placement,
	// applied at runtime.
	CPUIsolationTierSoft
	// CPUIsolationTierHard additionally sheds kernel housekeeping from the
	// cores, which requires a kernel command-line change and a reboot.
	CPUIsolationTierHard
)

// String implements fmt.Stringer.
func (t CPUIsolationTier) String() string {
	switch t {
	case CPUIsolationTierUnspecified:
		return "unspecified"
	case CPUIsolationTierNone:
		return "none"
	case CPUIsolationTierSoft:
		return "soft"
	case CPUIsolationTierHard:
		return "hard"
	}
	return fmt.Sprintf("unknown(%d)", uint8(t))
}

// NeedsKernelIsolation reports whether this tier can only be satisfied on a node
// whose kernel isolates CPUs (isolcpus). Keeping other workloads off a core is
// something EVE can arrange at runtime; keeping the *kernel's* own scheduling
// off it is not, so the hard tier is a property of how the node was booted.
//
// A request for it on a node without kernel isolation must fail closed rather
// than be served as soft isolation: a workload told it is shielded from
// housekeeping, and placed on a core the scheduler still uses, is worse off than
// one that was refused, because nothing about it looks wrong.
func (t CPUIsolationTier) NeedsKernelIsolation() bool {
	return t == CPUIsolationTierHard
}

// CPUDisruptionPolicy guards a running workload against collateral node-level
// disruption.
type CPUDisruptionPolicy uint8

const (
	// CPUDisruptionPolicyUnspecified defaults to allow.
	CPUDisruptionPolicyUnspecified CPUDisruptionPolicy = iota
	// CPUDisruptionPolicyAllow lets node-level disruptive actions proceed.
	CPUDisruptionPolicyAllow
	// CPUDisruptionPolicyProtect defers a node-level disruptive action that
	// would take this workload down until the controller acknowledges it.
	CPUDisruptionPolicyProtect
)

// String implements fmt.Stringer.
func (p CPUDisruptionPolicy) String() string {
	switch p {
	case CPUDisruptionPolicyUnspecified:
		return "unspecified"
	case CPUDisruptionPolicyAllow:
		return "allow"
	case CPUDisruptionPolicyProtect:
		return "protect"
	}
	return fmt.Sprintf("unknown(%d)", uint8(p))
}

// CPUPlacementPolicy is one workload's complete CPU placement intent. The zero
// value means "no policy", i.e. legacy behavior driven by VmConfig.CPUsPinned.
type CPUPlacementPolicy struct {
	Policy        CPUPolicy
	FullPCPUsOnly bool
	// ThreadsPerCore is how many SMT siblings of each dedicated core become
	// vCPUs. 0 means unset; see EffectiveThreadsPerCore.
	ThreadsPerCore   uint32
	NUMAPolicy       CPUNUMAPolicy
	IOPlacement      CPUIOPlacement
	IsolationTier    CPUIsolationTier
	DisruptionPolicy CPUDisruptionPolicy
}

// IsDedicated reports whether the workload asked for CPUs of its own.
func (p CPUPlacementPolicy) IsDedicated() bool {
	return p.Policy == CPUPolicyDedicated
}

// IsTopologyAware reports whether the intent calls for whole-physical-core,
// SMT/NUMA-aware placement. Dedicated alone is not enough: without
// full-pcpus-only the workload is allocated at SMT-thread granularity and may
// share a physical core, which is the legacy pinning behavior.
func (p CPUPlacementPolicy) IsTopologyAware() bool {
	return p.IsDedicated() && p.FullPCPUsOnly
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

// CPUPlacementQuality is how good a workload's actual CPU placement is,
// reported so an operator or controller can decide whether a disruptive repack
// is worth it. It is status, not an error: a sub-optimally placed workload runs
// normally, and nothing about it needs fixing unless someone judges the
// improvement worth a restart.
type CPUPlacementQuality uint8

const (
	// CPUPlacementQualityUnspecified means placement quality was not evaluated,
	// which is the case for any workload that is not whole-core pinned.
	CPUPlacementQualityUnspecified CPUPlacementQuality = iota
	// CPUPlacementQualityOptimal means no better placement exists for this
	// workload -- including the common case where the workload got different
	// CPUs than first proposed but ones that are just as good.
	CPUPlacementQualityOptimal
	// CPUPlacementQualityNeedsRepack means a better placement exists but only
	// by moving workloads that are already running. Moving a running workload
	// means restarting it, so this is reported and left to the operator rather
	// than acted on.
	CPUPlacementQualityNeedsRepack
)

// String implements fmt.Stringer.
func (q CPUPlacementQuality) String() string {
	switch q {
	case CPUPlacementQualityUnspecified:
		return "unspecified"
	case CPUPlacementQualityOptimal:
		return "optimal"
	case CPUPlacementQualityNeedsRepack:
		return "needs-repack"
	}
	return fmt.Sprintf("unknown(%d)", uint8(q))
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
	// CPUPoolKindIsolated is the set the running kernel isolates (isolcpus).
	// It overlaps the other two rather than partitioning with them.
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
}

// AppCPUDemand is one application's CPU-relevant configuration, as the
// controller expressed it. It carries only what a placement decision needs --
// not the whole VmConfig -- so the demand set stays independent of everything
// else an app config describes.
//
// The intent here is the controller's alone. The operator-editable /persist
// override is read by domainmgr, which zedmanager knows nothing about, so an
// entry saying "not pinned" does not mean the workload will not be pinned.
type AppCPUDemand struct {
	UUID uuid.UUID
	// DisplayName is for logs and diagnostics only; nothing keys off it.
	DisplayName string
	VCpus       int
	// CPUsPinned is the legacy pin flag, which still decides when the
	// controller sent no CPUPlacement policy.
	CPUsPinned   bool
	CPUPlacement CPUPlacementPolicy
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
//
// An empty set is published explicitly, so "no pinned apps are configured" is
// distinguishable from "zedmanager has not spoken yet".
type CPUDemandSet struct {
	// Apps is sorted by UUID, so an unchanged set is byte-identical between
	// publications and does not look like a change.
	Apps []AppCPUDemand
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
