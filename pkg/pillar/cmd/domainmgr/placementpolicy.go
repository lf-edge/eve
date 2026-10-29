// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"fmt"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// placementError carries a machine-parseable code alongside the message, so the
// failure reaches the controller as a structured ErrorInfo rather than prose.
type placementError struct {
	// Status is the refusal, as the controller sees it.
	Status types.CPUPlacementStatus
	Msg    string
	// Retry is what would change the outcome, for the failures that can say
	// something more specific than their status's generic condition (which
	// workloads are in the way, how many cores short the node is). Empty means
	// the generic condition is used; it never reaches the controller empty,
	// see retryConditionFor.
	Retry string
}

func (e *placementError) Error() string { return e.Msg }

// retryCondition is what would change the outcome: the refusal's own, or its
// status's generic condition.
func (e *placementError) retryCondition() string {
	if e.Retry != "" {
		return e.Retry
	}
	return retryConditionFor(e.Status)
}

func placementErrorf(status types.CPUPlacementStatus, format string,
	args ...interface{}) *placementError {
	return &placementError{Status: status, Msg: fmt.Sprintf(format, args...)}
}

// retryWhen attaches the specific condition this failure clears under, for the
// cases where the generic per-status text can be improved on with real numbers or
// real workload names.
func (e *placementError) retryWhen(format string, args ...interface{}) *placementError {
	e.Retry = fmt.Sprintf(format, args...)
	return e
}

// noAutoRetry is appended to every placement retry condition.
//
// A CPU-placement failure is not re-attempted by the device: the workload holds
// no CPUs, sets neither BootFailed nor ConfigFailed, and stays failed until the
// controller or the operator acts -- exactly how EVE already treats a workload
// that cannot get an assigned PCI device. Saying so is the point of the field
// here: a controller told only "when cores free" would sit and wait for a
// recovery that never comes on its own.
const noAutoRetry = " The device does not re-attempt placement on its own."

// retryConditionFor is the condition a placement failure clears under when the
// failure itself has nothing more specific to add. Every refusal produced on
// this path has an entry: an ErrorInfo that says "insufficient" with an empty
// retry_condition tells a controller that something is wrong and nothing about
// what would make it right, which is the one outcome worse than a blunt message.
func retryConditionFor(status types.CPUPlacementStatus) string {
	switch status {
	case types.CPUPlacementStatusInsufficient:
		return "Stop another pinned workload to free whole physical cores, or " +
			"deploy this one on a node with more cores, then start it again." +
			noAutoRetry
	case types.CPUPlacementStatusNeedsRepack:
		return "Restart the pinned workloads together so they repack, then start " +
			"this one again." + noAutoRetry
	case types.CPUPlacementStatusOddVCPU:
		return "Change the workload's vCPU count to an even number, or set " +
			"threads_per_core=1, and deploy it again. No change on the node makes " +
			"an odd count placeable on two-thread cores." + noAutoRetry
	case types.CPUPlacementStatusIsolationUnavailable:
		return "Set cpu_policy=dedicated for the workload, or deploy it on a node " +
			"booted with CPU isolation (isolcpus). EVE does not change a node's " +
			"kernel command line." + noAutoRetry
	case types.CPUPlacementStatusTopologyUnsupported:
		return "Deploy the workload on a node whose CPU topology EVE can read and " +
			"whose hypervisor can pin individual vCPUs, or turn off whole-core " +
			"placement (full_pcpus_only) for it. No amount of free CPUs makes this " +
			"node able to honour the request." + noAutoRetry
	case types.CPUPlacementStatusPolicyInvalid:
		return "Change the workload's CPU placement policy to one this node " +
			"implements and deploy it again. No change on the node makes the " +
			"request as written satisfiable." + noAutoRetry
	}
	// A refusal with no entry is still better served by a true statement than
	// by an empty field: every failure on this path is fail-closed, so it needs
	// either the workload's configuration or the node to change.
	return "Change the workload's CPU placement configuration, or deploy it on a " +
		"node that can satisfy it, then start it again." + noAutoRetry
}

// resolvedPlacement is a workload's CPU placement intent translated into the
// allocator's vocabulary.
type resolvedPlacement struct {
	// Mode is ModeShared for a workload placed one logical CPU at a time, or
	// not given CPUs of its own at all; the other modes take whole cores.
	Mode cpuallocator.PinMode
	NUMA cpuallocator.NUMAPolicy
	// IOHousekeeping pins the emulator/IO threads onto the housekeeping set
	// instead of leaving them on the workload's dedicated cores.
	IOHousekeeping bool
	// RequireIsolated restricts placement to cores the running kernel isolates,
	// which is what the isolated CPU policy asks for. It is the only way to be
	// given one: those cores are withheld from every workload that did not ask.
	RequireIsolated bool
}

// resolvePlacement translates a placement intent into allocator parameters. It
// refuses an intent this device cannot serve as sent rather than reinterpreting
// or silently downgrading it, so a workload never runs believing it got
// something it did not.
func resolvePlacement(p types.CPUPlacementPolicy, container bool) (resolvedPlacement, error) {
	if err := rejectUnservable(p, container); err != nil {
		return resolvedPlacement{}, err
	}
	res := resolvedPlacement{
		NUMA:            numaPolicyFor(p.NUMAPolicy),
		IOHousekeeping:  p.IOPlacement == types.CPUIOPlacementHousekeeping,
		RequireIsolated: p.NeedsKernelIsolation(),
	}
	if !p.IsTopologyAware() {
		res.Mode = cpuallocator.ModeShared
		return res, nil
	}
	switch tpc := p.EffectiveThreadsPerCore(); tpc {
	case 1:
		res.Mode = cpuallocator.ModeOnePerCore
	case 2:
		res.Mode = cpuallocator.ModeWholeCoreSMT
	default:
		return resolvedPlacement{}, placementErrorf(types.CPUPlacementStatusPolicyInvalid,
			"threads_per_core must be 1 or 2, got %d", tpc)
	}
	return res, nil
}

// request is the allocator request placing a workload this way, off the CPUs
// in avoid.
func (r resolvedPlacement) request(intent cpuIntent, avoid []cputopology.LCPU) cpuallocator.Request {
	return cpuallocator.Request{
		UUID:            intent.id,
		NumVCPUs:        intent.vcpus,
		Mode:            r.Mode,
		NUMA:            r.NUMA,
		RequireIsolated: r.RequireIsolated,
		Avoid:           avoid,
	}
}

// rejectUnservable refuses a policy whose fields cannot all take effect as sent.
//
// Every field means the same whatever the others say, so there are two ways a
// policy can fail here. A field can be one the request cannot carry: the
// refining fields (full_pcpus_only, threads_per_core, numa_policy, io_placement)
// shape CPUs of the workload's own, and numa_policy, threads_per_core and
// io_placement need whole cores; io_placement and pinning need vCPUs, which a
// container does not have. Or the combination is valid API that this EVE does
// not implement: pinning on the shared pool, an unpinned VM on CPUs of its own,
// or isolated CPUs taken one at a time. Either way the request is refused as
// an invalid policy rather than served as something else.
func rejectUnservable(p types.CPUPlacementPolicy, container bool) error {
	invalid := func(format string, args ...interface{}) error {
		return placementErrorf(types.CPUPlacementStatusPolicyInvalid, format, args...)
	}
	var wholeCoreFields []string
	if p.ThreadsPerCore != 0 {
		wholeCoreFields = append(wholeCoreFields, fmt.Sprintf("threads_per_core=%d", p.ThreadsPerCore))
	}
	if p.NUMAPolicy != types.CPUNUMAPolicyUnspecified {
		wholeCoreFields = append(wholeCoreFields, fmt.Sprintf("numa_policy=%s", p.NUMAPolicy))
	}
	if p.IOPlacement != types.CPUIOPlacementUnspecified {
		wholeCoreFields = append(wholeCoreFields, fmt.Sprintf("io_placement=%s", p.IOPlacement))
	}
	switch {
	case !p.HasOwnCPUs() && (p.FullPCPUsOnly || len(wholeCoreFields) > 0):
		set := wholeCoreFields
		if p.FullPCPUsOnly {
			set = append([]string{"full_pcpus_only"}, set...)
		}
		return invalid("%s refine CPUs of the workload's own, which cpu_policy=%s "+
			"does not give it", strings.Join(set, ", "), p.Policy)
	case p.Pinned && container:
		return invalid("pin_cpu=true on a container: a container has no vCPUs to pin")
	case !p.HasOwnCPUs() && p.Pinned:
		return invalid("pin_cpu=true with cpu_policy=%s: pinning vCPUs on the "+
			"shared pool is not implemented on this node", p.Policy)
	case !p.HasOwnCPUs():
		return nil
	case !p.FullPCPUsOnly && len(wholeCoreFields) > 0:
		return invalid("%s require full_pcpus_only", strings.Join(wholeCoreFields, ", "))
	case !p.FullPCPUsOnly && p.NeedsKernelIsolation():
		return invalid("cpu_policy=isolated without full_pcpus_only is not " +
			"implemented on this node: isolated CPUs are given out as whole cores")
	case container && p.IOPlacement != types.CPUIOPlacementUnspecified:
		return invalid("io_placement=%s on a container: it places a VM's QEMU "+
			"threads, and a container has none", p.IOPlacement)
	case !container && !p.Pinned:
		return invalid("pin_cpu=false with cpu_policy=%s: an unpinned VM on CPUs of "+
			"its own is not implemented on this node", p.Policy)
	}
	return nil
}

func numaPolicyFor(p types.CPUNUMAPolicy) cpuallocator.NUMAPolicy {
	switch p {
	case types.CPUNUMAPolicyNone:
		return cpuallocator.NUMAAllowCross
	case types.CPUNUMAPolicySingleNode:
		return cpuallocator.NUMALocal
	default: // unspecified or best-effort
		return cpuallocator.NUMABestEffort
	}
}

// refuseCPUs records a placement refusal in the status: the verdict the
// controller acts on, so it can tell "a repack would fix this" from "nothing
// would" without parsing text, and the error an operator reads. That error's
// retry condition is the only place the report says what would change the
// answer.
//
// The message says what happened; the retry condition says what to do about it.
// They are deliberately not the same sentence: a UI shows the two fields in
// different places, and repeating the message in the condition wastes the only
// field an operator can act on.
func refuseCPUs(status *types.DomainStatus, refusal *placementError) {
	status.CPUPlacementStatus = refusal.Status
	status.SetErrorDescription(types.ErrorDescription{
		Error:               refusal.Msg,
		ErrorRetryCondition: refusal.retryCondition(),
	})
}

// placementStatusFor maps an allocator outcome onto the refusal the controller
// sees. NeedsRebalance and Insufficient are deliberately distinct: the first
// says a repack would fix this, the second that nothing would.
//
// TopologyUnsupported outranks the status. The allocator reports it as an
// InvalidRequest, but the request is well-formed -- it is the node that cannot
// present the requested thread count, most often because SMT is switched off in
// the platform firmware. Reporting that as an invalid policy sends the operator
// hunting for a mistake in a config that has none.
func placementStatusFor(res cpuallocator.Result) types.CPUPlacementStatus {
	if res.TopologyUnsupported {
		return types.CPUPlacementStatusTopologyUnsupported
	}
	switch res.Status {
	case cpuallocator.NeedsRebalance:
		return types.CPUPlacementStatusNeedsRepack
	case cpuallocator.Insufficient:
		return types.CPUPlacementStatusInsufficient
	default:
		return types.CPUPlacementStatusPolicyInvalid
	}
}

// liveAllocationError classifies a failed live allocation by consulting the
// plan, and is the only place the two placement failure codes are chosen
// between.
//
// The live allocator can only say "this does not fit among what is free right
// now". The plan is computed from an empty slate over the whole configured set,
// so it answers the question the controller actually needs answered: whether the
// workload fits on this node at all. Without that distinction every fragmented
// node reports an insufficient one, and the controller -- whose only
// remedy is restarting the pinned workloads so they repack -- cannot tell a node
// it can fix from one it cannot, so it never tries.
//
// Only a shortage is reinterpreted. InvalidRequest means the caller asked for
// something impossible, which is a bug on this side; blaming it on the running
// workloads would send the operator repacking a node that is not the problem.
//
// blockers names the workloads standing on the CPUs the plan set aside for this
// one, when they are known; an empty list only costs the retry condition its
// names, never its meaning.
//
// unplaced names the running workloads the plan leaves out. A plan that places
// this workload only by dropping one that is running is an eviction, not a
// repack -- restarting the pinned workloads would just move the failure to
// someone else -- so it is reported as a shortage.
func liveAllocationError(displayName string, id uuid.UUID, live cpuallocator.Result,
	plan map[uuid.UUID]cpuallocator.Result, blockers, unplaced []string) *placementError {
	switch live.Status {
	case cpuallocator.Insufficient, cpuallocator.NeedsRebalance:
		if planned, isPlanned := plan[id]; isPlanned &&
			planned.Status == cpuallocator.Success && planned.Assignment != nil {
			if len(unplaced) > 0 {
				return placementErrorf(types.CPUPlacementStatusInsufficient,
					"CPU placement for %s: %s; it is planned onto host CPUs %v "+
						"only by leaving out %s, which is running, so no repack "+
						"can make room for it",
					displayName, live.Message, planned.Assignment.CPUs(),
					strings.Join(unplaced, ", "))
			}
			return placementErrorf(types.CPUPlacementStatusNeedsRepack,
				"CPU placement for %s: %s; the planned placement on host CPUs %v "+
					"does fit this node",
				displayName, live.Message, planned.Assignment.CPUs()).
				retryWhen("%sRestarting the pinned workloads together so they repack "+
					"lets this one take its planned CPUs.%s",
					heldByClause(blockers), noAutoRetry)
		}
		// The live allocator's NeedsRebalance is only a guess about what a repack
		// could do; a plan that has no slot for this workload settles it.
		if planned, isPlanned := plan[id]; isPlanned &&
			live.Status == cpuallocator.NeedsRebalance &&
			planned.Status != cpuallocator.Success {
			return placementErrorf(types.CPUPlacementStatusInsufficient,
				"CPU placement for %s: %s; no placement of the workloads "+
					"configured on this node fits it either, so no repack can "+
					"make room for it", displayName, live.Message)
		}
	}
	err := placementErrorf(placementStatusFor(live),
		"CPU placement for %s: %s", displayName, live.Message)
	if live.TopologyUnsupported {
		// The generic condition for this code speaks about the hypervisor, which
		// is the other way to reach it; here the node's cores are the problem.
		return err.retryWhen("Enable SMT (hyper-threading) in the platform "+
			"firmware and reboot the node, or set threads_per_core=1 for this "+
			"workload and deploy it again. Freeing CPUs cannot help.%s", noAutoRetry)
	}
	if condition := shortageRetryCondition(live); condition != "" {
		return err.retryWhen("%s", condition)
	}
	return err
}

// heldByClause names the workloads in the way, as a sentence the retry condition
// can lead with. Empty when nothing is known, so the condition still reads.
func heldByClause(blockers []string) string {
	if len(blockers) == 0 {
		return ""
	}
	return fmt.Sprintf("The planned CPUs are held by %s. ",
		strings.Join(blockers, ", "))
}

// shortageRetryCondition states in numbers the condition a shortage clears
// under, which is what a controller needs in order to decide between waiting for
// capacity and placing the workload somewhere else.
//
// It returns "" when the allocator counted no cores -- a thread-granular request
// is not a whole-core shortage -- and the code's generic condition is used
// instead. It deliberately does not claim that no arrangement could ever fit:
// this path is also reached for a workload the plan says nothing about, where
// that is not known.
func shortageRetryCondition(res cpuallocator.Result) string {
	if res.CoresNeeded <= 0 {
		return ""
	}
	switch res.Status {
	case cpuallocator.NeedsRebalance:
		return fmt.Sprintf("It can run once %d whole physical cores are free within a "+
			"single NUMA node (%d free across all nodes now) and the workload is "+
			"started again; restarting the pinned workloads together so they repack "+
			"may also achieve it.%s", res.CoresNeeded, res.CoresFree, noAutoRetry)
	case cpuallocator.Insufficient:
		return fmt.Sprintf("It can run once %d whole physical cores are free at once "+
			"(%d free now) and the workload is started again; freeing them needs "+
			"another pinned workload to stop, or a node with more cores.%s",
			res.CoresNeeded, res.CoresFree, noAutoRetry)
	}
	return ""
}

// validateVCPUCount is the device-side backstop for constraints the controller
// is also expected to enforce at deploy time.
func validateVCPUCount(r resolvedPlacement, vcpus int) error {
	if r.Mode == cpuallocator.ModeWholeCoreSMT && vcpus%2 != 0 {
		return placementErrorf(types.CPUPlacementStatusOddVCPU,
			"whole-core-smt requires an even vCPU count, got %d", vcpus)
	}
	return nil
}

// cpuIntent is everything a placement decision needs to know about a workload.
// The plan covers workloads that have no DomainConfig yet, so it is built from
// either source: a DomainConfig or an entry in zedmanager's demand set.
type cpuIntent struct {
	id          uuid.UUID
	displayName string
	vcpus       int
	policy      types.CPUPlacementPolicy
	// container is a workload without vCPUs (NOHYPER).
	container bool
}

func intentOfConfig(config *types.DomainConfig) cpuIntent {
	return cpuIntent{
		id:          config.UUIDandVersion.UUID,
		displayName: config.DisplayName,
		vcpus:       config.VCpus,
		policy:      config.VmConfig.CPUPlacement,
		container:   config.VirtualizationMode == types.NOHYPER,
	}
}

func intentOfDemand(app types.AppCPUDemand) cpuIntent {
	return cpuIntent{
		id:          app.UUID,
		displayName: app.DisplayName,
		vcpus:       app.VCpus,
		policy:      app.CPUPlacement,
		container:   app.VirtualizationMode == types.NOHYPER,
	}
}

// ownsCPUs is whether the workload gets CPUs no other workload runs on.
func (i cpuIntent) ownsCPUs() bool {
	return i.policy.HasOwnCPUs()
}

// placement resolves the intent into allocator terms, or refuses it.
func (i cpuIntent) placement() (resolvedPlacement, error) {
	return resolvePlacement(i.policy, i.container)
}
