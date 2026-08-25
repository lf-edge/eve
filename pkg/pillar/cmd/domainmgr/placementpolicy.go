// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// placementError carries a machine-parseable code alongside the message, so the
// failure reaches the controller as a structured ErrorInfo rather than prose.
type placementError struct {
	Code string
	Msg  string
	// Retry is what would change the outcome, for the failures that can say
	// something more specific than their code's generic condition (which
	// workloads are in the way, how many cores short the node is). Empty means
	// the code's generic condition is used; it never reaches the controller
	// empty, see retryConditionFor.
	Retry string
}

func (e *placementError) Error() string { return e.Msg }

func placementErrorf(code, format string, args ...interface{}) *placementError {
	return &placementError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// retryWhen attaches the specific condition this failure clears under, for the
// cases where the generic per-code text can be improved on with real numbers or
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
// failure itself has nothing more specific to add. Every code produced on this
// path has an entry: an ErrorInfo that says "insufficient" with an empty
// retry_condition tells a controller that something is wrong and nothing about
// what would make it right, which is the one outcome worse than a blunt message.
func retryConditionFor(code string) string {
	switch code {
	case types.ErrorCodeCPUPlacementInsufficient:
		return "Stop another pinned workload to free whole physical cores, or " +
			"deploy this one on a node with more cores, then start it again." +
			noAutoRetry
	case types.ErrorCodeCPUPlacementNeedsRepack:
		return "Restart the pinned workloads together so they repack, then start " +
			"this one again." + noAutoRetry
	case types.ErrorCodeCPUPolicyOddVCPU:
		return "Change the workload's vCPU count to an even number, or set " +
			"threads_per_core=1, and deploy it again. No change on the node makes " +
			"an odd count placeable on two-thread cores." + noAutoRetry
	case types.ErrorCodeCPUIsolationTierUnavailable:
		return "Lower the workload's isolation_tier to soft or none, or deploy it " +
			"on a node booted with CPU isolation. This node cannot change its " +
			"isolation without a kernel command-line change and a reboot." + noAutoRetry
	case types.ErrorCodeCPUTopologyUnsupported:
		return "Deploy the workload on a node whose hypervisor can pin individual " +
			"vCPUs, or turn off whole-core placement (full_pcpus_only) for it. No " +
			"amount of free CPUs makes this node able to honour the request." + noAutoRetry
	case types.ErrorCodeCPUPolicyInvalid:
		return "Change the workload's CPU placement policy to one this node " +
			"implements and deploy it again. No change on the node makes the " +
			"request as written satisfiable." + noAutoRetry
	}
	// A code with no entry is still better served by a true statement than by
	// an empty field: every failure on this path is fail-closed, so it needs
	// either the workload's configuration or the node to change.
	return "Change the workload's CPU placement configuration, or deploy it on a " +
		"node that can satisfy it, then start it again." + noAutoRetry
}

// resolvedPlacement is a workload's CPU placement intent translated into the
// allocator's vocabulary.
type resolvedPlacement struct {
	// TopologyAware selects the whole-physical-core, SMT/NUMA-aware allocator.
	// When false the workload is either not pinned at all or pinned at
	// thread granularity through the legacy shared-pool path.
	TopologyAware bool
	Mode          cpuallocator.PinMode
	NUMA          cpuallocator.NUMAPolicy
	// IOHousekeeping pins the emulator/IO threads onto the housekeeping set
	// instead of leaving them on the workload's dedicated cores.
	IOHousekeeping bool
}

// resolvePlacement translates a placement intent into allocator parameters. It
// rejects intents this device cannot satisfy rather than silently downgrading
// them, so a workload never runs believing it got guarantees it did not.
func resolvePlacement(p types.CPUPlacementPolicy) (resolvedPlacement, error) {
	if err := rejectUnenforceableFields(p); err != nil {
		return resolvedPlacement{}, err
	}
	if !p.IsolationTier.SupportedBySoftIsolation() {
		return resolvedPlacement{}, placementErrorf(
			types.ErrorCodeCPUIsolationTierUnavailable,
			"isolation tier %q requires a kernel command-line change and is not supported on this node",
			p.IsolationTier)
	}

	// Nothing on the device defers a node-level disruptive action yet, so
	// accepting "protect" would tell the controller its workload is shielded
	// while a reboot or an upgrade still takes it down unannounced. Refuse it
	// for the same reason the hard isolation tier is refused: an unenforced
	// guarantee is worse than a rejected one.
	if p.DisruptionPolicy == types.CPUDisruptionPolicyProtect {
		return resolvedPlacement{}, placementErrorf(types.ErrorCodeCPUPolicyInvalid,
			"disruption policy %q is not implemented on this node; "+
				"a node-level action can still take this workload down",
			p.DisruptionPolicy)
	}

	res := resolvedPlacement{
		TopologyAware:  p.IsTopologyAware(),
		NUMA:           numaPolicyFor(p.NUMAPolicy),
		IOHousekeeping: p.IOPlacement == types.CPUIOPlacementHousekeeping,
	}
	if !res.TopologyAware {
		res.Mode = cpuallocator.ModeShared
		return res, nil
	}
	switch tpc := p.EffectiveThreadsPerCore(); tpc {
	case 1:
		res.Mode = cpuallocator.ModeOnePerCore
	case 2:
		res.Mode = cpuallocator.ModeWholeCoreSMT
	default:
		return resolvedPlacement{}, placementErrorf(types.ErrorCodeCPUPolicyInvalid,
			"threads_per_core must be 1 or 2, got %d", tpc)
	}
	return res, nil
}

// rejectUnenforceableFields refuses a policy whose whole-core fields cannot take
// effect as written.
//
// full_pcpus_only, threads_per_core and numa_policy only mean anything for a
// workload that gets CPUs of its own, so a policy that sets them without
// cpu_policy=dedicated describes a placement this device will not perform. The
// request is refused rather than honoured in part, for the same reason the hard
// isolation tier is: the workload would otherwise run on shared, thread-granular
// CPUs while the controller believes it asked for whole cores on one NUMA node.
//
// threads_per_core is checked here as well as on the whole-core path, so an
// out-of-range value is reported as the invalid policy it is instead of being
// quietly dropped along with the rest.
func rejectUnenforceableFields(p types.CPUPlacementPolicy) error {
	if p.IsDedicated() {
		return nil
	}
	var set []string
	if p.FullPCPUsOnly {
		set = append(set, "full_pcpus_only")
	}
	if p.ThreadsPerCore != 0 {
		set = append(set, fmt.Sprintf("threads_per_core=%d", p.ThreadsPerCore))
	}
	if p.NUMAPolicy != types.CPUNUMAPolicyUnspecified {
		set = append(set, fmt.Sprintf("numa_policy=%s", p.NUMAPolicy))
	}
	if len(set) == 0 {
		return nil
	}
	return placementErrorf(types.ErrorCodeCPUPolicyInvalid,
		"%s require cpu_policy=dedicated, which this workload does not request "+
			"(cpu_policy=%s)", strings.Join(set, ", "), p.Policy)
}

func numaPolicyFor(p types.CPUNUMAPolicy) cpuallocator.NUMAPolicy {
	switch p {
	case types.CPUNUMAPolicyNone:
		return cpuallocator.NUMAAllowCross
	// Both mean "one node or fail" for now. They differ in Kubernetes only by
	// how many *other* aligned resources are weighed, and CPU placement weighs
	// none yet -- see the comment on CPUNUMAPolicyRestricted.
	case types.CPUNUMAPolicyRestricted, types.CPUNUMAPolicySingleNode:
		return cpuallocator.NUMALocal
	default: // unspecified or best-effort
		return cpuallocator.NUMABestEffort
	}
}

// placementErrorDescription turns a placement failure into a status error,
// carrying the structured code when the failure has one so the controller can
// distinguish "a repack would fix this" from "nothing would" without parsing the
// message text, plus the retry condition, which is the only place the report says
// what would change the answer.
//
// The message says what happened; the retry condition says what to do about it.
// They are deliberately not the same sentence: a UI shows the two fields in
// different places, and repeating the message in the condition wastes the only
// field an operator can act on.
func placementErrorDescription(err error) types.ErrorDescription {
	description := types.ErrorDescription{Error: err.Error()}
	var placementErr *placementError
	if errors.As(err, &placementErr) {
		description.ErrorCode = placementErr.Code
		description.ErrorRetryCondition = placementErr.Retry
		if description.ErrorRetryCondition == "" {
			description.ErrorRetryCondition = retryConditionFor(placementErr.Code)
		}
	}
	return description
}

// placementErrorCode maps an allocator outcome onto the published error-code
// registry. NeedsRebalance and Insufficient are deliberately distinct: the
// first says a repack would fix this, the second that nothing would.
//
// TopologyUnsupported outranks the status. The allocator reports it as an
// InvalidRequest, but the request is well-formed -- it is the node that cannot
// present the requested thread count, most often because SMT is switched off in
// the platform firmware. Reporting that as cpu.policy.invalid sends the operator
// hunting for a mistake in a config that has none.
func placementErrorCode(res cpuallocator.Result) string {
	if res.TopologyUnsupported {
		return types.ErrorCodeCPUTopologyUnsupported
	}
	switch res.Status {
	case cpuallocator.NeedsRebalance:
		return types.ErrorCodeCPUPlacementNeedsRepack
	case cpuallocator.Insufficient:
		return types.ErrorCodeCPUPlacementInsufficient
	default:
		return types.ErrorCodeCPUPolicyInvalid
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
// node reports cpu.placement.insufficient, and the controller -- whose only
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
func liveAllocationError(displayName string, id uuid.UUID, live cpuallocator.Result,
	plan map[uuid.UUID]cpuallocator.Result, blockers []string) *placementError {
	switch live.Status {
	case cpuallocator.Insufficient, cpuallocator.NeedsRebalance:
		if planned, isPlanned := plan[id]; isPlanned &&
			planned.Status == cpuallocator.Success && planned.Assignment != nil {
			return placementErrorf(types.ErrorCodeCPUPlacementNeedsRepack,
				"topology pinning for %s: %s; the planned placement on host CPUs %v "+
					"does fit this node",
				displayName, live.Message, assignmentCPUs(planned.Assignment)).
				retryWhen("%sRestarting the pinned workloads together so they repack "+
					"lets this one take its planned CPUs.%s",
					heldByClause(blockers), noAutoRetry)
		}
	}
	err := placementErrorf(placementErrorCode(live),
		"topology pinning for %s: %s", displayName, live.Message)
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
	if r.TopologyAware && r.Mode == cpuallocator.ModeWholeCoreSMT && vcpus%2 != 0 {
		return placementErrorf(types.ErrorCodeCPUPolicyOddVCPU,
			"whole-core-smt requires an even vCPU count, got %d", vcpus)
	}
	return nil
}

// cpuIntent is everything a placement decision needs to know about a workload.
//
// It exists because the decision has to be made for workloads that have no
// DomainConfig yet: the plan covers every app the controller intends to run,
// and most of them have not got as far as a DomainConfig when the first one is
// placed. Both sources -- a DomainConfig and an entry in the demand set --
// reduce to this.
type cpuIntent struct {
	id          uuid.UUID
	displayName string
	vcpus       int
	// pinned is the controller's legacy pin flag. It is not the final answer:
	// see cpuIntentPinned.
	pinned bool
	policy types.CPUPlacementPolicy
}

func intentOfConfig(config *types.DomainConfig) cpuIntent {
	return cpuIntent{
		id:          config.UUIDandVersion.UUID,
		displayName: config.DisplayName,
		vcpus:       config.VCpus,
		pinned:      config.VmConfig.CPUsPinned,
		policy:      config.VmConfig.CPUPlacement,
	}
}

func intentOfDemand(app types.AppCPUDemand) cpuIntent {
	return cpuIntent{
		id:          app.UUID,
		displayName: app.DisplayName,
		vcpus:       app.VCpus,
		pinned:      app.CPUsPinned,
		policy:      app.CPUPlacement,
	}
}

// placementFor resolves the effective placement for a domain.
//
// The controller's intent is authoritative whenever it sent one. The
// operator-editable /persist override only applies to workloads the controller
// said nothing about, which keeps it useful for bring-up and manual testing on
// a device with no policy-aware controller, without letting a stale local file
// silently contradict what the controller asked for.
func placementFor(config *types.DomainConfig) (resolvedPlacement, error) {
	return placementForIntent(intentOfConfig(config))
}

func placementForIntent(intent cpuIntent) (resolvedPlacement, error) {
	if controllerSentPolicy(intent.policy) {
		return resolvePlacement(intent.policy)
	}
	return placementFromPersist(intent.id)
}

// controllerSentPolicy reports whether the controller expressed any CPU
// placement intent at all.
//
// It cannot key off cpu_policy alone. The placement fields are independent on
// the wire, so a controller can set isolation_tier or full_pcpus_only while
// leaving cpu_policy unset -- and gating on cpu_policy meant every other field
// was dropped without a word, taking the two refusals that exist to prevent an
// unenforced guarantee (hard isolation, protect disruption) with it.
//
// The zero value still means "no policy", which is what keeps the /persist
// override available for a workload the controller said nothing about.
func controllerSentPolicy(p types.CPUPlacementPolicy) bool {
	return p != types.CPUPlacementPolicy{}
}

// effectiveCPUsPinned reports whether a workload must get host CPUs of its own.
//
// It exists because the two sources of placement intent disagree about how
// pinning is switched on. The controller sets CPUsPinned (zedagent derives it
// from a dedicated policy), but the /persist override cannot: it is an operator
// file, not part of the app config. Without this, asking for
// static + full-pcpus-only in /persist did nothing at all unless the controller
// also happened to pin the workload -- which defeats the point of the override,
// namely bringing whole-core placement up on a device whose controller knows
// nothing about it.
//
// Precedence is unchanged: the controller's intent wins whenever it sent any,
// including an explicit "shared", and the override only speaks for workloads
// the controller said nothing about.
func effectiveCPUsPinned(config *types.DomainConfig) bool {
	return cpuIntentPinned(intentOfConfig(config))
}

func cpuIntentPinned(intent cpuIntent) bool {
	if intent.pinned {
		return true
	}
	if controllerSentPolicy(intent.policy) {
		return false
	}
	placement, err := placementFromPersist(intent.id)
	return err == nil && placement.TopologyAware
}

// placementFromPersist reads the operator-editable /persist/pinning override.
//
// An unreadable or invalid file leaves the workload on the controller's intent
// alone, logged at error severity. It cannot fail the workload instead: the
// override speaks only for workloads the controller said nothing about, so
// refusing to start would take down workloads that never asked for anything the
// file could grant. What it must not do is quietly pretend the file granted
// something -- hence TopologyAware stays false, and no placement quality is
// claimed.
func placementFromPersist(id uuid.UUID) (resolvedPlacement, error) {
	cfg, err := loadPinningConfig()
	if err != nil {
		log.Errorf("CPU placement: %s is unreadable (%v); ignoring the operator "+
			"override for %s and using the controller's intent alone",
			pinConfigFile, err, id)
		return resolvedPlacement{Mode: cpuallocator.ModeShared}, nil
	}
	mode, numa, found, err := pinningPolicyOf(cfg, id)
	if err != nil {
		log.Errorf("CPU placement: %v; ignoring the operator override for %s", err, id)
		return resolvedPlacement{Mode: cpuallocator.ModeShared}, nil
	}
	return resolvedPlacement{
		TopologyAware:  found,
		Mode:           mode,
		NUMA:           numa,
		IOHousekeeping: ioPlacementOf(cfg, id) == "housekeeping",
	}, nil
}
