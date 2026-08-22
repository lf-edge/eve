// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test that a CPU placement request this node cannot honour is refused with the
// right structured code, and that the refusal costs the node nothing.

package apps_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// The remaining CPU placement failure codes as they travel on the wire, in
// ZInfoApp.AppErr[].error_code. errCodeNeedsRepack and errCodeInsufficient --
// the two a shortage produces -- live in cpuneedsrepack_test.go.
//
// Spelled out here rather than imported from pillar's types package for the same
// two reasons given there: evetest builds against a released pillar module,
// which does not carry constants added on a feature branch; and these strings
// *are* the published contract a controller matches on, so a test referencing
// the device's own constant could not notice one of them being renamed under it.
const (
	// errCodeOddVCPU means whole-core-SMT was asked for with an odd vCPU count.
	// Every core contributes two vCPUs, so no arrangement satisfies it and no
	// amount of free capacity would help.
	errCodeOddVCPU = "cpu.policy.odd_vcpu"
	// errCodeTierUnavailable means the requested isolation tier cannot be
	// provided by this node as it is currently running.
	errCodeTierUnavailable = "cpu.isolation.tier_unavailable"
	// errCodePolicyInvalid means the policy itself is malformed or asks for
	// something this device does not implement.
	errCodePolicyInvalid = "cpu.policy.invalid"
	// errCodeTopologyUnsupported means the active hypervisor cannot bind vCPUs
	// to named host CPUs at all. Listed only so the exclusivity check below
	// covers it; it is not reachable on the kvm path this test runs on (see the
	// test's doc comment).
	errCodeTopologyUnsupported = "cpu.topology.unsupported"
	// errCodeDegraded is the advisory a *running* workload gets. It is in the
	// exclusivity list because emitting it beside a fatal refusal would tell the
	// controller a workload is up when it never started.
	errCodeDegraded = "cpu.placement.degraded"
)

// placementErrorCodes is the whole published registry of cpu.* codes. Each
// refusal below is required to carry its own code and none of the others, which
// is what makes the assertion "exactly this code" rather than "at least this
// code": a device that answered every unsatisfiable request with, say,
// cpu.policy.invalid would satisfy a per-case ContainElement check for that one
// case while being useless to a controller.
var placementErrorCodes = []string{
	errCodeOddVCPU,
	errCodeTierUnavailable,
	errCodePolicyInvalid,
	errCodeTopologyUnsupported,
	errCodeNeedsRepack,
	errCodeInsufficient,
	errCodeDegraded,
}

const (
	// refusalHolderVCPUs is the whole-core-SMT request of the one application in
	// this test that must actually run: two vCPUs, i.e. exactly one physical
	// core. It is there so that "the dedicated pool is unchanged" is a statement
	// about a non-empty pool -- an assertion that the pool stayed empty would
	// hold on a device that never allocates anything at all.
	refusalHolderVCPUs = 2
	// refusalOddVCPUs is the odd vCPU count offered to whole-core-SMT. Three
	// rather than one: a single vCPU could be refused by an allocator that simply
	// cannot round up, whereas three is a count the device *could* serve by
	// handing over two whole cores and wasting a thread -- which is precisely the
	// silent downgrade the code exists to prevent.
	refusalOddVCPUs = 3
	// refusalEvenVCPUs is the vCPU count used by every case whose defect is not
	// the count itself. Even, and small enough to fit the free capacity left
	// after the holder, so no refusal below can be explained away as a shortage.
	refusalEvenVCPUs = 2
	// refusalInvalidThreadsPerCore is a threads_per_core the API has no meaning
	// for. Only 1 (sibling parked) and 2 (both siblings become vCPUs) exist.
	refusalInvalidThreadsPerCore = 3
	// refusalErrorTimeout bounds waiting for the device to report a refusal. It
	// covers creating the app's volume from the already-downloaded image, the
	// trip through zedmanager/domainmgr and the info message back.
	refusalErrorTimeout = 10 * time.Minute
	// refusalPoolStableFor is how long the node's CPU pool report must keep
	// matching the pre-attempt baseline, and refusalPoolPolling how often it is
	// re-read.
	//
	// Checked with Consistently rather than Eventually because the property is
	// "nothing changed": a single read could be satisfied by a message published
	// before the refused applications were ever configured. Spanning several
	// publish intervals (the device is lowered to placementDevInfoInterval)
	// guarantees at least one report computed *after* the refusals is seen.
	//
	// Neither the baseline nor the re-reads touch the device: the pool report is
	// picked out of the ZInfoDevice messages the harness already receives, so the
	// whole stability window costs no SSH sessions.
	refusalPoolStableFor = 100 * time.Second
	refusalPoolPolling   = 10 * time.Second
)

// refusedRequest is one unsatisfiable placement request plus the code the device
// must answer it with.
type refusedRequest struct {
	spec cpuPlacementApp
	// wantCode is the error_code the controller must receive.
	wantCode string
	// why states what makes the request impossible to honour, and is quoted in
	// the failure messages so a failing run explains itself.
	why string
}

// TestCPUPlacementFailsClosed verifies that every class of unsatisfiable CPU
// placement request this device can be sent is refused, is refused with its own
// machine-parseable code, and leaves the node exactly as it found it.
//
// Failing *open* is the failure mode that matters here, and it is the reason
// this test exists rather than trusting the unit tests that cover the same
// decisions. A device that starts a workload with weaker guarantees than it
// asked for reports success: the app is RUNNING, the controller is satisfied,
// and the workload silently runs without the isolation it was deployed for. That
// is worse than not starting, and it is invisible from the controller -- so the
// only place it can be caught is a test that sends the impossible request over
// the wire and looks at what comes back (design doc §3 "fail cleanly, never
// mis-place", §10.4 "a hard requirement never degrades silently").
//
// The second half of each verdict is that a refusal must be *free*. A request
// the device rejects must not have reserved the cores it was rejected for: the
// controller was told the workload did not start, so from its point of view that
// capacity is available, and a node quietly holding it would shrink its own
// usable capacity on every rejected deploy -- with nothing anywhere saying why.
// That is asserted against the node's own cpu_pools report, which is what a
// controller actually reads to answer "will the next workload fit here?".
//
// Codes covered, and what makes each request impossible
// ----------------------------------------------------
//   - cpu.policy.odd_vcpu -- whole-core-SMT with an odd vCPU count. Each
//     dedicated core contributes both its SMT threads as vCPUs, so the vCPU
//     count is necessarily even and no arrangement of cores satisfies an odd
//     one. Free capacity is irrelevant.
//   - cpu.isolation.tier_unavailable -- isolation tier "hard". Shedding kernel
//     housekeeping off the workload's cores needs a kernel command-line change
//     and a reboot, which the device cannot do while placing a workload. The
//     alternative to refusing is delivering soft isolation and calling it hard.
//   - cpu.policy.invalid, twice, by the two independent routes that reach it:
//     threads_per_core = 3, a value the API gives no meaning to (only 1 and 2
//     exist); and disruption policy "protect", which was deliberately turned
//     from accepted-but-unenforced into a refusal, because nothing on the device
//     defers a node-level action yet and a workload told it is shielded would
//     still be taken down by a reboot without warning.
//
// Not covered: cpu.topology.unsupported. It fires when the active hypervisor
// cannot pin individual vCPUs or synthesize a guest SMT topology, which is a
// property of the hypervisor (kvm can, kubevirt cannot -- hypervisor.Capabilities
// .CPUTopologyPinning), not of anything a controller can configure. On the kvm
// path this test runs on there is no configuration that reaches it, and this test
// runs only on kvm because under kubevirt the kubelet, not the pillar allocator,
// selects CPUs. It is listed in placementErrorCodes anyway, so that a device
// answering one of the cases below with it would be caught.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- placement is not network dependent; a
//     single mgmt+apps port is enough to run the holder app and reach it.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), local NI "local-ni".
//   - timer.deviceinfo.interval lowered to its minimum: the node's CPU pool
//     report rides the periodic ZInfoDevice publish, and the residue assertion
//     needs a report computed after the refusals.
//   - 8 CPUs as 4 dual-thread cores. EVE reserves the lowest CPU, making its
//     whole core unallocatable, so three cores are allocatable: one goes to the
//     holder app and two stay free. Every refused request below asks for at most
//     two cores, so each of them would fit the free capacity if it were
//     honourable -- which is what makes the refusal attributable to the policy
//     rather than to a shortage.
//   - Five container apps (lfedge/evetest-ubuntu-ctr): one that must run and
//     four that must not, all on the same boot. A refused app costs no CPUs, so
//     they cost no capacity and there is no reason to spend a device boot each.
//
// Phases / assertions
// -------------------
//  1. holder-placed: the one valid app runs and is fully verified, and the
//     node's dedicated pool and free housekeeping set are recorded as the
//     baseline the refusals must not move.
//  2. refusals-reported: the four unsatisfiable apps are deployed together. Each
//     must report its own code and none of the other cpu.* codes, at ERROR
//     severity with a non-empty retry condition, and must not reach RUNNING or
//     even BOOTING. Asserted entirely from the info messages the controller
//     receives, which touches the device not at all.
//  3. no-residue: the node's dedicated pool and free housekeeping set still
//     equal the baseline across several publish intervals, and -- read from the
//     device in a single batched session -- no refused app is activated, holds a
//     host CPU or carries a placement quality, while the holder still holds
//     exactly what it held. A refusal must not be paid for by a workload that
//     was already placed, nor by the node's capacity.
//
// The device-side reads are deliberately batched into one SSH session rather
// than one per file. By the time this test runs, most of the node's CPUs belong
// to a pinned workload and EVE's own services are squeezed onto the
// housekeeping set; short-lived SSH sessions on such a device were observed
// dying with "connection reset by peer". Ten small reads are ten chances to lose
// one, and retrying each of them just spends more sessions -- so the chattiness
// is removed instead of worked around.
//
// Test params
// -----------
//   - HYPERVISOR. Skipped under Kubevirt, where concrete CPU selection belongs
//     to the kubelet rather than to the pillar allocator this test exercises.
//
// Suite placement
// ---------------
//   - TestAppsSuite, with the other CPU placement tests: it wants the same
//     device (8 CPUs, 2 threads per core), so the VM can be reused.
func TestCPUPlacementFailsClosed(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	if hypervisor == evetest.HypervisorKubevirt {
		evetestT.Skip("under Kubevirt the kubelet selects CPUs, not the pillar allocator")
	}

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			MinCPUs:           8,
			ThreadsPerCore:    2,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)

	// The holder app asks for a whole core with both siblings as vCPUs, which a
	// device of single-thread cores cannot provide. Without it there is no
	// non-empty dedicated pool to assert stays unchanged, so the interesting half
	// of this test would hold vacuously.
	topo, err := device.HostCPUTopology()
	t.Expect(err).ToNot(HaveOccurred())
	if !deviceHasSMT(topo) {
		evetestT.Skip("the device has no SMT sibling threads, so the whole-core-SMT " +
			"holder application cannot be placed and there would be no non-empty " +
			"dedicated pool for the refusals to leave unchanged")
	}
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// The residue assertion reads the node's CPU pool report, which only reaches
	// the controller on the periodic ZInfoDevice publish; at the 10 minute default
	// the test would spend most of its time waiting for a message.
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(pillartypes.DevInfoInterval, placementDevInfoInterval)
	devConfig.SetConfigProperties(cfgProps)

	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	niUUID := addLocalNI(devConfig)

	// Phase 1: the workload that must be unaffected by everything below.
	holderSpec := wholeCoreSMTApp("cpu-refused-holder-app", refusalHolderVCPUs,
		appSSHFwdPort)
	holder := &placedApp{spec: holderSpec}
	holder.uuid = devConfig.AddApplication(placementAppConfig(holderSpec, niUUID, 0))
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("holder-configured")

	device.WaitUntilAppIsRunning(holder.uuid, placementRunningTimeout)
	logPlacementDiagnostics(device, []uuid.UUID{holder.uuid}, placementShellTimeout)
	// Nothing else is running, so the holder must have landed on its planned slot.
	assertAppPlacement(t, device, topo, holder, true)
	holderOrdered := append([]uint32(nil), holder.status.OrderedCPUs...)
	holderDedicated := append([]uint32(nil), holder.dedicated...)

	// The baseline every refusal must leave alone, taken from the node's own
	// report rather than from domainmgr's per-app view: this is the report a
	// controller consults to decide whether the next workload fits here, so it is
	// the one whose silent shrinking would do the damage.
	baseline := awaitCPUPoolReport(t, device,
		"the holder application holding its whole core",
		func(g Gomega, report cpuPoolReport) {
			g.Expect(report.dedicated.GetCpuIds()).To(ContainElements(intsOf(holderDedicated)),
				"the node's dedicated pool %v omits host CPUs %v, which %q holds",
				report.dedicated.GetCpuIds(), holderDedicated, holderSpec.appName)
		})
	baseDedicated := append([]uint32(nil), baseline.dedicated.GetCpuIds()...)
	baseFree := append([]uint32(nil), baseline.housekeeping.GetFreeCpuIds()...)
	baseFreeWholeCores := baseline.housekeeping.GetFreeWholeCores()
	evetest.Logger().Infof("baseline before any refused request: dedicated %v, free "+
		"housekeeping %v, free whole cores %d", baseDedicated, baseFree, baseFreeWholeCores)
	// Stated as an assertion because every refusal below is only attributable to
	// its policy if the request could otherwise have been served. With no free
	// whole core left, "the device refused it" would prove nothing.
	t.Expect(baseFreeWholeCores).To(BeNumerically(">=", 2),
		"the node reports only %d free whole core(s) after placing %q; the refused "+
			"requests below ask for up to two cores each and must be refusable only "+
			"on policy grounds, so the node has to have the capacity to serve them. "+
			"The sizing above assumes four dual-thread cores, one CPU of which EVE "+
			"reserves; on a differently sized device it has to be recomputed",
		baseFreeWholeCores, holderSpec.appName)
	evetest.Checkpoint("holder-placed")

	// Phase 2: every class of request this node cannot honour, deployed together.
	// Each is sized to fit the free capacity, so nothing here can be refused for
	// running out of cores.
	refused := []refusedRequest{
		{
			spec: oddVCPUWholeCoreApp("cpu-refused-odd-vcpu-app", refusalOddVCPUs,
				appSSHFwdPort+1),
			wantCode: errCodeOddVCPU,
			why: fmt.Sprintf("whole-core-smt turns both SMT threads of every "+
				"dedicated core into vCPUs, so the vCPU count is necessarily even; "+
				"%d cannot be produced by any number of cores", refusalOddVCPUs),
		},
		{
			spec: hardIsolationApp("cpu-refused-hard-tier-app", refusalEvenVCPUs,
				appSSHFwdPort+2),
			wantCode: errCodeTierUnavailable,
			why: "hard isolation sheds kernel housekeeping off the workload's cores, " +
				"which needs a kernel command-line change and a reboot; the device " +
				"cannot do that while placing a workload, and delivering soft " +
				"isolation instead would hand the workload weaker guarantees than it " +
				"asked for without telling anyone",
		},
		{
			spec: invalidThreadsPerCoreApp("cpu-refused-threads-app", refusalEvenVCPUs,
				appSSHFwdPort+3),
			wantCode: errCodePolicyInvalid,
			why: fmt.Sprintf("threads_per_core=%d has no meaning in the API: a "+
				"dedicated core either contributes one vCPU with its sibling parked "+
				"or both siblings as vCPUs, and nothing else",
				refusalInvalidThreadsPerCore),
		},
		{
			spec: protectedDisruptionApp("cpu-refused-protect-app", refusalEvenVCPUs,
				appSSHFwdPort+4),
			wantCode: errCodePolicyInvalid,
			why: "nothing on the device defers a node-level disruptive action yet, so " +
				"accepting \"protect\" would tell the controller its workload is " +
				"shielded while a reboot or an upgrade still takes it down unannounced",
		},
	}

	// Subscribed before the configuration is applied, so a refusal reported
	// quickly cannot be missed.
	watched := make([]<-chan *eveinfo.ZInfoApp, 0, len(refused))
	uuids := make([]uuid.UUID, 0, len(refused))
	for _, request := range refused {
		appUUID := devConfig.AddApplication(placementAppConfig(request.spec, niUUID, 0))
		uuids = append(uuids, appUUID)
		updates, stop := device.WatchAppInfo(appUUID)
		defer stop()
		watched = append(watched, updates)
	}
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("refusals-configured")

	for i, request := range refused {
		appName := request.spec.appName
		reported := awaitRefusalError(t, watched[i], appName, refusalErrorTimeout)
		codes := errorCodesOf(reported)

		// The whole point: the controller must receive this code, not merely an
		// error. Asserted on error_code and never on the description -- the prose
		// is for humans and may be reworded at any time, while the code is the
		// published contract.
		t.Expect(codes).To(ContainElement(request.wantCode),
			"%q asked for something this node cannot honour (%s) and reported %v; "+
				"the controller must receive %q so it can tell the user what to fix "+
				"instead of showing a bare \"failed to start\"",
			appName, request.why, codes, request.wantCode)
		// And no other code from the registry, so each condition is genuinely
		// distinguished rather than all of them collapsing onto one token.
		for _, other := range placementErrorCodes {
			if other == request.wantCode {
				continue
			}
			t.Expect(codes).ToNot(ContainElement(other),
				"%q must be refused with %q alone but also reported %q (all codes: "+
					"%v); the codes are alternatives a controller switches on, so "+
					"reporting two of them leaves it no verdict",
				appName, request.wantCode, other, codes)
		}

		// Severity, because the code alone does not say whether the workload is
		// broken or merely imperfect. cpu.placement.degraded rides the same
		// per-app error list at WARNING severity precisely so a controller can
		// tell an advisory from a refusal; a refusal published at WARNING would be
		// read as "running, with a remark".
		refusal := errorWithCode(reported, request.wantCode)
		t.Expect(refusal).ToNot(BeNil())
		t.Expect(refusal.GetSeverity()).To(Equal(eveinfo.Severity_SEVERITY_ERROR),
			"%q was refused with %q at severity %s; a refusal is not an advisory, "+
				"and a controller that distinguishes them by severity would treat "+
				"this workload as running", appName, request.wantCode,
			refusal.GetSeverity())

		// The code says which condition it is; the retry condition says what would
		// change the answer. Every refusal here is fail-closed, so there is always
		// something true to say -- either the workload's configuration or the node
		// has to change -- and an empty field would leave the operator with an
		// error they cannot act on. Only its presence is asserted: the wording is
		// prose meant for a human and will be rewritten.
		t.Expect(refusal.GetRetryCondition()).ToNot(BeEmpty(),
			"%q was refused with %q but the device suggested no retry condition; "+
				"the refusal is permanent until something changes, so the one field "+
				"that could tell the operator *what* to change must not be empty",
			appName, request.wantCode)

		evetest.Logger().Infof("%q refused with code=%q severity=%s retry=%q "+
			"description=%q", appName, refusal.GetErrorCode(), refusal.GetSeverity(),
			refusal.GetRetryCondition(), refusal.GetDescription())

		// Fail closed. This is the assertion the whole test is built around: a
		// workload that got weaker guarantees than it asked for and started anyway
		// looks like success from every angle a controller can see.
		//
		// The states are checked rather than the API's ZSwState_ERROR because no
		// pillar agent puts an application into that state for a domainmgr
		// failure -- the reported state stays at the last one actually reached
		// (INSTALLED, since the domain is never created). What "fail closed" means
		// operationally is that the workload never ran, so that is what is
		// asserted: never RUNNING and never even BOOTING, alongside the
		// ERROR-severity refusal above. Phase 3 adds the device's own verdict,
		// that zedmanager never considered it activated.
		state := device.GetAppInfo(uuids[i]).GetState()
		evetest.Logger().Infof("%q is reported in state %s after being refused",
			appName, state)
		t.Expect(state).ToNot(Equal(eveinfo.ZSwState_RUNNING),
			"%q is reported as RUNNING although the device refused its placement "+
				"(%s); starting the workload with weaker guarantees than it asked "+
				"for is the one outcome worse than not starting it, because nothing "+
				"anywhere says it happened", appName, request.why)
		t.Expect(state).ToNot(Equal(eveinfo.ZSwState_BOOTING),
			"%q is reported as BOOTING although its placement was refused; the "+
				"domain must never be created for a request the device cannot honour",
			appName)
	}
	logPlacementDiagnostics(device, append([]uuid.UUID{holder.uuid}, uuids...),
		placementShellTimeout)
	evetest.Checkpoint("refusals-reported")

	// Phase 3: the refusals cost nothing. A rejected request that still reserved
	// cores would shrink the node's usable capacity on every failed deploy, and
	// the controller -- which was told the workload did not start -- would have no
	// way of learning where the cores went.
	//
	// The node's own account comes first, because it is what a controller sizes
	// the next deploy against. Held to the baseline across several publish
	// intervals rather than read once, so a report computed before the refused
	// apps existed cannot satisfy it.
	t.Consistently(func(g Gomega) {
		report, err := readCPUPoolReport(device)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(report.dedicated.GetCpuIds()).To(ConsistOf(intsOf(baseDedicated)),
			"the node's dedicated pool changed from %v to %v although every "+
				"application deployed since was refused and never ran; a refused "+
				"request that still reserves cores silently shrinks the node's "+
				"capacity, and nothing tells the controller why",
			baseDedicated, report.dedicated.GetCpuIds())
		g.Expect(report.housekeeping.GetFreeCpuIds()).To(ConsistOf(intsOf(baseFree)),
			"the free housekeeping CPUs changed from %v to %v although every "+
				"application deployed since was refused", baseFree,
			report.housekeeping.GetFreeCpuIds())
		g.Expect(report.housekeeping.GetFreeWholeCores()).To(Equal(baseFreeWholeCores),
			"the node reported %d free whole core(s) before the refused requests "+
				"and %d after; the whole-core count is what bounds how many more "+
				"whole-core workloads fit here, so losing one to a refused request "+
				"costs the node a workload it could have run", baseFreeWholeCores,
			report.housekeeping.GetFreeWholeCores())
	}, refusalPoolStableFor, refusalPoolPolling).Should(Succeed())

	// And the device's own books, for every workload at once. The pool report
	// above is an aggregate; this is where a refused workload individually
	// holding something would show up, and it is also where the holder is checked
	// to be untouched -- refusing a request by disturbing a workload that was
	// already placed would be a different way of making the same mistake, landing
	// the cost of an impossible ask on somebody who asked for something possible.
	residues := readRefusalResidues(t, device,
		append([]uuid.UUID{holder.uuid}, uuids...))

	for i, request := range refused {
		appName := request.spec.appName
		residue := residues[uuids[i].String()]
		// zedmanager's own verdict on whether it brought the workload up. The
		// device-side counterpart of "did not reach RUNNING": the reported state
		// says what the controller was told, this says what the device believes it
		// did. The refusal has to stop the activation, not accompany it.
		t.Expect(residue.App).ToNot(BeNil(),
			"zedmanager published no AppInstanceStatus for %q at all", appName)
		t.Expect(residue.App.Activated).To(BeFalse(),
			"zedmanager considers %q activated although domainmgr refused to place "+
				"it (%s)", appName, request.why)
		// domainmgr does publish a DomainStatus for a workload it refused to
		// place -- that is where the error itself lives -- so this is expected to
		// be present, and its emptiness is the assertion.
		t.Expect(residue.Domain).ToNot(BeNil(),
			"domainmgr published no DomainStatus for %q, so what it recorded for "+
				"the refused workload cannot be checked", appName)
		t.Expect(residue.Domain.CPUs).To(BeEmpty(),
			"%q was refused and never ran, but domainmgr records host CPUs %v for "+
				"it; cores held by a workload the controller believes did not start "+
				"are cores nobody can ever use again", appName, residue.Domain.CPUs)
		t.Expect(residue.Domain.OrderedCPUs).To(BeEmpty(),
			"%q was refused but domainmgr recorded a per-vCPU assignment %v for it",
			appName, residue.Domain.OrderedCPUs)
		t.Expect(residue.Domain.PlacementQuality).To(Equal(placementQualityUnspecified),
			"%q never ran, so it has no placement to rate, but its quality is "+
				"reported as %s; a quality here would have the device publish the "+
				"\"running, but could be packed better\" advisory beside a fatal "+
				"error", appName, placementQualityName(residue.Domain.PlacementQuality))
	}

	t.Expect(device.GetAppInfo(holder.uuid).GetState()).To(Equal(eveinfo.ZSwState_RUNNING),
		"%q was running before the refused applications were deployed and must "+
			"still be running", holderSpec.appName)
	holderNow := residues[holder.uuid.String()].Domain
	t.Expect(holderNow).ToNot(BeNil(),
		"domainmgr no longer publishes a DomainStatus for the running application %q",
		holderSpec.appName)
	t.Expect(holderNow.OrderedCPUs).To(Equal(holderOrdered),
		"%q ran on host CPUs %v before the refused requests and runs on %v after; "+
			"a running workload is never moved, least of all on account of a "+
			"request that was rejected", holderSpec.appName, holderOrdered,
		holderNow.OrderedCPUs)
	t.Expect(subtractCPUs(holderNow.CPUs, holderNow.EmulatorCPUs)).
		To(ConsistOf(intsOf(holderDedicated)),
			"%q occupied host CPUs %v exclusively before the refused requests and "+
				"occupies %v after", holderSpec.appName, holderDedicated,
			subtractCPUs(holderNow.CPUs, holderNow.EmulatorCPUs))
	evetest.Checkpoint("no-residue")

	for _, appUUID := range append([]uuid.UUID{holder.uuid}, uuids...) {
		deleteAppAndWait(t, device, devConfig, appUUID)
	}
}

// oddVCPUWholeCoreApp asks for whole-core-SMT placement with an odd vCPU count.
// The policy is exactly the valid whole-core-SMT one -- only the count is wrong
// -- so the refusal cannot be attributed to anything else in the policy.
func oddVCPUWholeCoreApp(appName string, vCPUs int, sshFwdPort uint16) cpuPlacementApp {
	spec := wholeCoreSMTApp(appName, vCPUs, sshFwdPort)
	spec.mode = "whole-core-smt (odd vCPU count)"
	return spec
}

// hardIsolationApp asks for the hard isolation tier on top of an otherwise valid
// whole-core-SMT request.
//
// The tier is the only defect: the mode, the thread count and the vCPU count are
// all satisfiable, and the request fits the node's free capacity. So if the
// device starts this workload it has delivered soft isolation under the name of
// hard isolation -- the silent downgrade the tier check exists to prevent.
func hardIsolationApp(appName string, vCPUs int, sshFwdPort uint16) cpuPlacementApp {
	spec := wholeCoreSMTApp(appName, vCPUs, sshFwdPort)
	spec.mode = "whole-core-smt + hard isolation tier"
	spec.placement.IsolationTier = eveconfig.IsolationTier_ISOLATION_TIER_HARD
	return spec
}

// invalidThreadsPerCoreApp asks for a threads-per-core the API defines no
// meaning for. A device that quietly rounded it to 1 or 2 would place the
// workload in a mode the controller never asked for.
//
// The harness copies every CPUPlacementConfig field straight into VmConfig
// without validating or clamping it (evetest.CPUPlacementConfig -> toProto), so
// this really does reach the device as threads_per_core=3 -- as do the hard
// isolation tier and the protect disruption policy below. That is deliberate:
// the device has to be the backstop, since a real controller is not obliged to
// pre-validate and a test whose harness sanitized the request would prove
// nothing about the device.
func invalidThreadsPerCoreApp(appName string, vCPUs int,
	sshFwdPort uint16) cpuPlacementApp {
	spec := wholeCoreSMTApp(appName, vCPUs, sshFwdPort)
	spec.mode = fmt.Sprintf("dedicated whole cores, threads_per_core=%d",
		refusalInvalidThreadsPerCore)
	spec.placement.ThreadsPerCore = refusalInvalidThreadsPerCore
	return spec
}

// protectedDisruptionApp asks for the "protect" disruption policy on top of an
// otherwise valid whole-core-SMT request.
//
// This one is a refusal by deliberate choice rather than by impossibility: the
// placement itself is fine, but nothing on the device defers a node-level
// disruptive action, so accepting the field would promise the workload a
// protection it does not have. It is here to keep that choice from silently
// regressing into acceptance -- which is what "unimplemented field is ignored"
// normally decays into.
func protectedDisruptionApp(appName string, vCPUs int, sshFwdPort uint16) cpuPlacementApp {
	spec := wholeCoreSMTApp(appName, vCPUs, sshFwdPort)
	spec.mode = "whole-core-smt + protect disruption policy"
	spec.placement.DisruptionPolicy = eveconfig.DisruptionPolicy_DISRUPTION_POLICY_PROTECT
	return spec
}

// awaitRefusalError blocks until the device reports an error carrying a
// machine-parseable code for the application, and returns every error it
// reported alongside it.
//
// It waits for a *coded* error rather than for any error, because an application
// on its way to being placed can briefly carry unrelated errors from the volume
// or network path, and the first of those arriving would otherwise be mistaken
// for the refusal and fail the code assertion for the wrong reason. A refusal
// that never carries a code at all still fails here -- on the timeout, with the
// errors that were reported quoted in the message, which is the correct verdict:
// an uncoded refusal is exactly the failure this test exists to catch.
func awaitRefusalError(t *GomegaWithT, updates <-chan *eveinfo.ZInfoApp,
	appName string, timeout time.Duration) []*eveinfo.ErrorInfo {
	var reported, lastSeen []*eveinfo.ErrorInfo
	t.Eventually(updates, timeout, placementPolling).Should(Receive(
		matchers.SatisfyPredicate("the device reports a coded error for "+appName,
			func(info *eveinfo.ZInfoApp) bool {
				if len(info.GetAppErr()) > 0 {
					lastSeen = info.GetAppErr()
				}
				for _, appErr := range info.GetAppErr() {
					if appErr.GetErrorCode() != "" {
						reported = info.GetAppErr()
						return true
					}
				}
				return false
			})),
		"the device never reported an error with a machine-parseable code for %q, "+
			"although it cannot honour its placement request; the errors it did "+
			"report were %v. A refusal a controller can only understand by reading "+
			"English prose is not usable: it cannot tell the user what to fix",
		appName, lastSeen)
	for _, appErr := range reported {
		evetest.Logger().Infof("%q reported error: code=%q severity=%s retry=%q "+
			"description=%q", appName, appErr.GetErrorCode(), appErr.GetSeverity(),
			appErr.GetRetryCondition(), appErr.GetDescription())
	}
	return reported
}

// errorWithCode returns the reported error carrying the given code, so severity
// and retry condition are read off the refusal itself rather than off whichever
// error happens to come first.
func errorWithCode(errs []*eveinfo.ErrorInfo, code string) *eveinfo.ErrorInfo {
	for _, appErr := range errs {
		if appErr.GetErrorCode() == code {
			return appErr
		}
	}
	return nil
}

// refusalResidue is everything the device itself records about one workload that
// bears on whether a refusal cost anything: what domainmgr assigned it, and
// whether zedmanager considers it brought up.
//
// Both members are pointers so that "the device published nothing for this
// workload" is distinguishable from "it published an empty allocation". The
// difference matters: the second is the expected outcome of a refusal, while the
// first would mean the assertions below were checking a file that does not
// exist and passing for that reason.
type refusalResidue struct {
	Domain *domainCPUStatus `json:"domain"`
	App    *struct {
		Activated bool
	} `json:"app"`
}

// refusalResidueScript prints one JSON object holding, for each requested
// workload, domainmgr's DomainStatus and zedmanager's AppInstanceStatus -- the
// two pubsub files under /run that say what the device actually did.
//
// It assembles the reply itself instead of the test reading the files one by
// one, because by this point most of the node's CPUs are dedicated to a pinned
// workload and EVE's services share what is left; a short-lived SSH session on
// such a device has been seen dying with "connection reset by peer". Ten reads
// are ten chances to lose one, and per-read retries only spend more sessions --
// so this is one session for the whole set.
//
// Missing files become JSON null rather than an error: the caller distinguishes
// them, and a shell failing halfway would return unparseable output that says
// nothing about which file was the problem.
const refusalResidueScript = `printf '{'
sep=''
for u in @UUIDS@; do
  printf '%s"%s":{"domain":' "$sep" "$u"
  if [ -f "/run/domainmgr/DomainStatus/$u.json" ]; then
    cat "/run/domainmgr/DomainStatus/$u.json"
  else
    printf 'null'
  fi
  printf ',"app":'
  if [ -f "/run/zedmanager/AppInstanceStatus/$u.json" ]; then
    cat "/run/zedmanager/AppInstanceStatus/$u.json"
  else
    printf 'null'
  fi
  printf '}'
  sep=','
done
printf '}'
`

// readRefusalResidues runs that script and returns the result keyed by
// application UUID.
//
// Retried only to absorb an SSH session that failed to come up -- none of the
// values it returns converges, so a device that really did leak a core returns
// the same wrong answer every time and still fails the assertions.
func readRefusalResidues(t *GomegaWithT, device *evetest.EdgeDevice,
	appUUIDs []uuid.UUID) map[string]refusalResidue {

	ids := make([]string, 0, len(appUUIDs))
	for _, appUUID := range appUUIDs {
		ids = append(ids, appUUID.String())
	}
	script := strings.ReplaceAll(refusalResidueScript, "@UUIDS@", strings.Join(ids, " "))

	residues := map[string]refusalResidue{}
	t.Eventually(func(g Gomega) {
		stdout, stderr, err := device.RunShellScript(script, placementShellTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred(),
			"failed to read the pubsub state of %v (stderr: %s)", ids, stderr)
		g.Expect(json.Unmarshal([]byte(stdout), &residues)).To(Succeed(),
			"the device's reply is not the expected JSON document: %q", stdout)
		g.Expect(residues).To(HaveLen(len(ids)))
	}, placementSettleTimeout, placementPolling).Should(Succeed(),
		"the device never returned the recorded CPU state of %v", ids)

	// Logged for every workload before anything is asserted, so a failing run
	// shows what the device recorded for all of them, not only for the first one
	// that broke an assertion.
	for _, id := range ids {
		residue := residues[id]
		if residue.Domain == nil {
			evetest.Logger().Infof("device state for %s: no DomainStatus published "+
				"(activated=%v)", id, residue.App != nil && residue.App.Activated)
			continue
		}
		evetest.Logger().Infof("device state for %s: activated=%v cpus=%v "+
			"emulator=%v ordered=%v quality=%s", id,
			residue.App != nil && residue.App.Activated, residue.Domain.CPUs,
			residue.Domain.EmulatorCPUs, residue.Domain.OrderedCPUs,
			placementQualityName(residue.Domain.PlacementQuality))
	}
	return residues
}
