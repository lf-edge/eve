// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test that a CPU shortage a repack would fix is reported as such -- and that
// the node's own capacity report explains it in whole cores, not free threads.

package apps_test

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// Placement failure codes as they travel on the wire, in
// ZInfoApp.AppErr[].error_code.
//
// Spelled out here rather than imported from pillar's types package for two
// reasons: evetest builds against a released pillar module, which does not carry
// constants added on a feature branch; and these strings *are* the published
// contract a controller matches on, so a test that referenced the device's own
// constant could not notice one of them being renamed under it.
const (
	// errCodeNeedsRepack means the workload would fit if the pinned workloads
	// currently running were restarted together. Actionable.
	errCodeNeedsRepack = "cpu.placement.needs_repack"
	// errCodeInsufficient means no arrangement on this node fits it. Not
	// actionable without changing the node or the request.
	errCodeInsufficient = "cpu.placement.insufficient"
)

const (
	// repackFragmenterVCPUs is the size of each thread-granular workload used to
	// fragment the node, and repackFragmenters how many of them are deployed.
	//
	// Together they must claim every allocatable thread but one, because the
	// thread-granular allocator hands out the lowest-numbered free CPUs: a set of
	// them therefore occupies a contiguous run, and only its top end can leave a
	// core half-owned. On the 8-CPU device below that is 6 of the 7 allocatable
	// threads (cpu0 is reserved for EVE), i.e. three 2-vCPU workloads -- after
	// which stopping one of them opens the gaps this test is about (see
	// chooseFragmentingVictim).
	repackFragmenterVCPUs = 2
	repackFragmenters     = 3
	// repackWholeCoreVCPUs is the whole-core-SMT request that must fail on the
	// fragmented node and succeed after the repack. Two vCPUs = one physical
	// core: the smallest whole-core request there is, so its failure cannot be
	// blamed on the size of the ask.
	repackWholeCoreVCPUs = 2
	// repackOversizedVCPUs is a one-per-core request for more physical cores than
	// the device has at all -- the contrast case, where no repack helps.
	repackOversizedVCPUs = 8
	// repackErrorTimeout bounds waiting for the device to report a placement
	// failure. It covers creating the app's volume from the already-downloaded
	// image, the trip through zedmanager/domainmgr and the info message back.
	repackErrorTimeout = 10 * time.Minute
	// repackStopTimeout bounds one deactivation.
	repackStopTimeout = 5 * time.Minute
)

// TestCPUPlacementNeedsRepack verifies the distinction between the two CPU
// placement failure codes EVE publishes, on a node deliberately fragmented so
// that the distinction is the only thing separating a right answer from a wrong
// one.
//
// The codes exist because a controller has to react differently to them:
// cpu.placement.needs_repack says a placement for this workload does exist and
// is only blocked by where the *running* workloads sit, so restarting the pinned
// workloads together would let it run; cpu.placement.insufficient says nothing
// on this node fits it and only a bigger node or a smaller request will help.
// Reporting the first as the second is not a cosmetic error: the controller's
// one remedy for a fragmented node is a repack, and it has no reason to attempt
// one on a node that says nothing fits.
//
// How a node gets fragmented is the crux, and it is not obvious. A whole-core
// workload takes and releases *whole* physical cores, so no arrangement of
// whole-core workloads can leave a core partly used. Only a thread-granular
// dedicated workload -- CPU_POLICY_DEDICATED without full_pcpus_only -- claims
// individual logical CPUs, and a set of them can leave several cores with one
// thread taken and one free. Such a core is refused to every whole-core request
// (its sibling is not the requester's to have), so the node can hold plenty of
// free threads and yet not a single free whole core. That state is exactly what
// the node's whole-core counters exist to report, and what this test is the
// first to observe end to end.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- placement is not network dependent; a
//     single mgmt+apps port is enough to run the apps and reach one over SSH.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), local NI "local-ni".
//   - timer.deviceinfo.interval lowered to its minimum: the node's CPU pool
//     report rides the periodic ZInfoDevice publish, and phases 2 and 3 assert
//     on it right after a workload stops or fails to start.
//   - 8 CPUs as 4 dual-thread cores. EVE reserves the lowest CPU, which makes
//     its whole core unallocatable, leaving three allocatable cores (six
//     threads) plus the reserved core's free sibling: seven threads a dedicated
//     workload can be given.
//   - Four container apps (lfedge/evetest-ubuntu-ctr), each with its own
//     forwarded SSH port: three thread-granular ones that fragment the node and
//     one whole-core-SMT one that must fail on it, plus -- in phase 4 -- an
//     oversized whole-core app that no node of this size can ever host.
//
// Phases / assertions
// -------------------
//  1. fragmenters-placed: the three thread-granular apps run, each with host
//     CPUs of its own at thread granularity -- pinned, but with no per-vCPU
//     assignment and no synthesized guest SMT topology, which is what makes them
//     able to half-own a core (assertThreadGranularPlacement), and on disjoint
//     CPU sets (assertPlacementSetInvariants).
//  2. node-fragmented: one fragmenter is stopped -- which one is derived from the
//     allocation the device actually made, not assumed -- so that what remains
//     half-owns physical cores. The node must then report zero free whole cores
//     while still reporting more free threads than the whole-core request needs:
//     the condition under which a free-thread count answers "will it fit?"
//     wrongly.
//  3. needs-repack-reported: a 2-vCPU whole-core-SMT app deployed onto that node
//     must fail to start and must report cpu.placement.needs_repack and not
//     cpu.placement.insufficient, with its placement quality left unspecified (it
//     never ran, so it has no placement to rate) and no CPUs held.
//  4. insufficient-reported: a whole-core request for more cores than the device
//     has must report cpu.placement.insufficient -- the other code, from the same
//     boot, so the two are known to be told apart rather than both spelled the
//     same way.
//  5. repack-honoured: the pinned workloads are stopped and started again
//     together, which is the repack the error code asked for. The whole-core app
//     must now run and be validly placed, and so must the fragmenters. This is
//     what turns needs_repack from a label into a checked claim: if the workload
//     still could not run, the node lied to the controller.
//
// Test params
// -----------
//   - HYPERVISOR. Skipped under Kubevirt, where concrete CPU selection belongs
//     to the kubelet rather than to the pillar allocator this test exercises.
//
// Suite placement
// ---------------
//   - TestAppsSuite, with the other CPU placement tests: it wants the same device
//     (8 CPUs, 2 threads per core), so the VM can be reused.
func TestCPUPlacementNeedsRepack(test *testing.T) {
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

	// Checked before anything is deployed: without SMT siblings a core cannot be
	// half-owned at all, so there is no fragmentation to create and every
	// assertion below would either hold vacuously or fail for the wrong reason.
	topo, err := device.HostCPUTopology()
	t.Expect(err).ToNot(HaveOccurred())
	if !deviceHasSMT(topo) {
		evetestT.Skip("the device has no SMT sibling threads, so no physical core can " +
			"be left half-owned and a node cannot be fragmented at all")
	}
	cores := physicalCores(topo)
	evetest.Logger().Infof("device physical cores (as sibling lists): %v", cores)
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// Phases 2 and 3 read the node's CPU pool report, which only reaches the
	// controller on the periodic ZInfoDevice publish; at the 10 minute default
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

	// Phase 1: the workloads that can fragment the node.
	fragmenters := make([]*placedApp, 0, repackFragmenters)
	for i := 0; i < repackFragmenters; i++ {
		spec := threadGranularApp(fmt.Sprintf("cpu-frag-app-%d", i+1),
			repackFragmenterVCPUs, appSSHFwdPort+uint16(i))
		appUUID := devConfig.AddApplication(placementAppConfig(spec, niUUID, 0))
		fragmenters = append(fragmenters, &placedApp{spec: spec, uuid: appUUID})
	}
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("fragmenters-configured")

	waitUntilAppsRunning(device, fragmenters)
	logPlacementDiagnostics(device, appUUIDs(fragmenters), placementShellTimeout)
	for _, app := range fragmenters {
		assertThreadGranularPlacement(t, device, app)
	}
	// Their sets must be disjoint and EVE must still have somewhere to run:
	// everything below reasons about which CPUs are taken, so it is worth
	// nothing if two workloads were handed the same CPU.
	assertPlacementSetInvariants(t, device, topo, fragmenters)
	evetest.Checkpoint("fragmenters-placed")

	// The node's own account while all three run. Also the source of the
	// EVE-reserved CPU set: the housekeeping pool's CPUs that are not reported
	// free are exactly the ones held back for EVE, which is knowledge the
	// simulation below needs and which no test should hard-code.
	running := awaitCPUPoolReport(t, device,
		"all three thread-granular workloads holding their threads",
		func(g Gomega, report cpuPoolReport) {
			for _, app := range fragmenters {
				g.Expect(report.dedicated.GetCpuIds()).To(ContainElements(intsOf(app.dedicated)),
					"the node's dedicated pool %v omits host CPUs %v, which %q holds",
					report.dedicated.GetCpuIds(), app.dedicated, app.spec.appName)
			}
		})
	reserved := subtractCPUs(running.housekeeping.GetCpuIds(),
		running.housekeeping.GetFreeCpuIds())
	evetest.Logger().Infof("CPUs held back for EVE itself: %v", reserved)

	// Phase 2: stop one fragmenter to open the gaps. Which one is derived from
	// the allocation the device made, because the thread-granular allocator's
	// choice of CPUs is not the test's to dictate: releasing the wrong pair
	// would hand back a whole free core and there would be nothing to prove.
	victim, fragmented := chooseFragmentingVictim(t, cores, reserved, fragmenters)
	evetest.Logger().Infof("stopping %q (host CPUs %v) to fragment the node: "+
		"expecting free threads %v, half-owned cores %v and no free whole core",
		victim.spec.appName, victim.dedicated, fragmented.free, fragmented.halfOwned)
	setPlacementAppsActivated(t, device, devConfig, niUUID, []*placedApp{victim}, false)

	var survivors []*placedApp
	for _, app := range fragmenters {
		if app != victim {
			survivors = append(survivors, app)
		}
	}

	// The state the rest of the test depends on, read from the report a
	// controller would use to decide whether another workload fits here. Free
	// threads above the whole-core request while no whole core is free is the
	// interesting condition: a controller counting free threads would answer
	// "yes, it fits" and be wrong.
	fragmentedReport := awaitCPUPoolReport(t, device,
		"free threads but not one free whole core",
		func(g Gomega, report cpuPoolReport) {
			g.Expect(report.housekeeping.GetFreeCpuIds()).To(ContainElements(intsOf(victim.dedicated)),
				"host CPUs %v released by the stopped %q are not reported as free "+
					"(free housekeeping CPUs: %v)", victim.dedicated,
				victim.spec.appName, report.housekeeping.GetFreeCpuIds())
			g.Expect(report.housekeeping.GetFreeWholeCores()).To(BeZero(),
				"the node reports %d free whole core(s) with free threads %v; the "+
					"thread-granular workloads were sized to leave a thread of every "+
					"allocatable core taken, so a free whole core means the node was "+
					"never fragmented and nothing below would be testing the repack "+
					"verdict", report.housekeeping.GetFreeWholeCores(),
				report.housekeeping.GetFreeCpuIds())
		})
	freeThreads := fragmentedReport.housekeeping.GetFreeCpuIds()
	t.Expect(len(freeThreads)).To(BeNumerically(">=", repackWholeCoreVCPUs),
		"the node reports only %d free thread(s) (%v), fewer than the %d vCPUs the "+
			"whole-core workload asks for; the interesting failure is the one where "+
			"a plain free-thread count says the workload fits -- with fewer free "+
			"threads than vCPUs even a naive count would refuse it, and the "+
			"whole-core accounting would not be what made the difference",
		len(freeThreads), freeThreads, repackWholeCoreVCPUs)
	// Fragmentation, stated as such: a core with one thread taken and one free is
	// the thing that cannot arise from whole-core workloads, and the reason the
	// free threads above are unusable for a whole-core request.
	halfOwned := halfOwnedCores(cores, fragmentedReport.dedicated.GetCpuIds(), freeThreads)
	t.Expect(halfOwned).ToNot(BeEmpty(),
		"no physical core has one thread taken and the other free (dedicated %v, "+
			"free %v); without a half-owned core the node is merely full, which is a "+
			"genuine insufficiency rather than the repackable shortage this test is "+
			"about", fragmentedReport.dedicated.GetCpuIds(), freeThreads)
	evetest.Logger().Infof("node fragmented: free threads %v, free whole cores %d, "+
		"half-owned cores %v (dedicated %v)", freeThreads,
		fragmentedReport.housekeeping.GetFreeWholeCores(), halfOwned,
		fragmentedReport.dedicated.GetCpuIds())
	evetest.Checkpoint("node-fragmented")

	// Phase 3: the whole-core workload the node cannot place right now, but could
	// place if the fragmenters were restarted alongside it.
	wholeCoreSpec := wholeCoreSMTApp("cpu-repack-core-app", repackWholeCoreVCPUs,
		appSSHFwdPort+repackFragmenters)
	wholeCore := &placedApp{spec: wholeCoreSpec}
	wholeCore.uuid = devConfig.AddApplication(placementAppConfig(wholeCoreSpec, niUUID, 0))
	// Subscribed before the config is applied, so a failure reported quickly
	// cannot be missed.
	coreUpdates, stopCoreWatch := device.WatchAppInfo(wholeCore.uuid)
	defer stopCoreWatch()
	device.ApplyConfig(devConfig, true, true)

	reported := awaitAppErrors(t, coreUpdates, wholeCoreSpec.appName, repackErrorTimeout)
	codes := errorCodesOf(reported)
	t.Expect(codes).To(ContainElement(errCodeNeedsRepack),
		"%q could not be placed on a node with free threads %v and no free whole "+
			"core, and reported %v; the planned layout for the configured set does "+
			"fit this node, so this is a shortage a repack would fix and the node "+
			"must say so with %q -- a controller told %q has no reason to attempt "+
			"the one remedy it has",
		wholeCoreSpec.appName, freeThreads, codes, errCodeNeedsRepack, errCodeInsufficient)
	t.Expect(codes).ToNot(ContainElement(errCodeInsufficient),
		"%q reported %q alongside %v; the two codes are alternatives -- one says a "+
			"repack would fix this and the other that nothing would -- so reporting "+
			"both leaves the controller no verdict at all",
		wholeCoreSpec.appName, errCodeInsufficient, codes)
	logPlacementDiagnostics(device,
		append(appUUIDs(fragmenters), wholeCore.uuid), placementShellTimeout)

	// A failed placement holds nothing and is rated as nothing. The quality
	// channel describes running workloads: a "needs repack" quality here would
	// have the device publish the "running, but could be packed better" advisory
	// beside a fatal error, telling the controller a workload is up when it is
	// not.
	failedStatus, err := readDomainCPUStatus(device, wholeCore.uuid)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(failedStatus.CPUs).To(BeEmpty(),
		"%q failed to start, so it must hold no host CPUs, but domainmgr records %v",
		wholeCoreSpec.appName, failedStatus.CPUs)
	t.Expect(failedStatus.PlacementQuality).To(Equal(placementQualityUnspecified),
		"%q never started, so it has no placement to rate, but its quality is "+
			"reported as %s", wholeCoreSpec.appName,
		placementQualityName(failedStatus.PlacementQuality))
	t.Expect(device.GetAppInfo(wholeCore.uuid).GetState()).
		ToNot(Equal(eveinfo.ZSwState_RUNNING),
			"%q is reported as running although the device refused to place it",
			wholeCoreSpec.appName)

	// And the node's account is unchanged: a refused workload must not have
	// consumed the capacity it was refused.
	awaitCPUPoolReport(t, device, "the refused workload holding nothing",
		func(g Gomega, report cpuPoolReport) {
			g.Expect(report.housekeeping.GetFreeCpuIds()).To(ConsistOf(intsOf(freeThreads)),
				"the free housekeeping CPUs changed from %v to %v although %q was "+
					"refused and never ran", freeThreads,
				report.housekeeping.GetFreeCpuIds(), wholeCoreSpec.appName)
		})
	evetest.Checkpoint("needs-repack-reported")

	// Phase 4: the other code. A request for more physical cores than the device
	// has cannot be satisfied by any arrangement, so no repack helps and the node
	// must not suggest one. Deployed after the verdict above is recorded, and
	// left in place afterwards: a workload the plan cannot place takes no CPUs
	// from anyone, so it changes nothing for the others.
	oversizedSpec := onePerCoreApp("cpu-repack-oversized-app", repackOversizedVCPUs,
		appSSHFwdPort+repackFragmenters+1)
	oversized := &placedApp{spec: oversizedSpec}
	oversized.uuid = devConfig.AddApplication(placementAppConfig(oversizedSpec, niUUID, 0))
	oversizedUpdates, stopOversizedWatch := device.WatchAppInfo(oversized.uuid)
	defer stopOversizedWatch()
	device.ApplyConfig(devConfig, true, true)

	oversizedCodes := errorCodesOf(awaitAppErrors(t, oversizedUpdates,
		oversizedSpec.appName, repackErrorTimeout))
	t.Expect(oversizedCodes).To(ContainElement(errCodeInsufficient),
		"%q asked for %d dedicated physical cores on a device with %d cores in "+
			"total and reported %v; no arrangement of workloads can satisfy that, so "+
			"the node must report %q and not send the controller repacking a node "+
			"that is not the problem", oversizedSpec.appName, repackOversizedVCPUs,
		len(cores), oversizedCodes, errCodeInsufficient)
	t.Expect(oversizedCodes).ToNot(ContainElement(errCodeNeedsRepack),
		"%q asked for more cores than the device has and reported %q; a repack "+
			"cannot conjure cores, and telling the controller otherwise invites it "+
			"to restart every pinned workload on the node for nothing",
		oversizedSpec.appName, errCodeNeedsRepack)
	evetest.Checkpoint("insufficient-reported")

	// Phase 5: perform the repack the node asked for, and see whether it was
	// telling the truth. Stopping the pinned workloads and starting them again
	// together is exactly what needs_repack advises: the whole-core workload must
	// now get its core, and the fragmenters must still fit around it -- that is
	// what the plan claimed when the device chose the code. If the workload still
	// cannot start, the node reported an actionable failure that no action fixes.
	repacked := append([]*placedApp{wholeCore}, survivors...)
	evetest.Logger().Infof("repacking: stopping and restarting %d pinned workload(s)",
		len(repacked))
	setPlacementAppsActivated(t, device, devConfig, niUUID, repacked, false)
	// Said out loud before the attempt, because a failure to come up here is not
	// a flaky app start: it means the device reported an actionable failure that
	// the prescribed action does not fix.
	evetest.Logger().Infof("starting the pinned workloads together again; %q must now "+
		"be placed -- it reported %s, so a repack is exactly what should let it run",
		wholeCoreSpec.appName, errCodeNeedsRepack)
	setPlacementAppsActivated(t, device, devConfig, niUUID, repacked, true)
	logPlacementDiagnostics(device, appUUIDs(repacked), placementShellTimeout)

	// Placement is verified in full rather than just "it started": a repack that
	// brought the workload up without its whole core, or without the per-vCPU
	// pinning, would have satisfied the promise in name only. Optimality is not
	// required -- the workloads are released together but the device activates
	// them in whatever order it reaches them, so whichever starts first may take
	// a slot the plan set aside for another (see assertAppPlacement).
	assertAppPlacement(t, device, topo, wholeCore, false)
	for _, app := range survivors {
		assertThreadGranularPlacement(t, device, app)
	}
	assertPlacementSetInvariants(t, device, topo, repacked)
	evetest.Checkpoint("repack-honoured")

	for _, app := range append(repacked, victim, oversized) {
		deleteAppAndWait(t, device, devConfig, app.uuid)
	}
}

// assertThreadGranularPlacement verifies one thread-granular dedicated workload:
// it holds host CPUs exclusively, but as individual logical CPUs rather than as
// whole physical cores.
//
// The negative half of this is the interesting half. No per-vCPU assignment and
// no synthesized guest SMT topology is what separates thread granularity from
// whole-core placement, and it is precisely why such a workload can leave a core
// half-owned: it never asks for the sibling. A regression that quietly promoted
// these workloads to whole-core placement would make the node impossible to
// fragment, and every fragmentation test would then pass by never reaching the
// state it means to test.
func assertThreadGranularPlacement(t *GomegaWithT, device *evetest.EdgeDevice,
	app *placedApp) {
	spec := app.spec
	t.Eventually(func(g Gomega) {
		status, err := readDomainCPUStatus(device, app.uuid)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(status.CPUs).ToNot(BeEmpty(),
			"domainmgr recorded no CPU set at all for %s", spec.appName)
		app.status = status
	}, placementSettleTimeout, placementPolling).Should(Succeed())

	status := app.status
	app.dedicated = subtractCPUs(status.CPUs, status.EmulatorCPUs)
	evetest.Logger().Infof("thread-granular placement for %q: dedicated host CPUs %v "+
		"(emulator CPUs %v), pinned=%v, quality=%s", spec.appName, app.dedicated,
		status.EmulatorCPUs, status.CPUsPinned,
		placementQualityName(status.PlacementQuality))

	t.Expect(status.CPUsPinned).To(BeTrue(),
		"a dedicated CPU policy must give %q host CPUs of its own even without "+
			"full_pcpus_only, and must do so without the legacy pin_cpu flag",
		spec.appName)
	t.Expect(app.dedicated).To(HaveLen(spec.vCPUs),
		"%q asked for %d vCPUs at thread granularity, so it must hold exactly that "+
			"many host CPUs, not %v", spec.appName, spec.vCPUs, app.dedicated)
	t.Expect(uniqueCPUs(app.dedicated)).To(HaveLen(spec.vCPUs),
		"the same host CPU must not be counted twice for %q (dedicated: %v)",
		spec.appName, app.dedicated)
	t.Expect(status.OrderedCPUs).To(BeEmpty(),
		"%q asked for dedicated CPUs without full_pcpus_only, so no vCPU may be "+
			"bound to a fixed host CPU (recorded: %v); pinning per vCPU here would "+
			"mean the workload was given whole-core treatment it did not ask for",
		spec.appName, status.OrderedCPUs)
	t.Expect(status.VMTopology.Threads).To(BeZero(),
		"%q holds individual SMT threads, which nothing guarantees are siblings, so "+
			"it must keep the flat guest topology; a synthesized threads=%d would "+
			"tell the guest its vCPUs share a core when they may not",
		spec.appName, status.VMTopology.Threads)
	t.Expect(status.PlacementQuality).To(Equal(placementQualityUnspecified),
		"%q is not whole-core placed, so there is no whole-core layout to rate it "+
			"against and its quality must not be reported as %s", spec.appName,
		placementQualityName(status.PlacementQuality))

	// The kernel enforces it as a cpuset covering exactly those CPUs, and the
	// vCPUs float within it -- which is all thread granularity promises. Both are
	// read inside one Eventually so they cannot describe different moments.
	t.Eventually(func(g Gomega) {
		cpuset, err := device.AppCPUSet(app.uuid)
		g.Expect(err).ToNot(HaveOccurred())
		affinities, err := device.AppVCPUAffinities(app.uuid)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(affinities).To(HaveLen(spec.vCPUs))
		g.Expect(cpuset).To(ConsistOf(intsOf(app.dedicated)),
			"the cpuset %v of %q must be exactly its dedicated CPUs %v: wider and it "+
				"runs on CPUs the node considers free, narrower and it cannot use "+
				"what it was given", cpuset, spec.appName, app.dedicated)
		for vcpu, allowed := range affinities {
			g.Expect(allowed).To(ConsistOf(intsOf(app.dedicated)),
				"guest vCPU %d of %q may run on %v while the workload holds %v; a "+
					"thread-granular workload's vCPUs are confined to its own CPUs and "+
					"free to move within them", vcpu, spec.appName, allowed, app.dedicated)
		}
		app.cpuset = cpuset
	}, placementSettleTimeout, placementPolling).Should(Succeed())
	evetest.Logger().Infof("cpuset for %q: %v", spec.appName, app.cpuset)
}

// nodeShape is what a set of dedicated CPUs leaves of the node's physical cores,
// computed from the topology rather than read from EVE -- so it can be used to
// predict the outcome of stopping a workload before stopping it.
type nodeShape struct {
	// free is every logical CPU that is neither dedicated to a workload nor held
	// back for EVE, i.e. what could still be handed out.
	free []uint32
	// freeWhole is one representative CPU per physical core all of whose threads
	// are free. This -- not len(free) -- bounds how many more whole-core
	// workloads fit.
	freeWhole []uint32
	// halfOwned is one representative CPU per physical core with at least one
	// thread taken and at least one free. Such a core is the fingerprint of
	// thread-granular allocation, and is refused to every whole-core request.
	halfOwned []uint32
}

// shapeOf classifies every physical core against a dedicated and a reserved set.
func shapeOf(cores [][]uint32, dedicated, reserved []uint32) nodeShape {
	isDedicated := cpuSetOf(dedicated)
	isReserved := cpuSetOf(reserved)
	var shape nodeShape
	for _, core := range cores {
		var taken, free []uint32
		for _, cpu := range core {
			switch {
			case isDedicated[cpu]:
				taken = append(taken, cpu)
			case !isReserved[cpu]:
				free = append(free, cpu)
			}
		}
		shape.free = append(shape.free, free...)
		switch {
		case len(free) == len(core):
			shape.freeWhole = append(shape.freeWhole, core[0])
		case len(taken) > 0 && len(free) > 0:
			shape.halfOwned = append(shape.halfOwned, core[0])
		}
	}
	return shape
}

// chooseFragmentingVictim picks the thread-granular workload whose stopping
// leaves the node fragmented: no free whole core, yet more free threads than a
// whole-core request needs.
//
// It is a choice rather than a constant because the thread-granular allocator
// decides which CPUs each workload gets, and the workloads activate
// concurrently, so which of them ended up holding which pair is not the test's
// to dictate. Releasing the wrong pair hands back a complete free core and the
// whole-core workload below would simply start -- proving nothing. Simulating
// each candidate against the observed allocation is what makes the fragmented
// state reachable on every run instead of two runs in three.
func chooseFragmentingVictim(t *GomegaWithT, cores [][]uint32, reserved []uint32,
	apps []*placedApp) (*placedApp, nodeShape) {
	var all []uint32
	for _, app := range apps {
		all = append(all, app.dedicated...)
	}
	var best *placedApp
	var bestShape nodeShape
	for _, app := range apps {
		shape := shapeOf(cores, subtractCPUs(all, app.dedicated), reserved)
		evetest.Logger().Infof("stopping %q (host CPUs %v) would leave free threads %v, "+
			"free whole cores %v, half-owned cores %v", app.spec.appName, app.dedicated,
			shape.free, shape.freeWhole, shape.halfOwned)
		if len(shape.freeWhole) > 0 || len(shape.halfOwned) == 0 ||
			len(shape.free) < repackWholeCoreVCPUs {
			continue
		}
		// Prefer the candidate that half-owns the most cores: that is the
		// starkest form of the state -- every allocatable core carrying one
		// thread of somebody's workload and one thread nobody can use.
		if best == nil || len(shape.halfOwned) > len(bestShape.halfOwned) {
			best, bestShape = app, shape
		}
	}
	t.Expect(best).ToNot(BeNil(),
		"no thread-granular workload could be stopped to leave the node fragmented: "+
			"the ones deployed hold %v of a node whose cores are %v (reserved for "+
			"EVE: %v), and releasing any one of them either frees a whole core or "+
			"leaves too few free threads. The sizing above (see "+
			"repackFragmenterVCPUs) assumes a device with four dual-thread cores, "+
			"one CPU of which EVE reserves; on a differently sized device it has to "+
			"be recomputed", all, cores, reserved)
	return best, bestShape
}

// setPlacementAppsActivated flips the Activate flag of the given applications in
// one configuration change and waits until the device reports each of them in
// the state that change asks for.
//
// The local configuration is the authority here rather than
// EdgeDevice.ActivateApplication: the test adds applications to it between these
// calls, and mixing the two would silently re-activate a workload that was
// deliberately stopped.
func setPlacementAppsActivated(t *GomegaWithT, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig, niUUID uuid.UUID,
	apps []*placedApp, activate bool) {
	updates := make([]<-chan *eveinfo.ZInfoApp, 0, len(apps))
	for _, app := range apps {
		// Subscribed before the config change: the transition must not be missed
		// while the device is applying it.
		appUpdates, stop := device.WatchAppInfo(app.uuid)
		defer stop()
		updates = append(updates, appUpdates)

		config := placementAppConfig(app.spec, niUUID, 0)
		config.Activate = activate
		devConfig.UpdateApplication(app.uuid, config)
	}
	device.ApplyConfig(devConfig, true, true)

	for i, app := range apps {
		if activate {
			device.WaitUntilAppIsRunning(app.uuid, placementRunningTimeout)
			continue
		}
		// HALTED is the device's statement that the workload is down and has
		// given its CPUs back, which is what the phases here depend on -- a
		// config the device merely received would not do.
		t.Eventually(updates[i], repackStopTimeout, placementPolling).Should(
			Receive(matchers.SatisfyPredicate(
				"the application is reported as stopped",
				func(info *eveinfo.ZInfoApp) bool {
					return info.GetState() == eveinfo.ZSwState_HALTED
				})),
			"%q was deactivated but the device never reported it as halted",
			app.spec.appName)
	}
}

// awaitAppErrors blocks until the device reports at least one error for the
// application and returns the errors it reported.
//
// Read from the app's info message rather than from any device-internal state,
// because the question this test asks -- can a controller tell the two failures
// apart? -- is only meaningful about what actually reaches the controller.
func awaitAppErrors(t *GomegaWithT, updates <-chan *eveinfo.ZInfoApp,
	appName string, timeout time.Duration) []*eveinfo.ErrorInfo {
	var reported []*eveinfo.ErrorInfo
	t.Eventually(updates, timeout, placementPolling).Should(Receive(
		matchers.SatisfyPredicate("the device reports an error for "+appName,
			func(info *eveinfo.ZInfoApp) bool {
				if len(info.GetAppErr()) == 0 {
					return false
				}
				reported = info.GetAppErr()
				return true
			})),
		"the device never reported any error for %q, although it cannot place it",
		appName)
	for _, appErr := range reported {
		evetest.Logger().Infof("%q reported error: code=%q severity=%s retry=%q "+
			"description=%q", appName, appErr.GetErrorCode(), appErr.GetSeverity(),
			appErr.GetRetryCondition(), appErr.GetDescription())
	}
	return reported
}

// errorCodesOf lists the machine-parseable codes of the reported errors. An
// error without a code is reported as the empty string rather than dropped, so
// "the failure carried no code at all" shows up in the assertion message.
func errorCodesOf(errs []*eveinfo.ErrorInfo) []string {
	codes := make([]string, 0, len(errs))
	for _, appErr := range errs {
		codes = append(codes, appErr.GetErrorCode())
	}
	return codes
}

// halfOwnedCores returns one representative CPU per physical core with at least
// one thread dedicated to a workload and at least one thread free, derived from
// the node's own pool report so that the report and the topology are checked
// against each other rather than the topology alone.
func halfOwnedCores(cores [][]uint32, dedicated, free []uint32) []uint32 {
	isDedicated := cpuSetOf(dedicated)
	isFree := cpuSetOf(free)
	var out []uint32
	for _, core := range cores {
		var taken, spare int
		for _, cpu := range core {
			if isDedicated[cpu] {
				taken++
			}
			if isFree[cpu] {
				spare++
			}
		}
		if taken > 0 && spare > 0 {
			out = append(out, core[0])
		}
	}
	return out
}

// physicalCores groups the device's logical CPUs into physical cores, each as
// its ascending sibling list, cores ordered by their lowest sibling.
func physicalCores(topo evetest.HostTopology) [][]uint32 {
	var cores [][]uint32
	seen := map[uint32]bool{}
	for _, cpu := range topo.IDs() {
		if seen[cpu] {
			continue
		}
		siblings := topo.SiblingsOf(cpu)
		if len(siblings) == 0 {
			siblings = []uint32{cpu}
		}
		for _, sibling := range siblings {
			seen[sibling] = true
		}
		cores = append(cores, siblings)
	}
	return cores
}

func cpuSetOf(cpus []uint32) map[uint32]bool {
	set := make(map[uint32]bool, len(cpus))
	for _, cpu := range cpus {
		set[cpu] = true
	}
	return set
}
