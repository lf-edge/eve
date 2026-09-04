// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test that a CPU placement, once decided, is a property of the set of
// applications currently claiming CPUs rather than of the history that produced
// it -- and that an application which stops really does give its CPUs back.

package apps_test

import (
	"encoding/json"
	"fmt"
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

const (
	// stabilityStartDelay is how long the delayed application is held back
	// after the device boots. It must comfortably exceed the time EVE needs to
	// bring the other applications up -- their images are already on the device
	// by then, so that is well under a minute -- because the phase only proves
	// anything if the others really are running while this one is still
	// waiting. It is also time the test spends idle, so it is no longer than
	// that argument requires.
	stabilityStartDelay = 3 * time.Minute
	// stabilityStartDelayTimeout bounds waiting for the delayed application to
	// be released; it has to cover the delay itself plus the start.
	stabilityStartDelayTimeout = stabilityStartDelay + placementRunningTimeout
	// stabilityDelayReportTimeout bounds waiting for the device to report the
	// delayed application as held back after a reboot.
	stabilityDelayReportTimeout = 5 * time.Minute
	// stabilityAppRestartTimeout bounds one deactivate/activate round trip.
	stabilityAppRestartTimeout = 5 * time.Minute
)

// TestCPUPlacementStability verifies that the host CPUs a pinned application
// runs on are decided by *which applications are running or waiting to run*,
// and not by the history of how they got there -- neither by a reboot, nor by
// the order in which they start, nor by one of them being restarted.
//
// This is the property the batch planner exists to provide (see
// cpuallocator.Plan and docs/cpu-affinity-design.md §7). The plan is not
// persisted: it is recomputed from the app configs and the topology on every
// pinned activation, over the set of *activated* applications, and a workload
// claims the slot the plan set aside for it when it starts. Three things
// follow, and none of them is visible to a test that deploys a set once and
// looks at it once:
//
//   - The same configured set must yield the same assignment on every boot, or
//     an application's cores silently move under it across a reboot -- exactly
//     the thing a workload that was tuned (IRQ affinity, guest-side pinning,
//     NUMA-local buffers) for those cores cannot tolerate.
//   - An application that starts late must find its cores waiting for it. Under
//     greedy per-activation allocation whoever started first won the scarce
//     cores, so a delayed application could arrive to find the only core it can
//     use already taken. That race is the reason planning is done over the whole
//     set at once.
//   - Restarting one application must not disturb the others, and must give it
//     its own CPUs back: everything else keeps holding what it holds, so the
//     plan the restarted workload arrives into is the same one it left.
//
// The converse is equally deliberate, and phase 4 below exists to keep it from
// being "fixed" into a stability claim: a *stopped* application releases its
// CPUs, exactly as it releases an assigned PCI device. It is not in the demand
// set while it is stopped, so it holds nothing, and the cores it used to own
// are genuinely available to anything else the controller deploys. A node with
// the capacity for a workload must never refuse it because of an application
// that is not running.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- placement is not network dependent; a
//     single mgmt+apps port is enough to run the apps and reach them over SSH.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), local NI "local-ni".
//   - timer.deviceinfo.interval lowered to its minimum, so the node's CPU pool
//     report (ZInfoDevice.cpu_pools) follows a workload stopping promptly.
//   - 8 CPUs as 4 dual-thread cores. EVE reserves the lowest core, leaving
//     three allocatable ones: one for the whole-core-SMT app, two for the
//     one-per-core app. The set therefore fills the machine exactly, which is
//     what makes the ordering questions meaningful -- there is no spare core to
//     absorb a workload that took somebody else's.
//   - A best-effort app shares the reserved core with EVE, and is there to
//     confirm the housekeeping side of each phase still holds.
//
// Phases / assertions
// -------------------
//  1. baseline: all three apps deployed together and verified with the same
//     per-app and set-wide checks the other placement tests use.
//  2. reboot: the device is rebooted with the configuration unchanged. Every
//     pinned app must come back on exactly the same host CPUs, with per-vCPU
//     1:1 affinity re-established -- not merely a matching cpuset, which would
//     leave the vCPUs free to float within it.
//  3. restart under load: one pinned app -- the whole-core-SMT one -- is
//     stopped while the other keeps running. While it is down its cores must be
//     *released*: gone from the node's dedicated pool, back in the free
//     housekeeping pool, one more whole core reported free, and claimed by
//     nobody else, while the app that kept running keeps exactly the CPUs it
//     had. Started again, it must come back on exactly the same host CPUs,
//     because the running app still pins the rest of the layout.
//  4. reverse restart: both pinned apps are stopped and started again in
//     the opposite order. The resulting placement must be *valid*; it is
//     deliberately not required to equal the baseline, and this phase is left
//     out of the cross-phase comparison. See the phase itself for why.
//  5. delayed start: the whole-core-SMT app is given a start delay and the
//     device is rebooted. The other apps demonstrably start first (the delayed
//     one is reported START_DELAYED while they are RUNNING), and the delayed app
//     must still get its own CPUs back. It is the whole-core-SMT app that is
//     delayed on purpose: it is the most constrained workload, so it is the one
//     a greedy allocator would strand. It runs last because it is the only phase
//     that leans on a second EVE mechanism -- the start delay -- and a device
//     that fails to honor that would otherwise take the earlier verdicts with it.
//
// Every phase re-runs the full structural verification, so a phase can also
// catch a placement that is stable but wrong (e.g. the same CPUs, no longer
// pinned 1:1 after a reboot).
//
// Every phase that observes the set with *everything still holding its CPUs* is
// compared against every such phase before it -- they all observe the same
// running set, so they must all agree, and which of them is "right" is not the
// question. Phase 4, the reverse restart, is the one exception and is excluded
// from the comparison entirely, for the reason given there. A disagreement fails
// the test without stopping it: each phase costs a device boot, so a run that
// stopped at the first one would report a single broken property and hide the
// others.
//
// Test params
// -----------
//   - HYPERVISOR. Skipped under Kubevirt, where concrete CPU selection belongs
//     to the kubelet rather than to the pillar allocator this test exercises.
//
// Suite placement
// ---------------
//   - TestAppsSuite, right after the other CPU placement tests: it wants the
//     same device (8 CPUs, 2 threads per core), so the VM can be reused.
func TestCPUPlacementStability(test *testing.T) {
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
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// The node's CPU pool report rides on ZInfoDevice, and a change to it is not
	// itself a publish trigger, so without this the release assertions of phase
	// 3 would be waiting on the 10 minute default publish interval.
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

	// Deployed in this order, so that phase 4's reverse order really is the
	// adversarial one: the flexible one-per-core app activating before the
	// whole-core-SMT app that can only use a genuine two-thread core.
	smtSpec := wholeCoreSMTApp("cpu-stable-smt-app", 2, appSSHFwdPort)
	coreSpec := onePerCoreApp("cpu-stable-core-app", 2, appSSHFwdPort+1)
	sharedSpec := sharedApp("cpu-stable-shared-app", 1, appSSHFwdPort+2)

	deployed := make([]*placedApp, 0, 3)
	for _, spec := range []cpuPlacementApp{smtSpec, coreSpec, sharedSpec} {
		appUUID := devConfig.AddApplication(placementAppConfig(spec, niUUID, 0))
		deployed = append(deployed, &placedApp{spec: spec, uuid: appUUID})
	}
	smtApp, coreApp, sharedInst := deployed[0], deployed[1], deployed[2]
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")

	// Phase 1: the first observation of the set; every later phase must agree
	// with it, and with each other.
	waitUntilAppsRunning(device, deployed)
	verifyPlacement(t, device, deployed, "baseline", true)
	violations := placementViolations{t: evetestT}
	violations.compare("baseline", deployed)
	evetest.Checkpoint("baseline-recorded")

	// Phase 2: a reboot changes nothing about the configured set, so it must
	// change nothing about the placement either.
	evetest.Logger().Infof("Rebooting the device with the placement unchanged")
	device.SoftReboot(true)
	waitUntilPlacementRestored(t, device, deployed)
	verifyPlacement(t, device, deployed, "after-reboot", true)
	violations.compare("after-reboot", deployed)
	evetest.Checkpoint("reboot-placement-verified")

	// Phase 3: restart one pinned app while the other keeps running.
	//
	// This is the strong form of the stability property, and the one EVE really
	// owes a workload: the one-per-core app never stops, so it goes on holding
	// its cores; the set of activated apps is otherwise unchanged; and the plan
	// is a function of that set. The restarted app must therefore land back on
	// exactly the CPUs it left -- same host CPUs, same vCPU order, same parked
	// siblings.
	//
	// The whole-core-SMT app is the one restarted, for two reasons: it is the
	// most constrained workload (it needs a core with two real hardware
	// threads), so it is the one a greedy allocator would fail to hand its cores
	// back to; and stopping it releases a whole physical core, which is what
	// makes the release assertions below crisp.
	//
	// The best-effort app keeps running throughout -- it holds no dedicated
	// CPUs, and leaving it up keeps the housekeeping side of the invariants
	// under test.
	restarted, kept := smtApp, coreApp
	released := append([]uint32(nil), restarted.dedicated...)
	keptDedicated := append([]uint32(nil), kept.dedicated...)
	keptOrdered := append([]uint32(nil), kept.status.OrderedCPUs...)

	// What the node says while both are up. This also cross-checks the node-wide
	// report against domainmgr's per-app status -- a report that did not account
	// for the running workloads would make the release assertions meaningless.
	poolsWhileRunning := awaitCPUPoolReport(t, device,
		"both pinned applications holding their CPUs",
		func(g Gomega, report cpuPoolReport) {
			g.Expect(report.dedicated.GetCpuIds()).To(ContainElements(intsOf(released)),
				"the node's dedicated pool %v omits CPUs %v, which %q holds",
				report.dedicated.GetCpuIds(), released, restarted.spec.appName)
			g.Expect(report.dedicated.GetCpuIds()).To(ContainElements(intsOf(keptDedicated)),
				"the node's dedicated pool %v omits CPUs %v, which %q holds",
				report.dedicated.GetCpuIds(), keptDedicated, kept.spec.appName)
		})

	evetest.Logger().Infof("Stopping %q while %q keeps running",
		restarted.spec.appName, kept.spec.appName)
	device.DeactivateApplication(restarted.uuid, true, stabilityAppRestartTimeout)

	// A stopped application releases its CPUs, exactly as it releases an
	// assigned PCI device: it is no longer in the demand set, so it holds
	// nothing. Asserted explicitly, because the whole point of releasing is that
	// a node with the capacity for a workload must not refuse it on account of
	// an application that is not running.
	t.Eventually(func(g Gomega) {
		status, err := readDomainCPUStatus(device, restarted.uuid)
		if err != nil {
			// The DomainStatus went away with the domain, which is the clearest
			// possible statement that nothing is claimed.
			return
		}
		g.Expect(status.CPUs).To(BeEmpty(),
			"%q is stopped but domainmgr still records host CPUs %v for it",
			restarted.spec.appName, status.CPUs)
	}, stabilityAppRestartTimeout, placementPolling).Should(Succeed())

	// Nobody else may have picked the freed CPUs up either: a running workload
	// is never moved, so the app that kept running must hold exactly what it
	// held before, and in the same vCPU order.
	keptNow, err := readDomainCPUStatus(device, kept.uuid)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(keptNow.OrderedCPUs).To(Equal(keptOrdered),
		"%q kept running while %q was stopped, so its own placement must not have "+
			"changed: it ran on %v and now runs on %v",
		kept.spec.appName, restarted.spec.appName, keptOrdered, keptNow.OrderedCPUs)
	keptNowDedicated := subtractCPUs(keptNow.CPUs, keptNow.EmulatorCPUs)
	t.Expect(intersectCPUs(released, keptNowDedicated)).To(BeEmpty(),
		"%q took over host CPUs %v released by the stopped %q; released CPUs "+
			"become free capacity, they are not handed to a running workload",
		kept.spec.appName, intersectCPUs(released, keptNowDedicated),
		restarted.spec.appName)

	// And the node must say so to the controller: this is the report a
	// controller reads to decide whether another workload fits here.
	poolsWhileStopped := awaitCPUPoolReport(t, device,
		"the stopped application's CPUs back as free capacity",
		func(g Gomega, report cpuPoolReport) {
			g.Expect(intersectCPUs(released, report.dedicated.GetCpuIds())).To(BeEmpty(),
				"host CPUs %v are still reported as dedicated although %q, which held "+
					"them, is stopped (dedicated pool: %v)",
				intersectCPUs(released, report.dedicated.GetCpuIds()),
				restarted.spec.appName, report.dedicated.GetCpuIds())
			g.Expect(report.housekeeping.GetFreeCpuIds()).To(ContainElements(intsOf(released)),
				"host CPUs %v released by the stopped %q are not reported as free "+
					"(free housekeeping CPUs: %v)", released, restarted.spec.appName,
				report.housekeeping.GetFreeCpuIds())
			g.Expect(report.dedicated.GetCpuIds()).To(ContainElements(intsOf(keptDedicated)),
				"the node stopped reporting CPUs %v as dedicated although %q is still "+
					"running on them (dedicated pool: %v)", keptDedicated,
				kept.spec.appName, report.dedicated.GetCpuIds())
		})
	// Free threads alone would not prove the capacity is usable: what the
	// stopped workload gave back is a whole physical core, and only the
	// whole-core count says another whole-core workload could now be deployed
	// here -- which is the property an operator actually cares about.
	t.Expect(poolsWhileStopped.housekeeping.GetFreeWholeCores()).To(BeNumerically(">",
		poolsWhileRunning.housekeeping.GetFreeWholeCores()),
		"%q gave back the whole physical core behind host CPUs %v, so the node must "+
			"report more free whole cores than the %d it reported while the app was "+
			"running, but it reports %d", restarted.spec.appName, released,
		poolsWhileRunning.housekeeping.GetFreeWholeCores(),
		poolsWhileStopped.housekeeping.GetFreeWholeCores())
	evetest.Checkpoint("stopped-app-released-cpus")

	evetest.Logger().Infof("Starting %q again", restarted.spec.appName)
	device.ActivateApplication(restarted.uuid, true, stabilityAppRestartTimeout)
	verifyPlacement(t, device, deployed, "after-single-app-restart", true)
	violations.compare("after-single-app-restart", deployed)
	// The report has to follow a workload taking CPUs just as it followed one
	// giving them up; a report that only ever grows would pass everything above.
	awaitCPUPoolReport(t, device, "the restarted application's CPUs claimed again",
		func(g Gomega, report cpuPoolReport) {
			g.Expect(report.dedicated.GetCpuIds()).To(ContainElements(intsOf(released)),
				"%q is running on host CPUs %v again, but the node's dedicated pool "+
					"is %v", restarted.spec.appName, released,
				report.dedicated.GetCpuIds())
		})
	evetest.Checkpoint("single-app-restart-placement-verified")

	// Phase 4: stop *both* pinned apps and start them again in the opposite
	// order, with the flexible one-per-core app going first.
	//
	// The result must be a valid placement -- every per-app and set-wide
	// invariant still holds -- but it is deliberately NOT required to equal the
	// baseline, and the phase is deliberately left out of the cross-phase
	// comparison. Please do not "fix" that back.
	//
	// The reason is the release semantics phase 3 just asserted. With both
	// pinned apps stopped their cores are genuinely unowned, and the demand set
	// contains only activated apps, so the first one to come back is planned as
	// if it were alone on the node -- because it is. It may claim a slot the
	// full plan would have set aside for the other, and the one starting second
	// can then only take what is still free. That is a correct outcome, not a
	// stability violation: the alternative would be for a stopped application to
	// keep reserving CPUs nobody is using, which is precisely what EVE refuses
	// to do. Placement quality is likewise not required to be optimal here --
	// "needs-repack" is the node correctly reporting this situation.
	evetest.Logger().Infof("Restarting the pinned applications in reverse order")
	for _, app := range []*placedApp{smtApp, coreApp} {
		device.DeactivateApplication(app.uuid, true, stabilityAppRestartTimeout)
	}
	for _, app := range []*placedApp{coreApp, smtApp} {
		device.ActivateApplication(app.uuid, true, stabilityAppRestartTimeout)
	}
	verifyPlacement(t, device, deployed, "after-reverse-restart", false)
	evetest.Checkpoint("reverse-order-placement-verified")

	// Phase 5: the same set, but one pinned app is held back so the others are
	// already running when it starts. Its cores must have been kept for it.
	//
	// Last, because it is the phase that depends on a second EVE mechanism (the
	// start delay) rather than on placement alone: if the device fails to honor
	// the delay, this phase cannot reach its placement assertion at all, and the
	// verdicts of the earlier phases would be lost with it.
	evetest.Logger().Infof("Giving %q a %s start delay and rebooting",
		smtApp.spec.appName, stabilityStartDelay)
	devConfig.UpdateApplication(smtApp.uuid, placementAppConfig(smtSpec, niUUID,
		uint32(stabilityStartDelay.Seconds())))
	device.ApplyConfig(devConfig, true, true)

	// Subscribed before the reboot so the transition into START_DELAYED cannot
	// be missed while the device is away.
	delayedUpdates, stopDelayedWatch := device.WatchAppInfo(smtApp.uuid)
	defer stopDelayedWatch()
	device.SoftReboot(true)

	// Check what the device decided the start moment is before waiting on the
	// state it should produce. It separates the two ways this phase can fail: a
	// delay that was honored but turned out too short to stagger anything, and a
	// delay the device dropped -- the latter shows up as a start moment derived
	// from the zero time, which no clock can produce.
	var startTime time.Time
	t.Eventually(func(g Gomega) {
		var err error
		startTime, err = appStartTime(device, smtApp.uuid)
		g.Expect(err).ToNot(HaveOccurred())
	}, stabilityDelayReportTimeout, placementPolling).Should(Succeed())
	evetest.Logger().Infof("the device will start %q at %s", smtApp.spec.appName, startTime)
	t.Expect(startTime).To(BeTemporally(">", time.Now()),
		"the device recorded %s as the moment %q may start; a %s delay configured "+
			"for a fresh boot must land in the future, and a start moment at (or "+
			"near) the zero time means the configured delay was dropped rather "+
			"than applied", startTime, smtApp.spec.appName, stabilityStartDelay)

	// The device must also report the app as held back. The app was RUNNING when
	// the reboot was issued, so a START_DELAYED report can only be post-reboot.
	t.Eventually(delayedUpdates, stabilityDelayReportTimeout).Should(
		Receive(matchers.SatisfyPredicate(
			"the start-delayed application is reported as held back",
			func(info *eveinfo.ZInfoApp) bool {
				return info.GetState() == eveinfo.ZSwState_START_DELAYED
			})),
		"%q was configured with a %s start delay but the device never reported "+
			"it as delayed after the reboot", smtApp.spec.appName, stabilityStartDelay)

	waitUntilPlacementRestored(t, device, []*placedApp{coreApp, sharedInst})
	// The evidence that this phase tests what it claims to: the others are up
	// and the delayed one has not started, so whatever it gets next, it gets
	// after them.
	t.Expect(device.GetAppInfo(smtApp.uuid).GetState()).
		To(Equal(eveinfo.ZSwState_START_DELAYED),
			"%q must still be held back while the other applications are running, "+
				"otherwise this phase does not exercise a staggered start at all",
			smtApp.spec.appName)
	logPlacementDiagnostics(device, appUUIDs(deployed), placementShellTimeout)
	evetest.Checkpoint("delayed-app-held-back")

	device.WaitUntilAppIsRunning(smtApp.uuid, stabilityStartDelayTimeout)
	verifyPlacement(t, device, deployed, "after-delayed-start", true)
	violations.compare("after-delayed-start", deployed)
	evetest.Checkpoint("delayed-start-placement-verified")

	for _, app := range deployed {
		deleteAppAndWait(t, device, devConfig, app.uuid)
	}
}

// placementAppConfig builds the deployable configuration for one placement app
// spec. The whole configuration has to be reproducible from the spec because
// UpdateApplication takes a complete ApplicationInstanceConfig and refuses any
// change to the fixed resources -- so changing only the start delay means
// rebuilding everything else identically.
func placementAppConfig(spec cpuPlacementApp, niUUID uuid.UUID,
	startDelaySeconds uint32) evetest.ApplicationInstanceConfig {
	return evetest.ApplicationInstanceConfig{
		DisplayName:         spec.appName,
		Activate:            true,
		Image:               evetest.DockerContainer{ImageName: ubuntuCtrImage, Tag: ubuntuCtrTag},
		VirtualizationMode:  eveconfig.VmMode_HVM,
		CPUs:                uint(spec.vCPUs),
		MemoryBytes:         512 * evetest.MiB,
		NetworkAdapters:     singleVIFWithSSHOnPort(niUUID, spec.sshFwdPort),
		CPUPlacement:        spec.placement,
		StartDelayInSeconds: startDelaySeconds,
	}
}

// waitUntilAppsRunning blocks until every deployed application is running.
func waitUntilAppsRunning(device *evetest.EdgeDevice, deployed []*placedApp) {
	for _, app := range deployed {
		device.WaitUntilAppIsRunning(app.uuid, placementRunningTimeout)
	}
}

// waitUntilPlacementRestored blocks until the device itself shows every
// application placed again, and only then waits for them to be reported as
// running.
//
// The order matters after a reboot, and only after a reboot. The controller's
// last word on an application is from before the reboot -- RUNNING -- and
// WaitUntilAppIsRunning is satisfied by an application whose latest known state
// is RUNNING, so on its own it would return while the device is still bringing
// the workloads back, and the test would then read the placement of domains
// that do not exist yet. /run/domainmgr is a tmpfs the reboot wipes, so a
// DomainStatus that carries a CPU allocation again can only have been written
// by the current boot.
func waitUntilPlacementRestored(t *GomegaWithT, device *evetest.EdgeDevice,
	deployed []*placedApp) {
	for _, app := range deployed {
		appName := app.spec.appName
		t.Eventually(func(g Gomega) {
			status, err := readDomainCPUStatus(device, app.uuid)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(status.CPUs).ToNot(BeEmpty(),
				"the device has not placed %q on any CPU yet", appName)
		}, placementRunningTimeout, placementPolling).Should(Succeed())
	}
	waitUntilAppsRunning(device, deployed)
}

// verifyPlacement re-runs the full placement verification -- per application and
// then across the set -- and leaves what it read on each placedApp.
//
// It is run again after every phase rather than only comparing CPU numbers,
// because "the same CPUs as before" is not the whole property: a reboot that
// restored the cpuset but not the per-vCPU pinning, or that dropped the guest
// SMT topology, would leave the numbers identical and the placement broken.
//
// requireOptimal says whether the workloads must additionally sit on the slots
// the batch plan set aside for them. It is false only for phase 4, which starts
// pinned workloads into a node where the others are stopped and where landing
// off-plan is therefore the correct outcome rather than a defect.
func verifyPlacement(t *GomegaWithT, device *evetest.EdgeDevice,
	deployed []*placedApp, phase string, requireOptimal bool) {
	evetest.Logger().Infof("Verifying CPU placement (%s)", phase)
	logPlacementDiagnostics(device, appUUIDs(deployed), placementShellTimeout)
	topo, err := device.HostCPUTopology()
	t.Expect(err).ToNot(HaveOccurred())
	for _, app := range deployed {
		assertAppPlacement(t, device, topo, app, requireOptimal)
	}
	assertPlacementSetInvariants(t, device, topo, deployed)
}

// cpuPoolReport is the node's own account of how its logical CPUs are
// partitioned, as the controller receives it in ZInfoDevice.cpu_pools.
//
// The release assertions are made against this rather than only against
// domainmgr's per-app status because this is what a controller reads to answer
// "will another workload fit on that node?". A CPU that a stopped application
// no longer holds, but that the node still advertises as taken, is a CPU nobody
// can use.
//
// The isolated pool is carried alongside rather than as a third partition: it is
// a kernel fact that cuts across the other two, so its CPUs also appear in one
// of them. It is nil on a node booted without isolcpus, which is every device in
// this package except the one TestCPUIsolatedPool asks for.
type cpuPoolReport struct {
	housekeeping *eveinfo.CPUPoolUtilization
	dedicated    *eveinfo.CPUPoolUtilization
	isolated     *eveinfo.CPUPoolUtilization
}

// readCPUPoolReport picks the housekeeping and dedicated pools out of the latest
// device info. A device that reports neither has not published a CPU pool report
// at all, which is itself a failure of the phases below.
func readCPUPoolReport(device *evetest.EdgeDevice) (cpuPoolReport, error) {
	var report cpuPoolReport
	devInfo := device.GetDeviceInfo()
	if devInfo == nil {
		return report, fmt.Errorf("no device info received from the device yet")
	}
	for _, pool := range devInfo.GetCpuPools() {
		switch pool.GetKind() {
		case eveinfo.CPUPoolKind_CPU_POOL_KIND_HOUSEKEEPING:
			report.housekeeping = pool
		case eveinfo.CPUPoolKind_CPU_POOL_KIND_DEDICATED:
			report.dedicated = pool
		case eveinfo.CPUPoolKind_CPU_POOL_KIND_ISOLATED:
			report.isolated = pool
		}
	}
	if report.housekeeping == nil || report.dedicated == nil {
		return report, fmt.Errorf(
			"the device info carries no housekeeping and dedicated CPU pool (pools: %v)",
			devInfo.GetCpuPools())
	}
	return report, nil
}

// awaitCPUPoolReport polls the device info until the node's CPU pool report
// satisfies check, and returns the report that did.
//
// Polling rather than reading once: the report reaches the controller on the
// periodic ZInfoDevice publish, so the last message received still describes the
// node as it was before the workload the caller just stopped or started. Every
// property checked here converges, so a stale message only delays success -- it
// cannot satisfy an assertion the current state would fail.
func awaitCPUPoolReport(t *GomegaWithT, device *evetest.EdgeDevice, what string,
	check func(g Gomega, report cpuPoolReport)) cpuPoolReport {
	var report cpuPoolReport
	t.Eventually(func(g Gomega) {
		var err error
		report, err = readCPUPoolReport(device)
		g.Expect(err).ToNot(HaveOccurred())
		check(g, report)
	}, placementPoolReportTimeout, placementPolling).Should(Succeed(),
		"the node never reported %s", what)
	evetest.Logger().Infof("node CPU pool report (%s): dedicated %v; housekeeping %v "+
		"of which free %v, free whole cores %d", what,
		report.dedicated.GetCpuIds(), report.housekeeping.GetCpuIds(),
		report.housekeeping.GetFreeCpuIds(), report.housekeeping.GetFreeWholeCores())
	return report
}

// intersectCPUs returns the CPUs of a that also appear in b, so that "these must
// not be claimed any more" can be reported as the offending CPUs rather than as
// a bare boolean.
func intersectCPUs(a, b []uint32) []uint32 {
	inB := make(map[uint32]bool, len(b))
	for _, cpu := range b {
		inB[cpu] = true
	}
	var out []uint32
	for _, cpu := range a {
		if inB[cpu] {
			out = append(out, cpu)
		}
	}
	return out
}

// appStartTime reads the moment the device decided an application may start.
//
// It is read for diagnosis only, never as the property under test: the point of
// the phase is what the placement does, and this only tells the reader whether
// the device set the phase up as the test asked it to.
func appStartTime(device *evetest.EdgeDevice, appUUID uuid.UUID) (time.Time, error) {
	path := fmt.Sprintf("/run/zedmanager/AppInstanceStatus/%s.json", appUUID)
	data, err := device.ReadFile(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read %s: %w", path, err)
	}
	var status struct {
		StartTime time.Time
	}
	if err := json.Unmarshal(data, &status); err != nil {
		return time.Time{}, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return status.StartTime, nil
}

// cpuAssignment is what a pinned application holds: the host CPU behind each
// vCPU, in vCPU order, and the whole set of CPUs it occupies exclusively
// (including the SMT siblings it parks).
type cpuAssignment struct {
	ordered   []uint32
	dedicated []uint32
}

// snapshotAssignments records the pinned applications' assignments so a later
// phase can be compared against them. The slices are copied: verifyPlacement
// overwrites the placedApp fields on every phase.
func snapshotAssignments(deployed []*placedApp) map[string]cpuAssignment {
	out := map[string]cpuAssignment{}
	for _, app := range deployed {
		if !app.spec.wantPinned {
			continue
		}
		out[app.spec.appName] = cpuAssignment{
			ordered:   append([]uint32(nil), app.status.OrderedCPUs...),
			dedicated: append([]uint32(nil), app.dedicated...),
		}
	}
	return out
}

// placementObservation is one phase's view of what the pinned applications hold.
type placementObservation struct {
	phase       string
	assignments map[string]cpuAssignment
}

// placementViolations checks each phase against every phase before it and
// reports disagreements without stopping the test.
//
// Every phase passed to compare observes the same set of *activated*
// applications, so all such observations must agree; which of them is "right" is
// not the question, and comparing everything to a single reference would miss a
// phase that happens to agree with the reference while disagreeing with the
// phases in between. Reporting rather than failing keeps the run going: each
// phase costs a device boot, so stopping at the first disagreement would surface
// one broken property and hide the rest.
//
// A phase that stops every pinned application at once is deliberately not passed
// here at all: it observes a different activated set on the way, so its outcome
// is checked for validity instead (see phase 4 of TestCPUPlacementStability).
type placementViolations struct {
	t        *evetest.T
	observed []placementObservation
}

// compare reports how this phase's placement disagrees with the earlier ones and
// then records it for the phases still to come.
func (v *placementViolations) compare(phase string, deployed []*placedApp) {
	current := snapshotAssignments(deployed)
	clean := true
	for appName, now := range current {
		// Only the earliest phase that disagrees is reported. Later ones would
		// add no information: any two differing observations already prove the
		// assignment is not a function of the configured set.
		for _, earlier := range v.observed {
			was, known := earlier.assignments[appName]
			if !known {
				continue
			}
			// The order matters, not just the set: vCPU i runs on
			// OrderedCPUs[i], so the same CPUs permuted is still a different
			// placement as far as the guest is concerned.
			orderedDiffers := !equalCPUSlices(was.ordered, now.ordered)
			// Parked siblings are part of what the workload holds -- they are
			// held back so nothing else runs on its cores -- so a change here
			// means the cores it owns changed even if its vCPUs did not move.
			dedicatedDiffers := !equalCPUSets(was.dedicated, now.dedicated)
			if orderedDiffers {
				v.t.Errorf("CPU placement is not stable: %q ran on host CPUs %v "+
					"in phase %q but on %v in phase %q; the configured set is the "+
					"same in both, so the plan must produce the same assignment",
					appName, was.ordered, earlier.phase, now.ordered, phase)
			}
			if dedicatedDiffers {
				v.t.Errorf("CPU placement is not stable: %q occupied host CPUs %v "+
					"exclusively in phase %q but occupies %v in phase %q",
					appName, was.dedicated, earlier.phase, now.dedicated, phase)
			}
			if orderedDiffers || dedicatedDiffers {
				clean = false
				break
			}
		}
	}
	if clean {
		evetest.Logger().Infof("CPU placement (%s) agrees with every earlier phase",
			phase)
	}
	v.observed = append(v.observed, placementObservation{
		phase:       phase,
		assignments: current,
	})
}

// equalCPUSlices compares two CPU lists position by position.
func equalCPUSlices(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// equalCPUSets compares two CPU lists as sets.
func equalCPUSets(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[uint32]int{}
	for _, cpu := range a {
		seen[cpu]++
	}
	for _, cpu := range b {
		seen[cpu]--
		if seen[cpu] < 0 {
			return false
		}
	}
	return true
}
