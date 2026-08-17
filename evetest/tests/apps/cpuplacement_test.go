// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test topology-aware CPU placement driven by the controller's per-app policy.

package apps_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
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
	"github.com/lf-edge/eve/evetest/netmodels"
)

// Timeouts shared by every phase of a placement scenario.
const (
	// placementRunningTimeout excludes the image download, which the framework
	// waits for separately.
	placementRunningTimeout = 10 * time.Minute
	// placementSettleTimeout bounds how long the device may take to converge on
	// the placement it reports -- including redistributing a best-effort app's
	// cpuset once a pinned app takes its CPUs.
	placementSettleTimeout = 2 * time.Minute
	placementShellTimeout  = 30 * time.Second
	placementPolling       = 5 * time.Second
	// placementDevInfoInterval is the periodic device-info publish interval (in
	// seconds) the tests that assert on the node's CPU pool report lower the
	// device to. That report rides on ZInfoDevice, which zedagent publishes
	// when the pools change; the periodic publish is the backstop, for a trigger
	// dropped while another publish is in flight and for a report computed after
	// an event that left the pools as they were. 30s is the lowest value EVE
	// accepts.
	placementDevInfoInterval = 30
	// placementPoolReportTimeout bounds waiting for the node's CPU pool report to
	// catch up with the workloads currently running. It covers several publish
	// intervals plus the trip to the controller.
	placementPoolReportTimeout = 4 * time.Minute
)

// runCPUPlacementScenario deploys a whole set of applications with different CPU
// placement policies onto one device and verifies both what each application got
// and how their allocations relate to one another.
//
// Contention is the point. A single application's allocation can look correct by
// accident -- with nothing else on the machine, almost any set of CPUs satisfies
// it -- while the properties the allocator actually exists to guarantee (no host
// CPU dedicated twice, no physical core shared by two whole-core workloads, EVE
// and best-effort workloads left somewhere to run) only have meaning once
// several workloads compete. Booting a device costs minutes, so a scenario is a
// table: every application in it is deployed on the same boot, checked
// individually, and then the set is checked as a whole.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- placement is not network dependent; a
//     single mgmt+apps port is enough to run the apps and reach them over SSH.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps).
//   - Local NI "local-ni" on ethernet0.
//   - One container app (lfedge/evetest-ubuntu-ctr) per table entry, each with
//     its own forwarded SSH port and its own CPU placement policy.
//   - MinCPUs/ThreadsPerCore give the device VM enough physical cores that the
//     table fits *and* EVE keeps a non-empty housekeeping set; an allocation
//     that would empty it is refused, so an over-subscribed table shows up as a
//     deployment failure rather than as a wrong placement.
//
// Phases / assertions
// -------------------
//  1. apps-running: every app reaches RUNNING, i.e. the policies are jointly
//     satisfiable and do not wedge deployment.
//  2. per app (see assertAppPlacement): the allocation domainmgr recorded has
//     the shape the policy asked for, the kernel enforces it vCPU by vCPU, the
//     assigned CPUs relate to physical cores the way the mode promises, and the
//     guest sees exactly the vCPUs it was configured with.
//  3. the set as a whole (see assertPlacementSetInvariants): dedicated sets are
//     disjoint, no two whole-core apps share a physical core, housekeeping is
//     non-empty, and a best-effort app is not confined to somebody else's
//     dedicated CPUs.
//
// Phase 2 reads what EVE decided and then checks it against ground truth via
// /proc/<pid>/task, /sys/devices/system/cpu and QMP -- standard interfaces that
// stay valid across EVE versions. EVE's claim alone would not be evidence, and
// the kernel state alone would not show whether the policy or something else
// produced it: the test needs both, and that they agree.
//
// Test params
// -----------
//   - HYPERVISOR. Skipped under Kubevirt, where concrete CPU selection belongs
//     to the kubelet rather than to the pillar allocator this test exercises.
//
// Suite placement
// ---------------
//   - TestAppsSuite (deploys apps, hence hypervisor-parameterized).
func runCPUPlacementScenario(test *testing.T, sc cpuPlacementScenario) {
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
			MinCPUs:           sc.minCPUs,
			ThreadsPerCore:    sc.deviceThreadsPerCore,
			WithHypervisor:    hypervisor,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	// A controller sends the placement fields only to a node that says it places
	// CPUs, so this KVM node, whose topology EVE can read, has to say so -- and
	// its EVE, that it knows the fields at all.
	t.Eventually(func() bool {
		return device.GetDeviceInfo().GetOptionalCapabilities().GetCpuPlacement()
	}, placementSettleTimeout, placementPolling).Should(BeTrue(),
		"the node does not advertise optional_capabilities.cpu_placement; a "+
			"controller would never send it the CPU placement fields")
	t.Expect(device.GetDeviceInfo().GetApiCapability()).To(BeNumerically(">=",
		eveinfo.APICapability_API_CAPABILITY_CPU_PLACEMENT_POLICY),
		"the node places CPUs but its EVE does not report "+
			"API_CAPABILITY_CPU_PLACEMENT_POLICY")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
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

	evetest.Logger().Infof("CPU placement scenario %q: %d application(s)",
		sc.name, len(sc.apps))
	deployed := make([]*placedApp, 0, len(sc.apps))
	for _, spec := range sc.apps {
		appUUID := devConfig.AddApplication(placementAppConfig(spec, niUUID, 0))
		deployed = append(deployed, &placedApp{spec: spec, uuid: appUUID})
	}
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")

	// Phase 1: the policies must be jointly satisfiable, not wedge deployment.
	for _, app := range deployed {
		device.WaitUntilAppIsRunning(app.uuid, placementRunningTimeout)
	}
	evetest.Checkpoint("apps-running")

	// Dump how the device actually placed everything before asserting anything.
	// An end-to-end run is expensive, so a failure has to be diagnosable from
	// the log it already produced rather than from a second run with more
	// prints.
	logPlacementDiagnostics(device, appUUIDs(deployed), placementShellTimeout)

	topo, err := device.HostCPUTopology()
	t.Expect(err).ToNot(HaveOccurred())

	// Phase 2: each application on its own. Nothing was running before this
	// scenario, so every workload must have landed on its planned slot.
	for _, app := range deployed {
		assertAppPlacement(t, device, topo, app, true)
		evetest.Checkpoint("placement-verified-" + app.spec.appName)
	}

	// Phase 3: the set as a whole.
	assertPlacementSetInvariants(t, device, topo, deployed)
	evetest.Checkpoint("set-invariants-verified")

	for _, app := range deployed {
		deleteAppAndWait(t, device, devConfig, app.uuid)
	}
}

// assertAppPlacement verifies one application's placement: the allocation
// domainmgr recorded, that the kernel enforces it per guest vCPU, the
// relationship the assigned CPUs have to physical cores, and what the guest
// sees. It stores what it read on the placedApp, so the set-wide invariants can
// be checked afterwards without a second round of device queries.
//
// requireOptimal additionally demands that the workload landed on the slot the
// batch plan set aside for it. That holds whenever the pinned workloads either
// all start from nothing or start into a set that is already placed as the plan
// intended, which is the case for every scenario here. It does not hold once a
// pinned workload has been placed while others were stopped -- it was then
// planned as if it were alone on the node, and a workload starting afterwards
// can only take what is still free -- so a caller exercising that must pass
// false and check validity alone.
func assertAppPlacement(t *GomegaWithT, device *evetest.EdgeDevice,
	topo evetest.HostTopology, app *placedApp, requireOptimal bool) {
	spec := app.spec

	// The allocation domainmgr recorded. This is EVE's claim, not the proof --
	// the proof is in the affinity and topology checks below.
	t.Eventually(func(g Gomega) {
		status, err := readDomainCPUStatus(device, app.uuid)
		g.Expect(err).ToNot(HaveOccurred())
		if spec.wantPinned {
			g.Expect(status.OrderedCPUs).ToNot(BeEmpty(),
				"domainmgr recorded no per-vCPU CPU assignment for %s", spec.appName)
		} else {
			g.Expect(status.CPUs).ToNot(BeEmpty(),
				"domainmgr recorded no CPU set at all for %s", spec.appName)
		}
		app.status = status
	}, placementSettleTimeout, placementPolling).Should(Succeed())

	status := app.status
	// EmulatorCPUs is the shared housekeeping pool, which io_placement
	// "housekeeping" also appends to CPUs. Subtracting it and adding the parked
	// siblings, which are held but kept out of CPUs, leaves the CPUs this
	// workload alone may use, which is what the set-wide invariants are about.
	app.dedicated = append(subtractCPUs(status.CPUs, status.EmulatorCPUs), status.ParkedCPUs...)

	evetest.Logger().Infof("placement recorded for %q: vCPU CPUs %v, dedicated set %v, "+
		"emulator CPUs %v, guest topology %d/%d/%d, verdict=%s",
		spec.appName, status.OrderedCPUs, status.CPUs, status.EmulatorCPUs,
		status.VMTopology.Sockets, status.VMTopology.Cores, status.VMTopology.Threads,
		status.CPUPlacementStatus)

	if !spec.wantPinned {
		assertBestEffortPlacement(t, device, app)
		return
	}

	assigned := status.OrderedCPUs
	// The app never sets the legacy pin_cpu flag, so this also proves the
	// policy is what drove pinning.
	t.Expect(assigned).To(HaveLen(spec.vCPUs), "one host CPU must be assigned per vCPU")
	t.Expect(uniqueCPUs(assigned)).To(HaveLen(spec.vCPUs),
		"the same host CPU must not back two vCPUs (assigned: %v)", assigned)
	t.Expect(status.VMTopology.Threads).To(Equal(spec.wantGuestThreads),
		"%s must advertise a guest topology with %d thread(s) per core",
		spec.mode, spec.wantGuestThreads)
	t.Expect(status.VMTopology.Cores).To(Equal(spec.vCPUs/spec.wantGuestThreads),
		"%s must expose %d guest core(s)", spec.mode, spec.vCPUs/spec.wantGuestThreads)
	for _, cpu := range assigned {
		t.Expect(status.CPUs).To(ContainElement(cpu),
			"host CPU %d backs a vCPU but is missing from the dedicated set %v",
			cpu, status.CPUs)
	}
	// The table fits the machine, so every pinned workload must have landed on
	// its planned slot -- or on an equally good one. "repack advised" here would
	// mean the plan and the allocation disagree even though nothing had to be
	// worked around, i.e. the ordering that makes placement independent of
	// activation order did not hold.
	if requireOptimal {
		t.Expect(status.CPUPlacementStatus).To(Equal(eveinfo.CPUPlacementStatus_CPU_PLACEMENT_STATUS_PLACED),
			"%q reports %s although every pinned workload was placed against the "+
				"full set; a repack should never be needed when nothing had to be "+
				"worked around", spec.appName, status.CPUPlacementStatus)
		// And the controller is told so: the status is what it acts on.
		t.Eventually(func() eveinfo.CPUPlacementStatus {
			return device.GetAppInfo(app.uuid).GetCpuPlacementStatus()
		}, placementSettleTimeout, placementPolling).Should(Equal(eveinfo.CPUPlacementStatus_CPU_PLACEMENT_STATUS_PLACED),
			"%q is placed, but the controller is not told so", spec.appName)
	}

	// The kernel agrees, per guest vCPU. The framework resolves the
	// guest-vCPU-to-host-thread mapping over QMP, which is the only place it
	// exists (see EdgeDevice.AppVCPUAffinities).
	var affinities map[int][]uint32
	t.Eventually(func(g Gomega) {
		var err error
		affinities, err = device.AppVCPUAffinities(app.uuid)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(affinities).To(HaveLen(spec.vCPUs))
	}, placementSettleTimeout, placementPolling).Should(Succeed())

	evetest.Logger().Infof("guest vCPU affinities for %q: %v", spec.appName, affinities)
	for vcpu, cpu := range assigned {
		t.Expect(affinities[vcpu]).To(ConsistOf(cpu),
			"guest vCPU %d of %q must be pinned to exactly host CPU %d, but may run "+
				"on %v; a cgroup cpuset alone would leave it free to float across "+
				"the whole dedicated set", vcpu, spec.appName, cpu, affinities[vcpu])
	}

	// The physical-core relationship the mode promises.
	assertCoreRelationship(t, topo, assigned, spec)

	// The cpuset confines every thread of the workload, including any spawned
	// later, and must cover the dedicated CPUs.
	cpuset, err := device.AppCPUSet(app.uuid)
	t.Expect(err).ToNot(HaveOccurred())
	app.cpuset = cpuset
	evetest.Logger().Infof("cpuset for %q: %v", spec.appName, cpuset)
	t.Expect(cpuset).To(ContainElements(assigned),
		"the application cpuset %v must cover its dedicated CPUs %v", cpuset, assigned)

	assertGuestCPUCount(t, device, app)
}

// assertBestEffortPlacement verifies an application that asked for shared
// (best-effort) placement. Such a workload must be left alone: giving it a
// dedicated set, a synthesized SMT topology or per-vCPU pinning would all be
// wrong, and a placement verdict for it would claim a decision that never
// happened.
func assertBestEffortPlacement(t *GomegaWithT, device *evetest.EdgeDevice,
	app *placedApp) {
	spec := app.spec
	status := app.status

	t.Expect(status.OrderedCPUs).To(BeEmpty(),
		"%q asked for shared placement, so no vCPU may be bound to a fixed host CPU "+
			"(recorded: %v)", spec.appName, status.OrderedCPUs)
	t.Expect(status.VMTopology.Threads).To(BeZero(),
		"%q asked for shared placement, so it must keep the flat guest topology; "+
			"a synthesized threads=%d would tell the guest its vCPUs are SMT "+
			"siblings when nothing guarantees they are",
		spec.appName, status.VMTopology.Threads)
	t.Expect(status.CPUPlacementStatus).To(Equal(eveinfo.CPUPlacementStatus_CPU_PLACEMENT_STATUS_UNSPECIFIED),
		"%q makes no CPU request, so there is no placement verdict for it, but "+
			"domainmgr records %s", spec.appName, status.CPUPlacementStatus)

	// Every vCPU stays free to float across the whole cpuset. Read the cpuset
	// and the affinities together so they cannot describe different moments.
	t.Eventually(func(g Gomega) {
		cpuset, err := device.AppCPUSet(app.uuid)
		g.Expect(err).ToNot(HaveOccurred())
		affinities, err := device.AppVCPUAffinities(app.uuid)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(affinities).To(HaveLen(spec.vCPUs))
		for vcpu, allowed := range affinities {
			g.Expect(allowed).To(ConsistOf(cpuset),
				"vCPU %d of best-effort app %q may only run on %v while its cpuset "+
					"is %v; a best-effort workload must not be pinned to a subset "+
					"of its own cpuset", vcpu, spec.appName, allowed, cpuset)
		}
		app.cpuset = cpuset
	}, placementSettleTimeout, placementPolling).Should(Succeed())
	evetest.Logger().Infof("cpuset for best-effort app %q: %v", spec.appName, app.cpuset)

	assertGuestCPUCount(t, device, app)
}

// assertGuestCPUCount checks that the guest was told how many CPUs it has and
// sees exactly those -- a placement that quietly handed the guest a different
// vCPU count would satisfy every host-side check.
func assertGuestCPUCount(t *GomegaWithT, device *evetest.EdgeDevice, app *placedApp) {
	t.Eventually(func(g Gomega) {
		stdout, _, err := device.RunShellScriptInsideApp(app.uuid, appAuth,
			"nproc", placementShellTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(strings.TrimSpace(stdout)).To(Equal(strconv.Itoa(app.spec.vCPUs)),
			"%q must see exactly the vCPUs it was configured with", app.spec.appName)
	}, placementSettleTimeout, placementPolling).Should(Succeed())
}

// assertPlacementSetInvariants checks the properties that only exist once
// several workloads share a machine. They are what makes a dedicated CPU
// actually dedicated: each of them can be violated by an allocator that places
// every workload perfectly when considered on its own.
func assertPlacementSetInvariants(t *GomegaWithT, device *evetest.EdgeDevice,
	topo evetest.HostTopology, deployed []*placedApp) {
	var pinned []*placedApp
	for _, app := range deployed {
		if app.spec.wantPinned {
			pinned = append(pinned, app)
		}
	}

	// 1. Dedicated sets are disjoint. Parked SMT siblings count: they are held
	// back precisely so nobody else runs on the core, so handing one to another
	// workload defeats the point of asking for whole cores.
	owner := map[uint32]string{}
	for _, app := range pinned {
		for _, cpu := range app.dedicated {
			holder, taken := owner[cpu]
			t.Expect(taken).To(BeFalse(),
				"host CPU %d is dedicated to both %q and %q; two workloads with "+
					"dedicated CPUs must never overlap (%q holds %v, %q holds %v)",
				cpu, holder, app.spec.appName, holder, dedicatedOf(pinned, holder),
				app.spec.appName, app.dedicated)
			owner[cpu] = app.spec.appName
		}
	}

	// The kernel-side counterpart of the above: bookkeeping that keeps the sets
	// apart is worthless if the cgroup cpuset still lets one workload's threads
	// run on another's dedicated CPUs.
	for _, app := range pinned {
		for _, cpu := range app.cpuset {
			holder, dedicated := owner[cpu]
			t.Expect(dedicated && holder != app.spec.appName).To(BeFalse(),
				"the cpuset %v of %q includes host CPU %d, which is dedicated to %q",
				app.cpuset, app.spec.appName, cpu, holder)
		}
	}

	// 2. No physical core shared between two whole-core workloads. Disjoint CPU
	// sets are not enough: two workloads landing on the two SMT siblings of one
	// core hold disjoint sets and still contend for the same core's execution
	// resources, which is exactly what full_pcpus_only is bought to prevent.
	for i, a := range pinned {
		if a.spec.coreRule == coreRuleUnconstrained {
			continue
		}
		for _, b := range pinned[i+1:] {
			if b.spec.coreRule == coreRuleUnconstrained {
				continue
			}
			for _, ca := range a.status.OrderedCPUs {
				for _, cb := range b.status.OrderedCPUs {
					t.Expect(topo.SameCore(ca, cb)).To(BeFalse(),
						"host CPUs %d (%q) and %d (%q) are SMT siblings on one "+
							"physical core, but both workloads asked for whole "+
							"cores (%q: %v, %q: %v, siblings of %d: %v)",
						ca, a.spec.appName, cb, b.spec.appName,
						a.spec.appName, a.status.OrderedCPUs,
						b.spec.appName, b.status.OrderedCPUs, ca, topo.SiblingsOf(ca))
				}
			}
		}
	}

	// 3. Housekeeping is not empty. EVE's own services, the emulator threads and
	// every best-effort workload live on whatever is left, so an allocation that
	// consumes the last online CPU takes the device down with it.
	//
	// Retried, unlike the placement reads above: the set of online CPUs is a
	// kernel fact that cannot change while a test runs, so the only way this read
	// fails is the transport -- an SSH session that did not come up. Failing a
	// placement verdict on that would report a bug that is not there, and these
	// tests issue a burst of short-lived SSH sessions right here.
	var online []uint32
	t.Eventually(func(g Gomega) {
		var err error
		online, err = device.OnlineCPUs()
		g.Expect(err).ToNot(HaveOccurred())
	}, placementSettleTimeout, placementPolling).Should(Succeed())
	var housekeeping []uint32
	for _, cpu := range online {
		if _, dedicated := owner[cpu]; !dedicated {
			housekeeping = append(housekeeping, cpu)
		}
	}
	evetest.Logger().Infof("online CPUs %v, dedicated %v, housekeeping %v",
		online, slices.Sorted(maps.Keys(owner)), housekeeping)
	t.Expect(housekeeping).ToNot(BeEmpty(),
		"every online CPU (%v) ended up dedicated to a workload, leaving EVE and "+
			"any best-effort workload nowhere to run", online)

	// 4. A best-effort workload is not confined to somebody else's dedicated
	// CPUs. Eventually, because such a workload may have been deployed before
	// the pinned ones: it starts out with the whole machine in its cpuset and is
	// only pushed off as the pinned workloads take their CPUs. That
	// redistribution is the step this checks -- without it a best-effort app
	// keeps running on cores that are supposed to be exclusive.
	for _, app := range deployed {
		if app.spec.wantPinned {
			continue
		}
		t.Eventually(func(g Gomega) {
			cpuset, err := device.AppCPUSet(app.uuid)
			g.Expect(err).ToNot(HaveOccurred())
			for _, cpu := range cpuset {
				holder, dedicated := owner[cpu]
				g.Expect(dedicated).To(BeFalse(),
					"the cpuset %v of best-effort app %q includes host CPU %d, "+
						"which is dedicated to %q; best-effort workloads belong in "+
						"the housekeeping set %v", cpuset, app.spec.appName, cpu,
					holder, housekeeping)
			}
			app.cpuset = cpuset
		}, placementSettleTimeout, placementPolling).Should(Succeed())
		evetest.Logger().Infof("best-effort app %q settled on cpuset %v",
			app.spec.appName, app.cpuset)
	}
}

// coreRule is the relationship an application's assigned host CPUs must have to
// physical cores. It is the one property a count- or set-based assertion cannot
// capture, and the only thing that distinguishes the whole-core modes from each
// other and from thread-granular placement.
type coreRule int

const (
	// coreRuleUnconstrained places no requirement on cores: the workload is
	// shared, or dedicated at SMT-thread granularity (no full_pcpus_only).
	coreRuleUnconstrained coreRule = iota
	// coreRuleDistinctCores requires a physical core of its own per vCPU, with
	// the sibling threads held back rather than handed to another workload.
	coreRuleDistinctCores
	// coreRuleSiblingPairs requires vCPUs 2k and 2k+1 to land on the two SMT
	// siblings of one physical core, as the guest is told they are.
	coreRuleSiblingPairs
)

// cpuPlacementApp is one application in a placement scenario: the policy it
// asks for and the outcome that policy must produce.
type cpuPlacementApp struct {
	// mode describes the placement mode, for assertion messages.
	mode string
	// appName is the deployed application's display name.
	appName string
	// vCPUs is the vCPU count requested by the application.
	vCPUs int
	// sshFwdPort is the edge-node port forwarded to this app's sshd. It lives in
	// the device's namespace, so every app in a scenario needs its own.
	sshFwdPort uint16
	// placement is the CPU placement intent sent by the controller.
	placement evetest.CPUPlacementConfig
	// wantPinned is whether the policy must result in the workload getting host
	// CPUs of its own.
	wantPinned bool
	// wantGuestThreads is the threads-per-core the guest must be shown. Only
	// meaningful for a pinned app; a shared one keeps the flat topology.
	wantGuestThreads int
	// coreRule is the relationship the assigned CPUs must have to physical
	// cores.
	coreRule coreRule
}

// cpuPlacementScenario is one set of applications to deploy together, plus what
// the device VM must provide for the set to fit. Modes and combinations differ
// only in these values, so they share one body rather than being copied.
type cpuPlacementScenario struct {
	// name describes the scenario, for the log.
	name string
	// deviceThreadsPerCore is the SMT topology the device VM itself needs. A
	// mode that consumes both siblings of a core cannot be tested on a device
	// whose CPUs are all single-thread cores: there is no sibling to take.
	deviceThreadsPerCore uint8
	// minCPUs must cover every app's cores and still leave EVE a non-empty
	// housekeeping set; an allocation that would empty it is refused.
	minCPUs uint8
	// apps are deployed together, in this order, on one device boot.
	apps []cpuPlacementApp
}

// placedApp is a deployed application plus everything the assertions read about
// it, so the set-wide invariants can be checked without querying the device
// again for state the per-app phase already has.
type placedApp struct {
	spec   cpuPlacementApp
	uuid   uuid.UUID
	status domainCPUStatus
	// dedicated is the host CPUs this workload alone may use (vCPU CPUs plus
	// parked siblings), i.e. its recorded CPU set minus the shared emulator
	// pool, plus its parked CPUs. Empty for a best-effort workload.
	dedicated []uint32
	// cpuset is the cgroup cpuset the workload is confined to.
	cpuset []uint32
}

// onePerCoreApp asks for a dedicated physical core per vCPU, with the sibling
// threads parked idle.
func onePerCoreApp(appName string, vCPUs int, sshFwdPort uint16) cpuPlacementApp {
	return cpuPlacementApp{
		mode:       "one-per-core",
		appName:    appName,
		vCPUs:      vCPUs,
		sshFwdPort: sshFwdPort,
		placement: evetest.CPUPlacementConfig{
			Policy:         eveconfig.CpuPolicy_CPU_POLICY_DEDICATED,
			PinCPU:         true,
			FullPCPUsOnly:  true,
			ThreadsPerCore: 1,
			NUMAPolicy:     eveconfig.NumaPolicy_NUMA_POLICY_BEST_EFFORT,
		},
		wantPinned:       true,
		wantGuestThreads: 1,
		coreRule:         coreRuleDistinctCores,
	}
}

// wholeCoreSMTApp asks for dedicated whole physical cores with both SMT siblings
// of each becoming vCPUs, and the guest told which of its vCPUs are siblings.
func wholeCoreSMTApp(appName string, vCPUs int, sshFwdPort uint16) cpuPlacementApp {
	return cpuPlacementApp{
		mode:       "whole-core-smt",
		appName:    appName,
		vCPUs:      vCPUs,
		sshFwdPort: sshFwdPort,
		placement: evetest.CPUPlacementConfig{
			Policy:         eveconfig.CpuPolicy_CPU_POLICY_DEDICATED,
			PinCPU:         true,
			FullPCPUsOnly:  true,
			ThreadsPerCore: 2,
			NUMAPolicy:     eveconfig.NumaPolicy_NUMA_POLICY_BEST_EFFORT,
		},
		wantPinned:       true,
		wantGuestThreads: 2,
		coreRule:         coreRuleSiblingPairs,
	}
}

// sharedApp asks for best-effort placement in the shared pool, which is what
// every ordinary workload gets. It is in a placement scenario as the workload
// the dedicated ones must not disturb, and that must not disturb them.
func sharedApp(appName string, vCPUs int, sshFwdPort uint16) cpuPlacementApp {
	return cpuPlacementApp{
		mode:       "housekeeping",
		appName:    appName,
		vCPUs:      vCPUs,
		sshFwdPort: sshFwdPort,
		placement: evetest.CPUPlacementConfig{
			Policy: eveconfig.CpuPolicy_CPU_POLICY_HOUSEKEEPING,
		},
		wantPinned: false,
		coreRule:   coreRuleUnconstrained,
	}
}

// threadGranularApp asks for dedicated CPUs at SMT-thread granularity:
// CPU_POLICY_DEDICATED *without* full_pcpus_only. The workload gets host CPUs
// no other workload may use, but they are individual logical CPUs rather than
// whole physical cores, so it may well end up on a core whose other thread
// belongs to somebody else. That is the pre-policy pinning behaviour, and it is
// still what a workload wants when all it needs is not to be descheduled.
//
// It is the only shape that can leave a physical core *half* owned, which is why
// TestCPUPlacementNeedsRepack builds its fragmented node out of these: a
// whole-core workload takes and releases whole cores, so no arrangement of
// whole-core workloads can ever fragment the node.
//
// Its allocation is deliberately not asserted by assertAppPlacement: this path
// pins each vCPU to one of its CPUs but synthesizes no guest SMT topology, so it
// is checked by assertThreadGranularPlacement instead.
func threadGranularApp(appName string, vCPUs int, sshFwdPort uint16) cpuPlacementApp {
	return cpuPlacementApp{
		mode:       "thread-granular",
		appName:    appName,
		vCPUs:      vCPUs,
		sshFwdPort: sshFwdPort,
		placement: evetest.CPUPlacementConfig{
			Policy: eveconfig.CpuPolicy_CPU_POLICY_DEDICATED,
			PinCPU: true,
			// The point of this constructor: dedicated CPUs without whole
			// cores. ThreadsPerCore and NUMAPolicy are left unset: they need
			// whole cores, and the device refuses them without.
			FullPCPUsOnly: false,
		},
		wantPinned:       true,
		wantGuestThreads: 0,
		coreRule:         coreRuleUnconstrained,
	}
}

// assertCoreRelationship checks how one application's assigned CPUs relate to
// physical cores, which is the whole point of full_pcpus_only.
func assertCoreRelationship(t *GomegaWithT, topo evetest.HostTopology,
	assigned []uint32, spec cpuPlacementApp) {
	switch spec.coreRule {
	case coreRuleUnconstrained:
		return

	case coreRuleDistinctCores:
		for i, a := range assigned {
			for j, b := range assigned {
				if i >= j {
					continue
				}
				t.Expect(topo.SameCore(a, b)).To(BeFalse(),
					"host CPUs %d and %d are SMT siblings on one physical core, but "+
						"%s requires a distinct core per vCPU (assigned: %v, "+
						"siblings of %d: %v)",
					a, b, spec.mode, assigned, a, topo.SiblingsOf(a))
			}
		}

	case coreRuleSiblingPairs:
		// The guest is told vCPUs 2k and 2k+1 are siblings, so they must really
		// be siblings on the host. A placement that used complete sibling pairs
		// but paired them up differently would still satisfy every count- and
		// set-based check while lying to the guest about which vCPUs share a
		// core -- which is exactly the property the mode exists to provide.
		t.Expect(len(assigned)%2).To(Equal(0),
			"whole-core-smt cannot assign an odd number of CPUs")
		for i := 0; i+1 < len(assigned); i += 2 {
			a, b := assigned[i], assigned[i+1]
			t.Expect(topo.SameCore(a, b)).To(BeTrue(),
				"guest vCPUs %d and %d are presented to the guest as SMT siblings, so "+
					"host CPUs %d and %d must be siblings on one physical core "+
					"(assigned: %v, siblings of %d: %v)",
				i, i+1, a, b, assigned, a, topo.SiblingsOf(a))
		}
		// Distinct pairs must not share a core, or the workload would have been
		// given fewer physical cores than it asked for.
		for i := 0; i+1 < len(assigned); i += 2 {
			for j := i + 2; j+1 < len(assigned); j += 2 {
				t.Expect(topo.SameCore(assigned[i], assigned[j])).To(BeFalse(),
					"vCPU pairs (%d,%d) and (%d,%d) share one physical core; %s must "+
						"allocate a whole core per pair (assigned: %v)",
					i, i+1, j, j+1, spec.mode, assigned)
			}
		}
	}
}

// TestCPUPlacementOnePerCore exercises the one-per-core mode: every vCPU gets a
// physical core of its own and the sibling threads are held back rather than
// handed to another workload. See runCPUPlacementScenario for the phases.
func TestCPUPlacementOnePerCore(test *testing.T) {
	runCPUPlacementScenario(test, cpuPlacementScenario{
		name: "one-per-core",
		// Two dedicated cores still leave EVE a non-empty housekeeping set.
		minCPUs: 6,
		// No SMT is needed: this mode uses one thread per core by definition,
		// so the device's default single-thread cores are exactly right.
		deviceThreadsPerCore: 0,
		apps: []cpuPlacementApp{
			onePerCoreApp("cpu-pinned-app", 2, appSSHFwdPort),
		},
	})
}

// TestCPUPlacementWholeCoreSMT exercises the whole-core-SMT mode: the workload
// gets whole physical cores and *both* SMT siblings of each become vCPUs, with
// the guest told which of its vCPUs are siblings so it can place its own hot
// work accordingly. This is the mode a poll-mode datapath wants, and the one
// where a mismatch between the advertised and the real sibling relationship
// silently costs throughput rather than failing outright.
//
// It requires an SMT topology on the device VM itself (deviceThreadsPerCore
// below): with single-thread cores there is no sibling to allocate a second vCPU
// from, and the allocator correctly refuses instead of quietly using two cores.
func TestCPUPlacementWholeCoreSMT(test *testing.T) {
	runCPUPlacementScenario(test, cpuPlacementScenario{
		name: "whole-core-smt",
		// 8 CPUs as 4 dual-thread cores: two go to the app, two are left for
		// EVE's housekeeping set.
		minCPUs:              8,
		deviceThreadsPerCore: 2,
		apps: []cpuPlacementApp{
			wholeCoreSMTApp("cpu-smt-pinned-app", 4, appSSHFwdPort), // two whole cores
		},
	})
}

// TestCPUPlacementMultiApp deploys the three placement modes side by side on one
// device: a whole-core-SMT app, a one-per-core app and an ordinary best-effort
// app, all on the same boot.
//
// This is the case the single-mode tests cannot cover. With one workload on the
// machine there is nothing to collide with, so an allocator that ignores what
// other workloads hold still looks correct; here the two dedicated workloads
// must end up on disjoint CPUs *and* disjoint physical cores, and the
// best-effort one -- deployed first, so it starts out with the whole machine in
// its cpuset -- must be pushed off their cores as they take them. It also
// exercises the ordering that makes placement independent of activation order:
// whole-core-SMT is the most constrained mode (it can only use a core that
// really has two hardware threads), so if the machine were carved up in arrival
// order the flexible one-per-core app could take the cores it needs.
//
// The table is sized to the device: 8 CPUs as 4 dual-thread cores, of which EVE
// reserves the lowest (making its whole core unallocatable), leaves three
// allocatable cores -- one for the SMT app's two vCPUs, two for the one-per-core
// app's two vCPUs -- and the reserved core as housekeeping for EVE and the
// best-effort app.
func TestCPUPlacementMultiApp(test *testing.T) {
	runCPUPlacementScenario(test, cpuPlacementScenario{
		name:                 "multi-app",
		minCPUs:              8,
		deviceThreadsPerCore: 2,
		apps: []cpuPlacementApp{
			// First on purpose: a best-effort app deployed before any dedicated
			// one starts with every CPU in its cpuset, so it is only off the
			// dedicated cores if the device actively redistributes.
			sharedApp("cpu-shared-app", 1, appSSHFwdPort+2),
			wholeCoreSMTApp("cpu-smt-app", 2, appSSHFwdPort),  // one whole core
			onePerCoreApp("cpu-core-app", 2, appSSHFwdPort+1), // two whole cores
		},
	})
}

// placementDiagnosticsScript dumps everything relevant to how the device placed
// the applications' threads. It deliberately filters as little as possible: the
// point is to show what is actually there, including the cases the assertions
// did not anticipate.
const placementDiagnosticsScript = `UUIDS='@UUIDS@'
echo "## kernel / cpu count"
uname -r; nproc

echo "## per-CPU topology (core_id, package, siblings)"
for d in /sys/devices/system/cpu/cpu[0-9]*; do
  printf '  cpu%s core_id=%s pkg=%s siblings=%s\n' "${d#*/cpu}" \
    "$(cat "$d/topology/core_id" 2>/dev/null)" \
    "$(cat "$d/topology/physical_package_id" 2>/dev/null)" \
    "$(cat "$d/topology/thread_siblings_list" 2>/dev/null)"
done

echo "## online / isolated"
echo "  online=$(cat /sys/devices/system/cpu/online 2>/dev/null)"
echo "  isolated=$(cat /sys/devices/system/cpu/isolated 2>/dev/null)"

echo "## processes whose cmdline mentions qemu or an app UUID"
for p in /proc/[0-9]*; do
  cl=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
  case "$cl" in
    @UUID_CASES@) ;;
    *) continue ;;
  esac
  echo "  --- pid=${p#/proc/} comm=$(cat "$p/comm" 2>/dev/null)"
  echo "      cmdline=$(echo "$cl" | cut -c1-500)"
  echo "      cgroup=$(tr '\n' ' ' < "$p/cgroup" 2>/dev/null)"
  for td in "$p"/task/*; do
    echo "      tid=${td##*/} comm=$(cat "$td/comm" 2>/dev/null) aff=$(awk '/Cpus_allowed_list/{print $2}' "$td/status" 2>/dev/null)"
  done
done

echo "## every process comm (in case the filter above matched nothing)"
for p in /proc/[0-9]*; do
  echo "  ${p#/proc/} $(cat "$p/comm" 2>/dev/null)"
done

echo "## app cgroup cpusets"
for f in $(find /sys/fs/cgroup -name 'cpuset.cpus*' 2>/dev/null | grep -i @CGROUP_GREP@); do
  echo "  $f = $(cat "$f" 2>/dev/null)"
done

echo "## the CPU plan domainmgr computed for the configured set"
cat /run/domainmgr/cpuplan.json 2>/dev/null

echo "## DomainStatus as published by domainmgr"
for u in $UUIDS; do
  cat "/run/domainmgr/DomainStatus/$u.json" 2>/dev/null | cut -c1-4000
  echo
done
`

// logPlacementDiagnostics runs the diagnostics script and logs its output. It
// never fails the test: it exists so that whatever the assertions conclude, the
// evidence is in the log.
func logPlacementDiagnostics(device *evetest.EdgeDevice, appUUIDs []uuid.UUID,
	timeout time.Duration) {
	var uuids, cases, grep []string
	cases = append(cases, "*qemu*")
	grep = append(grep, "-e eve-user-apps")
	for _, appUUID := range appUUIDs {
		uuids = append(uuids, appUUID.String())
		cases = append(cases, "*"+appUUID.String()+"*")
		grep = append(grep, "-e "+appUUID.String())
	}
	script := placementDiagnosticsScript
	script = strings.ReplaceAll(script, "@UUIDS@", strings.Join(uuids, " "))
	script = strings.ReplaceAll(script, "@UUID_CASES@", strings.Join(cases, "|"))
	script = strings.ReplaceAll(script, "@CGROUP_GREP@", strings.Join(grep, " "))
	stdout, stderr, err := device.RunShellScript(script, timeout, 0)
	if err != nil {
		evetest.Logger().Warnf("CPU placement diagnostics failed: %v (stderr: %s)",
			err, stderr)
	}
	evetest.Logger().Infof("CPU placement diagnostics for apps %v:\n%s", uuids, stdout)
}

// domainCPUStatus is the subset of the DomainStatus that domainmgr publishes
// under /run which describes the CPU allocation. A local struct is used rather
// than pillar's own type because evetest builds against a released pillar
// module, which does not carry fields added on a feature branch.
type domainCPUStatus struct {
	// DomainName identifies the domain on the device and therefore locates its
	// QEMU monitor socket.
	DomainName   string
	CPUs         []uint32
	OrderedCPUs  []uint32
	ParkedCPUs   []uint32
	EmulatorCPUs []uint32
	VMTopology   struct {
		Sockets int
		Cores   int
		Threads int
	}
	// CPUPlacementStatus is domainmgr's verdict on the CPU request, whose values
	// are the wire's; it arrives as a number.
	CPUPlacementStatus eveinfo.CPUPlacementStatus
}

// readDomainCPUStatus reads back the allocation domainmgr decided on, so it can
// be cross-checked against what the kernel is actually enforcing. It is EVE's
// claim, not the proof.
func readDomainCPUStatus(device *evetest.EdgeDevice,
	appUUID uuid.UUID) (domainCPUStatus, error) {
	var status domainCPUStatus
	path := fmt.Sprintf("/run/domainmgr/DomainStatus/%s.json", appUUID)
	data, err := device.ReadFile(path)
	if err != nil {
		return status, fmt.Errorf("failed to read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &status); err != nil {
		return status, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return status, nil
}

func appUUIDs(apps []*placedApp) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(apps))
	for _, app := range apps {
		out = append(out, app.uuid)
	}
	return out
}

// dedicatedOf returns the dedicated CPUs of the named app, for use in assertion
// messages about a conflict between two of them.
func dedicatedOf(apps []*placedApp, appName string) []uint32 {
	for _, app := range apps {
		if app.spec.appName == appName {
			return app.dedicated
		}
	}
	return nil
}

func uniqueCPUs(cpus []uint32) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, cpu := range cpus {
		if !seen[cpu] {
			seen[cpu] = true
			out = append(out, cpu)
		}
	}
	return out
}

// subtractCPUs returns the CPUs in from that are not in remove.
func subtractCPUs(from, remove []uint32) []uint32 {
	return slices.DeleteFunc(slices.Clone(from), func(cpu uint32) bool {
		return slices.Contains(remove, cpu)
	})
}
