// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test that the SMT sibling a one-per-core workload leaves unused is *consumed*,
// not spare: nothing else may be scheduled on it.

package apps_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// parkedBusyLoops is how many busy loops the best-effort application spins
	// up, and parkedBusySeconds how long each of them lives. The load exists so
	// that phase 5 means something: an idle neighbour would not be observed on a
	// parked CPU no matter how the device was configured, whereas a saturated one
	// is exactly the workload the scheduler would spill onto any thread it is
	// allowed to touch. The loops are bounded with timeout(1) so that they cannot
	// outlive the test even if it fails and the app is left behind.
	parkedBusyLoops   = 2
	parkedBusySeconds = 240
	// parkedSampleCount is how many times the device is walked for the last-run
	// CPU of every application thread. One sample would only say the parked CPU
	// happened to be unused at that instant.
	parkedSampleCount = 10
	// parkedSampleTimeout bounds the whole sampling script: parkedSampleCount
	// passes over /proc, each of which forks per thread on a machine that is
	// deliberately under load.
	parkedSampleTimeout = 6 * time.Minute
	// parkedBusyLoadFloor is the CPU-equivalent of non-idle time the best-effort
	// application's cpuset must accumulate during the sampling window for the
	// window to count as loaded at all. parkedBusyLoops busy loops on
	// parkedBusyLoops vCPUs produce close to parkedBusyLoops CPUs of load; this
	// only has to distinguish "the loops ran" from "the loops never started".
	parkedBusyLoadFloor = 1.0
	// parkedIdleShareCeiling is the fraction of wall time a parked CPU may spend
	// off the idle task during the sampling window.
	//
	// It is deliberately loose rather than near zero, because absolute idleness is
	// not what EVE promises and asserting it would be flaky: kernel per-CPU
	// threads legitimately live there, EVE does not confine its own services to
	// the housekeeping set, and the emulator/IO threads of the workload that
	// *owns* the core may use it -- it is that workload's core to waste. What the
	// mode promises is that no *other* workload runs there, and a workload that
	// could would show up far above this ceiling: the best-effort app's own CPUs
	// sit near 100% in the very same window. Measured on the reference device the
	// parked CPU spends about 0.2% of the window off the idle task, so this leaves
	// two orders of magnitude of headroom for a busier node.
	parkedIdleShareCeiling = 0.25
)

// TestCPUPlacementParkedSiblings verifies that the SMT sibling threads a
// one-per-core workload does not use are *consumed by it*, not left as spare
// capacity for someone else.
//
// This is the semantics of full_pcpus_only with threads_per_core=1, and it is
// easy to mistake for waste. The workload asks for every thread of a physical
// core while using only one of them on purpose: the sibling thread shares that
// core's L1/L2 caches and its execution engine, so anything scheduled on it
// evicts the pinned vCPU's cache lines and steals issue slots and ALU time from
// it. The interference is invisible in any CPU accounting -- the pinned vCPU
// still has "its" thread -- and shows up only as jitter and lost throughput,
// which is precisely what a workload buys whole cores to avoid. Leaving the
// sibling idle is therefore the deliberate cost of the mode, not a bug to
// reclaim, and a "helpful" allocator that handed that thread to a best-effort
// app would silently destroy the guarantee it was asked for.
//
// EVE enforces this in three places (assignmentCPUs puts the parked CPUs in the
// reserved set and in the app's own cpuset; Placer.FreeCPUs excludes the whole
// dedicated union, parked included, from what a best-effort app's cpuset is
// built from; coreIsDedicated refuses a physical core with any sibling held).
// The existing multi-app test would catch a regression in any of them, but only
// as "a best-effort app's cpuset overlaps the dedicated union" -- which does not
// say that a *deliberately idle* thread leaked. This test names that.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- placement is not network dependent; a
//     single mgmt+apps port is enough to run the apps and reach them over SSH.
//
// Device configuration
// --------------------
//   - SystemAdapter for eth0 (DHCP, mgmt+apps), local NI "local-ni".
//   - timer.deviceinfo.interval lowered to its minimum, because phase 4 asserts
//     on the node's CPU pool report, which only reaches the controller on the
//     periodic ZInfoDevice publish.
//   - 8 CPUs as 4 dual-thread cores. EVE reserves the lowest CPU, which makes its
//     whole core unallocatable, leaving three allocatable cores: one for the
//     one-per-core app (1 vCPU -> 1 assigned thread + 1 parked sibling), one for
//     the whole-core-SMT app, one spare. That leaves four CPUs of housekeeping
//     for EVE and the best-effort app -- enough that saturating the best-effort
//     app cannot starve EVE's own services and trip its watchdog.
//   - Three container apps (lfedge/evetest-ubuntu-ctr), each with its own
//     forwarded SSH port: a best-effort one deployed first (so it starts out with
//     the whole machine in its cpuset and is only off the dedicated CPUs if the
//     device actively redistributes), the one-per-core app whose parked sibling is
//     the subject, and a second pinned app so that "no *other* workload" has more
//     than one witness.
//
// Phases / assertions
// -------------------
//  1. baseline: all three apps run and pass the same per-app and set-wide
//     placement checks the other placement tests use (verifyPlacement).
//  2. parked set identified: the one-per-core app's parked CPUs are computed as
//     its dedicated set minus its per-vCPU assignment, and each one is confirmed
//     to be the SMT sibling of an assigned CPU. Non-empty, or the device has no
//     SMT and the test skips rather than passing vacuously.
//  3. the parked CPUs are absent from every other workload: not in the
//     best-effort app's cpuset, and not in any other app's dedicated set or
//     cpuset.
//  4. the node does not advertise them as capacity: each parked CPU is in the
//     dedicated pool of ZInfoDevice.cpu_pools and in no free CPU list, so a
//     controller cannot be told to place another workload there.
//  5. nothing else actually runs there: while the best-effort app saturates its
//     own vCPUs, the last-run CPU of every thread of every other application is
//     sampled repeatedly and must never be a parked CPU, and the parked CPUs must
//     stay near idle while the best-effort app's CPUs are busy.
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
func TestCPUPlacementParkedSiblings(test *testing.T) {
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

	// Checked before anything is deployed: on a device whose cores are all
	// single-threaded there is no sibling to park, so every assertion below would
	// hold trivially. That is a skip, not a pass -- and finding out after three
	// applications have been brought up would only waste the boot.
	topo, err := device.HostCPUTopology()
	t.Expect(err).ToNot(HaveOccurred())
	if !deviceHasSMT(topo) {
		evetestT.Skip("the device has no SMT sibling threads at all, so a one-per-core " +
			"workload parks nothing and there is no thread that could leak")
	}
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)

	// Phase 4 reads the node's CPU pool report, which rides on the periodic
	// ZInfoDevice publish; at the 10 minute default the test would spend most of
	// its time waiting for a message.
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

	// The best-effort app is deployed first on purpose: it then starts with every
	// CPU in its cpuset, so it only ends up off the parked CPUs if the device
	// actively narrows it when the pinned apps take their cores. It gets one vCPU
	// per busy loop, so that phase 5's load really saturates it and the scheduler
	// has a reason to look for another CPU to put it on.
	sharedSpec := sharedApp("cpu-parked-shared-app", parkedBusyLoops, appSSHFwdPort+2)
	// One vCPU, so the app occupies exactly one physical core and the parked set
	// is exactly the one sibling thread it declines to use.
	coreSpec := onePerCoreApp("cpu-parked-core-app", 1, appSSHFwdPort)
	// A second pinned workload, so "no other workload holds a parked CPU" is
	// checked against something that also has dedicated CPUs of its own, not only
	// against the best-effort app.
	smtSpec := wholeCoreSMTApp("cpu-parked-smt-app", 2, appSSHFwdPort+1)

	deployed := make([]*placedApp, 0, 3)
	for _, spec := range []cpuPlacementApp{sharedSpec, coreSpec, smtSpec} {
		appUUID := devConfig.AddApplication(placementAppConfig(spec, niUUID, 0))
		deployed = append(deployed, &placedApp{spec: spec, uuid: appUUID})
	}
	sharedInst, coreApp := deployed[0], deployed[1]
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")

	// Phase 1: the placement itself has to be right before anything can be
	// concluded about the threads it parks.
	waitUntilAppsRunning(device, deployed)
	verifyPlacement(t, device, deployed, "baseline", true)
	evetest.Checkpoint("baseline-verified")

	// Phase 2: name the parked CPUs. Everything below is about these specific
	// CPUs, so if they cannot be identified the rest of the test proves nothing.
	parked := parkedCPUsOf(t, topo, coreApp)
	evetest.Logger().Infof("%q runs on host CPUs %v and parks their SMT siblings %v "+
		"(dedicated set %v)", coreApp.spec.appName, coreApp.status.OrderedCPUs, parked,
		coreApp.dedicated)
	evetest.Checkpoint("parked-cpus-identified")

	// Phase 3: the parked CPUs must not appear in anything else's allocation.
	assertParkedCPUsNotShared(t, parked, coreApp, deployed)
	evetest.Checkpoint("parked-cpus-not-shared")

	// Phase 4: nor may the node advertise them as capacity.
	assertParkedCPUsNotAdvertised(t, device, parked, coreApp)
	evetest.Checkpoint("parked-cpus-not-advertised")

	// Phase 5: and nothing else may actually be seen running on them.
	assertParkedCPUsUnused(t, device, parked, coreApp, sharedInst, deployed)
	evetest.Checkpoint("parked-cpus-unused")

	for _, app := range deployed {
		deleteAppAndWait(t, device, devConfig, app.uuid)
	}
}

// deviceHasSMT reports whether any physical core of the device carries more than
// one logical CPU.
func deviceHasSMT(topo evetest.HostTopology) bool {
	for _, cpu := range topo.IDs() {
		if len(topo.SiblingsOf(cpu)) > 1 {
			return true
		}
	}
	return false
}

// parkedCPUsOf derives the CPUs a one-per-core workload holds without using: the
// CPUs it occupies exclusively, minus the ones actually backing a vCPU.
//
// Each of them is confirmed to be the SMT sibling of an assigned CPU. That is
// what makes them *parked* rather than merely surplus: the workload holds them
// because they share a physical core -- its caches and its execution engine --
// with a thread it does run on. A CPU in the dedicated set that is not a sibling
// of anything assigned would be plain over-allocation, and stating the sibling
// relationship here is what keeps this test about the mode's semantics rather
// than about set arithmetic.
func parkedCPUsOf(t *GomegaWithT, topo evetest.HostTopology,
	app *placedApp) []uint32 {
	assigned := app.status.OrderedCPUs
	parked := subtractCPUs(app.dedicated, assigned)
	t.Expect(parked).ToNot(BeEmpty(),
		"%q asked for whole physical cores with one thread each and was assigned host "+
			"CPUs %v out of the dedicated set %v, so it should also be holding their "+
			"idle SMT siblings; holding nothing beyond the assigned threads means the "+
			"siblings were left available to other workloads, which is exactly the "+
			"cache and execution-unit interference full_pcpus_only is bought to prevent",
		app.spec.appName, assigned, app.dedicated)
	for _, cpu := range parked {
		sibling := false
		for _, a := range assigned {
			if topo.SameCore(cpu, a) {
				sibling = true
				break
			}
		}
		t.Expect(sibling).To(BeTrue(),
			"host CPU %d is held exclusively by %q but backs none of its vCPUs (%v) and "+
				"is not on a physical core with any of them either (siblings of %d: %v); "+
				"a parked CPU is only justified by sharing a core with a thread the "+
				"workload runs on -- anything else is capacity taken from the node for "+
				"no reason", cpu, app.spec.appName, assigned, cpu, topo.SiblingsOf(cpu))
	}
	return parked
}

// assertParkedCPUsNotShared checks that no workload other than the one parking
// them has a parked CPU in its allocation -- neither in a dedicated set nor in a
// cgroup cpuset.
//
// The cpuset is checked separately from the dedicated set because they can fail
// independently: bookkeeping that keeps the parked CPUs out of every other
// workload's *accounting* is worthless if the cgroup still lets that workload's
// threads run there, and a cpuset that happens to exclude them today is not a
// guarantee if the allocator considers them free.
func assertParkedCPUsNotShared(t *GomegaWithT, parked []uint32, owner *placedApp,
	deployed []*placedApp) {
	for _, app := range deployed {
		if app == owner {
			continue
		}
		t.Expect(intersectCPUs(parked, app.dedicated)).To(BeEmpty(),
			"host CPUs %v are dedicated to %q although %q parks them: they are the idle "+
				"SMT siblings of the cores it runs on, held back precisely so that "+
				"nothing else touches those cores' caches or execution units",
			intersectCPUs(parked, app.dedicated), app.spec.appName, owner.spec.appName)
		t.Expect(intersectCPUs(parked, app.cpuset)).To(BeEmpty(),
			"the cpuset %v of %q includes host CPUs %v, which %q parks as the idle SMT "+
				"siblings of its own cores; a thread of %q scheduled there would evict "+
				"that core's cache lines and steal issue slots from the pinned vCPU on "+
				"the sibling thread, which is the whole reason the sibling is held idle "+
				"instead of being handed out", app.cpuset, app.spec.appName,
			intersectCPUs(parked, app.cpuset), owner.spec.appName, app.spec.appName)
	}
}

// assertParkedCPUsNotAdvertised checks the node's own report: a parked CPU must
// be accounted for as dedicated and must appear in no pool's free CPU list.
//
// This is a different failure from a wrong cpuset. The controller decides where
// to place the *next* workload from this report, so a parked CPU advertised as
// free is a promise the node cannot keep: it would either be handed out --
// destroying the guarantee the one-per-core app paid for -- or the placement
// would be refused at the last moment, on a node the controller was told had
// room.
func assertParkedCPUsNotAdvertised(t *GomegaWithT, device *evetest.EdgeDevice,
	parked []uint32, owner *placedApp) {
	awaitCPUPoolReport(t, device, "the parked SMT siblings as dedicated capacity",
		func(g Gomega, report cpuPoolReport) {
			g.Expect(report.dedicated.GetCpuIds()).To(ContainElements(intsOf(parked)),
				"the node's dedicated CPU pool %v omits host CPUs %v, which %q holds as "+
					"the parked SMT siblings of its cores; a CPU the node does not "+
					"account for as taken is a CPU it may hand to the next workload",
				report.dedicated.GetCpuIds(), parked, owner.spec.appName)
			g.Expect(intersectCPUs(parked, report.housekeeping.GetFreeCpuIds())).
				To(BeEmpty(),
					"host CPUs %v are reported as free housekeeping capacity although "+
						"%q parks them (free housekeeping CPUs: %v); they are consumed, "+
						"not spare -- the sibling of a core carrying a pinned vCPU can "+
						"only be used by trashing that vCPU's caches and stealing its "+
						"execution-unit time",
					intersectCPUs(parked, report.housekeeping.GetFreeCpuIds()),
					owner.spec.appName, report.housekeeping.GetFreeCpuIds())
			g.Expect(intersectCPUs(parked, report.dedicated.GetFreeCpuIds())).To(BeEmpty(),
				"host CPUs %v are reported as free within the dedicated pool although "+
					"%q parks them (free dedicated CPUs: %v)",
				intersectCPUs(parked, report.dedicated.GetFreeCpuIds()),
				owner.spec.appName, report.dedicated.GetFreeCpuIds())
		})
}

// assertParkedCPUsUnused is the observational half of the test: with the
// best-effort application saturating its own vCPUs, no thread of any other
// application may be seen on a parked CPU, and the parked CPUs must stay near
// idle while the best-effort app's CPUs are busy.
//
// Load matters here. Every assertion above reads a *configuration* -- a cpuset, a
// dedicated set, a report -- and a configuration can be right while the effect it
// exists to produce is not. What this phase adds is a workload that would take
// the parked thread if the kernel let it: a saturated best-effort app is exactly
// the neighbour the scheduler spreads onto every CPU it is permitted to use, so
// its absence from the parked CPUs is evidence rather than coincidence. The
// busy-CPU measurement is reported alongside as the positive control -- without
// it, an app whose loops never started would make this phase pass for the wrong
// reason.
func assertParkedCPUsUnused(t *GomegaWithT, device *evetest.EdgeDevice,
	parked []uint32, owner, busy *placedApp, deployed []*placedApp) {
	startBusyLoad(t, device, busy)

	samples, cpuTimes := sampleAppThreadCPUs(t, device, appUUIDs(deployed))

	// The positive control: the window was loaded. A sampling window in which the
	// best-effort app did nothing would prove nothing about where it can run.
	busyLoad := nonIdleCPUEquivalents(cpuTimes, busy.cpuset)
	evetest.Logger().Infof("during the sampling window the cpuset %v of %q carried "+
		"%.2f CPUs of non-idle time", busy.cpuset, busy.spec.appName, busyLoad)
	t.Expect(busyLoad).To(BeNumerically(">=", parkedBusyLoadFloor),
		"the best-effort application %q was asked to saturate its %d vCPUs but its "+
			"cpuset %v only accumulated %.2f CPUs of non-idle time; without a neighbour "+
			"that actually wants CPU time, finding the parked CPUs %v unused says "+
			"nothing about whether they are reachable",
		busy.spec.appName, busy.spec.vCPUs, busy.cpuset, busyLoad, parked)

	// No thread of any other application was seen running on a parked CPU.
	//
	// Only observations of threads that demonstrably ran are considered (see
	// ranDuringInterval): a thread's last-run CPU is a leftover, and the
	// best-effort app is deployed before the pinned ones -- it starts with the
	// whole machine in its cpuset -- so a thread that has not been scheduled since
	// the cpuset was narrowed can still name a now-parked CPU without ever having
	// been able to run there again. Only a CPU a thread ran on *during* the window
	// is evidence.
	//
	// The owner's own threads are excluded: the parked sibling is part of the core
	// it bought, so its emulator/IO threads using it is the mode working as
	// intended, not a leak. Kernel threads are excluded by construction -- only
	// threads in an application's cgroup are sampled -- because ksoftirqd/N and
	// friends are bound to their CPU and legitimately live there.
	parkedSet := map[uint32]bool{}
	for _, cpu := range parked {
		parkedSet[cpu] = true
	}
	observed := 0
	for _, sample := range samples {
		if !sample.ranDuringInterval {
			continue
		}
		if sample.appUUID == owner.uuid {
			continue
		}
		observed++
		t.Expect(parkedSet).ToNot(HaveKey(sample.cpu),
			"thread %d (%q) of application %s ran on host CPU %d, which %q parks as the "+
				"idle SMT sibling of one of its cores; a foreign thread there contends "+
				"for that core's L1/L2 caches and its execution units with the pinned "+
				"vCPU on the other thread, which is the interference the workload asked "+
				"for whole cores to avoid (parked CPUs: %v)",
			sample.tid, sample.comm, sample.appUUID, sample.cpu, owner.spec.appName,
			parked)
	}
	t.Expect(observed).To(BeNumerically(">", 0),
		"none of the %d application thread observations over %d passes caught a thread "+
			"of an application other than %q that had actually run since the previous "+
			"pass, so the claim that no foreign thread ran on the parked CPUs %v rests "+
			"on no observation at all",
		len(samples), parkedSampleCount, owner.spec.appName, parked)
	evetest.Logger().Infof("sampled %d application thread observations over %d passes; "+
		"%d of them caught a thread of another application that had just run, none of "+
		"those on the parked CPUs %v", len(samples), parkedSampleCount, observed, parked)

	// And the parked CPUs stayed near idle throughout. This is the weakest of the
	// three -- see parkedIdleShareCeiling for why it cannot be tightened to zero
	// -- but it is the only one that would notice work arriving on a parked CPU
	// from somewhere the per-thread sampling does not look (a host-side helper
	// outside any app cgroup, or a thread that came and went between passes).
	for _, cpu := range parked {
		share, ok := nonIdleShare(cpuTimes, cpu)
		t.Expect(ok).To(BeTrue(),
			"/proc/stat carries no usable counters for the parked host CPU %d", cpu)
		evetest.Logger().Infof("parked host CPU %d spent %.1f%% of the sampling window "+
			"off the idle task", cpu, share*100)
		t.Expect(share).To(BeNumerically("<", parkedIdleShareCeiling),
			"parked host CPU %d spent %.1f%% of the sampling window off the idle task "+
				"while %q was holding it idle; over the same window the best-effort "+
				"application's cpuset %v carried %.2f CPUs of load, so this looks like "+
				"work that leaked onto a thread whose whole purpose is to stay unused so "+
				"the pinned vCPU on its sibling keeps the core's caches and execution "+
				"units to itself", cpu, share*100, owner.spec.appName, busy.cpuset,
			busyLoad)
	}
}

// parkedBusyLoadScript spins up bounded busy loops inside an application.
//
// timeout(1) bounds each loop, and the loops are detached so the SSH session
// that started them can return: the sampling below has to run while they are
// still going. The bound is what keeps a failed run from leaving a device
// spinning -- nothing here outlives parkedBusySeconds even if the test aborts.
const parkedBusyLoadScript = `i=0
while [ "$i" -lt @LOOPS@ ]; do
  nohup timeout @SECONDS@ sh -c 'while : ; do : ; done' >/dev/null 2>&1 </dev/null &
  i=$((i+1))
done
sleep 1
echo started
`

// startBusyLoad makes the best-effort application actually want CPU time, so
// that its absence from the parked CPUs is a statement about what it is allowed
// to use rather than about what it happened to need.
func startBusyLoad(t *GomegaWithT, device *evetest.EdgeDevice, app *placedApp) {
	waitForAppSSH(t, device, app.uuid)
	script := strings.ReplaceAll(parkedBusyLoadScript, "@LOOPS@",
		strconv.Itoa(parkedBusyLoops))
	script = strings.ReplaceAll(script, "@SECONDS@", strconv.Itoa(parkedBusySeconds))
	stdout, stderr, err := device.RunShellScriptInsideApp(app.uuid, appAuth, script,
		placementShellTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(),
		"failed to start the busy loops inside %q (stderr: %s)", app.spec.appName, stderr)
	t.Expect(strings.TrimSpace(stdout)).To(Equal("started"),
		"the busy loops inside %q did not report starting (stdout: %q)",
		app.spec.appName, stdout)
	evetest.Logger().Infof("started %d busy loop(s) for %ds inside %q",
		parkedBusyLoops, parkedBusySeconds, app.spec.appName)
}

// parkedSamplingScript walks the device parkedSampleCount times and reports, for
// every thread of every named application, the CPU it last ran on and how much
// CPU time it has used -- plus the per-CPU counters of /proc/stat before the
// first pass and after the last.
//
// It is one script rather than a call per sample because each round trip costs an
// SSH exchange, and the window has to stay short enough to sit inside the busy
// load. Threads are found by matching the application UUID in a process's cgroup
// path, which also means kernel threads are never sampled: they are in no
// application cgroup, and ksoftirqd/N or rcuc/N legitimately run on a parked CPU.
//
// The cumulative CPU time is reported alongside the CPU because the CPU on its
// own is a leftover, not an observation: it only says where the thread ran the
// last time it ran, which may predate the cpuset it is confined to now. Rising
// CPU time between two passes is what turns it into evidence.
//
// A thread's utime, stime and last-run CPU are fields 14, 15 and 39 of
// /proc/<tid>/stat. The comm field can contain spaces and parentheses, so the
// fields before them are cut off at the closing parenthesis rather than counted,
// which shifts the indices by two. comm itself is reported last so that spaces in
// it cannot shift anything.
const parkedSamplingScript = `UUIDS='@UUIDS@'

awk '/^cpu[0-9]/ {print "STAT begin " $0}' /proc/stat

i=0
while [ "$i" -lt @SAMPLES@ ]; do
  for p in /proc/[0-9]*; do
    cg=$(cat "$p/cgroup" 2>/dev/null | tr '\n' ' ')
    owner=""
    for u in $UUIDS; do
      case "$cg" in
        *"$u"*) owner=$u; break ;;
      esac
    done
    [ -n "$owner" ] || continue
    for td in "$p"/task/[0-9]*; do
      fields=$(awk '{sub(/.*\) /, ""); print $12+$13, $37}' "$td/stat" 2>/dev/null)
      [ -n "$fields" ] || continue
      echo "THREAD $owner ${td##*/} $fields $(cat "$td/comm" 2>/dev/null)"
    done
  done
  i=$((i+1))
  sleep 1
done

awk '/^cpu[0-9]/ {print "STAT end " $0}' /proc/stat
`

// threadSample is one observation of one application thread: the CPU it last ran
// on, and whether it demonstrably ran since the previous pass -- which is what
// makes that CPU an observation rather than a leftover.
type threadSample struct {
	appUUID uuid.UUID
	tid     int
	comm    string
	cpu     uint32
	// ranDuringInterval is true if the thread's cumulative CPU time grew since
	// the previous pass, i.e. it was scheduled in between and therefore really
	// ran on cpu. The first observation of a thread is never marked: there is
	// nothing to compare it against.
	ranDuringInterval bool
}

// cpuTimeWindow holds the per-CPU /proc/stat counters from the start and the end
// of the sampling window, so how each CPU spent the window can be derived.
type cpuTimeWindow struct {
	begin map[uint32][]uint64
	end   map[uint32][]uint64
}

// sampleAppThreadCPUs runs the sampling script and parses it.
func sampleAppThreadCPUs(t *GomegaWithT, device *evetest.EdgeDevice,
	appUUIDs []uuid.UUID) ([]threadSample, cpuTimeWindow) {
	uuids := make([]string, 0, len(appUUIDs))
	for _, appUUID := range appUUIDs {
		uuids = append(uuids, appUUID.String())
	}
	script := strings.ReplaceAll(parkedSamplingScript, "@UUIDS@", strings.Join(uuids, " "))
	script = strings.ReplaceAll(script, "@SAMPLES@", strconv.Itoa(parkedSampleCount))
	stdout, stderr, err := device.RunShellScript(script, parkedSampleTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(),
		"failed to sample where the applications' threads run (stderr: %s)", stderr)

	window := cpuTimeWindow{
		begin: map[uint32][]uint64{},
		end:   map[uint32][]uint64{},
	}
	// Cumulative CPU time per thread as of its previous observation, so a rise can
	// be detected without keeping every sample of every thread.
	lastCPUTime := map[int]uint64{}
	var samples []threadSample
	for _, line := range strings.Split(stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		switch fields[0] {
		case "STAT":
			cpu, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "cpu"), 10, 32)
			if err != nil {
				continue
			}
			var values []uint64
			for _, field := range fields[3:] {
				value, err := strconv.ParseUint(field, 10, 64)
				if err != nil {
					break
				}
				values = append(values, value)
			}
			if fields[1] == "begin" {
				window.begin[uint32(cpu)] = values
			} else {
				window.end[uint32(cpu)] = values
			}
		case "THREAD":
			appUUID, err := uuid.FromString(fields[1])
			if err != nil {
				continue
			}
			tid, err := strconv.Atoi(fields[2])
			if err != nil {
				continue
			}
			cpuTime, err := strconv.ParseUint(fields[3], 10, 64)
			if err != nil {
				continue
			}
			cpu, err := strconv.ParseUint(fields[4], 10, 32)
			if err != nil {
				continue
			}
			previous, seen := lastCPUTime[tid]
			lastCPUTime[tid] = cpuTime
			samples = append(samples, threadSample{
				appUUID: appUUID,
				tid:     tid,
				// comm is the rest of the line: it may itself contain spaces (a
				// QEMU vCPU thread is "CPU 0/KVM").
				comm:              strings.Join(fields[5:], " "),
				cpu:               uint32(cpu),
				ranDuringInterval: seen && cpuTime > previous,
			})
		}
	}
	t.Expect(samples).ToNot(BeEmpty(),
		"no application thread was found on the device at all, so nothing was "+
			"sampled; the assertions about where threads did *not* run would be "+
			"vacuous (script output: %s)", stdout)
	return samples, window
}

// nonIdleShare is the fraction of the sampling window a CPU spent off the idle
// task, from its /proc/stat counters. The second result is false if the CPU was
// not reported at both ends of the window.
func nonIdleShare(window cpuTimeWindow, cpu uint32) (float64, bool) {
	begin, okBegin := window.begin[cpu]
	end, okEnd := window.end[cpu]
	// user, nice, system, idle, iowait, ... -- iowait is counted as idle, which
	// on a CPU nothing is allowed to run on is the same thing anyway.
	if !okBegin || !okEnd || len(begin) < 5 || len(end) < 5 {
		return 0, false
	}
	var total, idle float64
	for i := range end {
		if i >= len(begin) {
			break
		}
		total += float64(end[i] - begin[i])
		if i == 3 || i == 4 {
			idle += float64(end[i] - begin[i])
		}
	}
	if total <= 0 {
		return 0, false
	}
	return (total - idle) / total, true
}

// nonIdleCPUEquivalents sums the non-idle share of the given CPUs, i.e. how many
// whole CPUs' worth of work happened on them during the window. It is the
// measure of the load the best-effort application generated, and has to be a sum
// rather than a per-CPU share because that load is free to float across the
// app's whole cpuset.
func nonIdleCPUEquivalents(window cpuTimeWindow, cpus []uint32) float64 {
	var sum float64
	for _, cpu := range cpus {
		if share, ok := nonIdleShare(window, cpu); ok {
			sum += share
		}
	}
	return sum
}
