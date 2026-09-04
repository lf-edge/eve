// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test the kernel-isolated CPU pool: a node booted with isolcpus keeps those
// cores for workloads that ask for hard isolation, and away from everything else.

package apps_test

import (
	"fmt"
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// isolatedCPUList is the isolcpus range the device is booted with.
//
// It has to be chosen before the device exists, so it cannot be derived from the
// topology. QEMU numbers a sockets=1,cores=N,threads=2 guest so that physical
// core c owns logical CPUs 2c and 2c+1, which makes 4-7 exactly cores 2 and 3 --
// two whole cores, and not the lowest-numbered ones, so a workload that landed
// on them cannot have got there by taking whatever was first.
//
// The assumption is verified rather than trusted: phase 2 fails with the real
// topology in the message if this range does not cover whole cores, because a
// range that straddles cores would silently turn every later assertion into a
// weaker one.
const isolatedCPUList = "4-7"

// isolatedDevName is a device of its own: the isolcpus setting is a boot
// parameter, so it cannot be applied to the warm device the other CPU placement
// tests share.
const isolatedDevName = "edge-dev-isolcpus"

// nohz_full is set alongside isolcpus, mirroring EVE's own set_isolcpus grub
// hook (pkg/grub/rootfs.cfg). isolcpus alone keeps the load balancer off a core;
// it does not stop the scheduler tick, so the two belong together on a node
// whose whole point is undisturbed cores.
func isolationGrubOptions() []string {
	return []string{fmt.Sprintf(
		`set_global dom0_extra_args "$dom0_extra_args isolcpus=%s nohz_full=%s "`,
		isolatedCPUList, isolatedCPUList)}
}

// isolatedWholeCoreApp asks for whole physical cores that the kernel isolates,
// i.e. the hard isolation tier. It is the only kind of workload allowed onto the
// isolated cores.
func isolatedWholeCoreApp(appName string, vCPUs int, sshFwdPort uint16) cpuPlacementApp {
	return cpuPlacementApp{
		mode:       "whole-core-smt-hard-isolation",
		appName:    appName,
		vCPUs:      vCPUs,
		sshFwdPort: sshFwdPort,
		placement: evetest.CPUPlacementConfig{
			Policy:         eveconfig.CpuPolicy_CPU_POLICY_DEDICATED,
			FullPCPUsOnly:  true,
			ThreadsPerCore: 2,
			NUMAPolicy:     eveconfig.NumaPolicy_NUMA_POLICY_BEST_EFFORT,
			IsolationTier:  eveconfig.IsolationTier_ISOLATION_TIER_HARD,
		},
		wantPinned:       true,
		wantGuestThreads: 2,
		coreRule:         coreRuleSiblingPairs,
	}
}

// TestCPUIsolatedPool verifies that kernel CPU isolation is a resource the
// device hands out, not a fact it merely reports.
//
// The isolated set used to be reported to the controller and otherwise ignored:
// no workload could ask for it, and nothing kept other workloads off it, so an
// operator who set isolcpus got a number in the device info and no change in
// behaviour. What the setting has to mean is that those cores belong to the
// workloads that request isolation and to nobody else -- including EVE's own
// housekeeping, since isolcpus keeps the scheduler's load balancer away but
// honours an explicit affinity, so a cpuset spanning an isolated CPU puts work
// there regardless.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- isolation is not network dependent; one
//     mgmt+apps port is enough to run the apps and reach them over SSH.
//
// Device configuration
// --------------------
//   - A device of its own (isolatedDevName), booted with isolcpus/nohz_full
//     injected through /config/grub.cfg. It cannot share the warm 8-CPU device
//     the other placement tests use, because this is a boot parameter.
//   - 8 CPUs, 2 threads per core: 4 physical cores, two isolated (see
//     isolatedCPUList) and two not, so both halves of the rule have room.
//   - DevInfoInterval lowered, because the node's CPU pool report rides on
//     ZInfoDevice and a change to it is not itself a publish trigger.
//   - Three apps: one asking for hard isolation, one asking for whole cores
//     without isolation, and one best-effort.
//
// Phases / assertions
// -------------------
//  1. isolation-applied: /proc/cmdline carries isolcpus and the kernel's own
//     /sys/devices/system/cpu/isolated agrees. Asserted against sysfs rather
//     than the command line alone: a malformed or capped parameter parses fine
//     and isolates nothing, which would make every later phase vacuous.
//  2. whole-core check: the isolated CPUs cover complete physical cores, which
//     is what isolatedCPUList assumes and what the hard tier needs.
//  3. pool-reported: the node advertises a CPU_POOL_KIND_ISOLATED pool holding
//     exactly the kernel's isolated set, and reports it as overlapping the other
//     pools rather than partitioning with them.
//  4. per app: each of the three is placed as its policy asks (the shared
//     assertions, same as the other placement tests).
//  5. isolation-honoured: the hard-tier app's CPUs lie wholly inside the
//     isolated set; the other two touch none of it. This is the assertion the
//     whole test exists for, in both directions -- "the workload that asked got
//     them" is only half a guarantee without "the ones that did not, did not".
//  6. housekeeping-clear: the isolated CPUs are absent from the node's free
//     housekeeping capacity, so nothing the device places later lands there.
//
// Test params
// -----------
//   - HYPERVISOR. Skipped under Kubevirt, where the kubelet selects CPUs rather
//     than the pillar allocator this test exercises.
//
// Suite placement
// ---------------
//   - TestAppsSuite, last of the CPU placement tests: it is the only one that
//     needs a device with a different kernel command line, so it does not
//     disturb the device the others share.
func TestCPUIsolatedPool(test *testing.T) {
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
			Name:              isolatedDevName,
			MinCPUs:           8,
			ThreadsPerCore:    2,
			WithHypervisor:    hypervisor,
			WithGrubOptions:   isolationGrubOptions(),
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(isolatedDevName)
	evetest.Checkpoint("setup-done")

	// Phase 1: the kernel applied the isolation, not just accepted the argument.
	cmdlineValue, present, err := device.KernelCmdlineParam("isolcpus")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(present).To(BeTrue(),
		"the device did not boot with isolcpus; the grub option did not reach "+
			"/config/grub.cfg or was not applied")
	t.Expect(cmdlineValue).To(Equal(isolatedCPUList))

	isolated, err := device.IsolatedCPUs()
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(isolated).To(Equal(evetest.ParseCPUList(isolatedCPUList)),
		"the kernel isolates %v, not the requested %s: the parameter was capped "+
			"or rejected, and everything below would pass vacuously",
		isolated, isolatedCPUList)
	evetest.Logger().Infof("kernel command line isolates CPUs %v (nohz_full: %v)",
		isolated, mustNohzFull(t, device))
	evetest.Checkpoint("isolation-applied")

	// Phase 2: the isolated set has to cover whole physical cores. The hard tier
	// is served in whole cores, so a range straddling two of them would leave
	// nothing placeable and turn phase 5 into a check of an error path.
	topo, err := device.HostCPUTopology()
	t.Expect(err).ToNot(HaveOccurred())
	isolatedCores := wholeIsolatedCores(topo, isolated)
	t.Expect(isolatedCores).ToNot(BeEmpty(),
		"isolcpus=%s covers no complete physical core on this device (topology: "+
			"%+v). Adjust isolatedCPUList to match the guest's CPU numbering.",
		isolatedCPUList, topo.CPUs)
	evetest.Logger().Infof("isolated CPUs %v form %d whole physical core(s)",
		isolated, len(isolatedCores))
	evetest.Checkpoint("whole-core-check")

	devConfig := evetest.NewEdgeDeviceConfig(isolatedDevName)
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

	// Two vCPUs each: the isolated app needs one of the two isolated cores, the
	// unisolated whole-core app one of the other two, and the best-effort app
	// shares whatever is left.
	specs := []cpuPlacementApp{
		isolatedWholeCoreApp("isolated-app", 2, 2201),
		wholeCoreSMTApp("unisolated-app", 2, 2202),
		sharedApp("besteffort-app", 2, 2203),
	}
	deployed := make([]*placedApp, 0, len(specs))
	for _, spec := range specs {
		appUUID := devConfig.AddApplication(placementAppConfig(spec, niUUID, 0))
		deployed = append(deployed, &placedApp{spec: spec, uuid: appUUID})
	}
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("config-applied")

	// Phase 3: the node advertises the isolated pool, and advertises it as
	// exactly what the kernel isolates. This is what a controller reads to know
	// the node has isolation to give, so a set that drifts from the kernel's is
	// worse than no report at all.
	report := awaitCPUPoolReport(t, device, "its isolated CPU pool",
		func(g Gomega, report cpuPoolReport) {
			g.Expect(report.isolated).ToNot(BeNil(),
				"the node reports no isolated CPU pool despite booting with isolcpus")
			g.Expect(report.isolated.GetCpuIds()).To(Equal(isolated))
		})
	// The isolated pool overlaps the other two rather than partitioning with
	// them, so its CPUs must also appear in one of them. A report that dropped
	// them from both would describe a node with CPUs belonging to no pool at all.
	for _, cpu := range isolated {
		t.Expect(append(report.housekeeping.GetCpuIds(), report.dedicated.GetCpuIds()...)).
			To(ContainElement(cpu),
				"isolated CPU %d appears in no other pool; the isolated set must "+
					"overlap the housekeeping/dedicated partition, not replace it",
				cpu)
	}
	evetest.Checkpoint("pool-reported")

	for _, app := range deployed {
		device.WaitUntilAppIsRunning(app.uuid, placementRunningTimeout)
	}
	evetest.Checkpoint("apps-running")

	logPlacementDiagnostics(device, appUUIDs(deployed), placementShellTimeout)

	// Phase 4: each app placed as its policy asks, by the shared assertions.
	for _, app := range deployed {
		assertAppPlacement(t, device, topo, app, true)
	}
	assertPlacementSetInvariants(t, device, topo, deployed)
	evetest.Checkpoint("placement-verified")

	// Phase 5: the point of the test, in both directions.
	for _, app := range deployed {
		onIsolated := intersectCPUs(app.dedicated, isolated)
		if app.spec.appName == "isolated-app" {
			t.Expect(app.dedicated).ToNot(BeEmpty())
			t.Expect(onIsolated).To(Equal(uniqueCPUs(app.dedicated)),
				"%s asked for hard isolation but holds CPUs outside the isolated "+
					"set %v: it has %v, of which only %v are isolated",
				app.spec.appName, isolated, app.dedicated, onIsolated)
			continue
		}
		t.Expect(onIsolated).To(BeEmpty(),
			"%s did not ask for isolation but holds isolated CPUs %v; the "+
				"operator's isolation is spent on a workload that never wanted it",
			app.spec.appName, onIsolated)
		// A best-effort workload's cpuset is the housekeeping set, which is the
		// other way onto an isolated CPU: nothing is dedicated to it, so the
		// dedicated check above says nothing about where it may run.
		t.Expect(intersectCPUs(app.cpuset, isolated)).To(BeEmpty(),
			"%s may run on isolated CPUs: its cpuset is %v",
			app.spec.appName, app.cpuset)
	}
	evetest.Checkpoint("isolation-honoured")

	// Phase 6: the node must not offer the isolated CPUs as ordinary free
	// capacity either, or the next workload the controller places lands there.
	awaitCPUPoolReport(t, device, "housekeeping capacity clear of the isolated set",
		func(g Gomega, report cpuPoolReport) {
			g.Expect(intersectCPUs(report.housekeeping.GetFreeCpuIds(), isolated)).
				To(BeEmpty(),
					"the node advertises isolated CPUs as free housekeeping capacity")
		})
	evetest.Checkpoint("housekeeping-clear")

	for _, app := range deployed {
		deleteAppAndWait(t, device, devConfig, app.uuid)
	}
}

// wholeIsolatedCores returns one representative CPU per physical core all of
// whose SMT siblings are isolated. A half-isolated core is no use to a workload
// that wants to be left alone -- the kernel still schedules freely on the other
// thread -- so those do not count.
func wholeIsolatedCores(topo evetest.HostTopology, isolated []uint32) []uint32 {
	inIsolated := make(map[uint32]bool, len(isolated))
	for _, cpu := range isolated {
		inIsolated[cpu] = true
	}
	seen := map[uint32]bool{}
	var out []uint32
	for _, cpu := range isolated {
		host, known := topo.CPUs[cpu]
		if !known || seen[cpu] {
			continue
		}
		whole := true
		for _, sibling := range host.Siblings {
			seen[sibling] = true
			if !inIsolated[sibling] {
				whole = false
			}
		}
		if whole {
			out = append(out, cpu)
		}
	}
	return out
}

// mustNohzFull reads the tick-free set for the log. It is not asserted on: the
// hard tier is served out of the isolated set, and whether the tick was also
// shed is a property of the kernel build, not of the placement under test.
func mustNohzFull(t *GomegaWithT, device *evetest.EdgeDevice) []uint32 {
	nohzFull, err := device.NohzFullCPUs()
	t.Expect(err).ToNot(HaveOccurred())
	return nohzFull
}
