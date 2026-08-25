// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package apps_test holds the EVE application-lifecycle tests.
//
// Helper layout. Every file whose name ends in _helpers_test.go contains no
// tests, only helpers; a file named for a test contains only that test, so the
// tests themselves stay easy to find.
//
// helpers_test.go holds the general app-lifecycle helpers shared by the whole
// package (device name, image and NI constants, app SSH auth, addLocalNI,
// singleVIFWithSSH, deleteAppAndWait, waitForAppSSH). The remaining helper files
// are named for the STATE THEY OBSERVE rather than for the test that first
// needed them, and each owns both its readers and the invariants about that
// state:
//
//	appstate_helpers_test.go     pillar's own view of the app - pubsub and
//	                             persisted state keyed by app UUID
//	appworkload_helpers_test.go  where the app is running as the hypervisor sees
//	                             it - VMIRS objects (and the kubectl plumbing for
//	                             them), qemu domain state directories
//	appvolumes_helpers_test.go   the app's disk in all three forms -
//	                             VolumeStatus, PVC, file under /persist - and the
//	                             storage invariants
//	<topic>_helpers_test.go      what one topic's tests build before they run,
//	                             plus the assertions meaningless outside it;
//	                             purge_helpers_test.go is the worked example
//
// Reading a file, listing a directory, testing for a path and flushing caches
// are NOT here: they are EdgeDevice methods in the framework
// (evetest/edgedevice.go), so every test package gets them. Prefer adding one
// there over a local helper whenever the operation says nothing about apps.
//
// Where does a new helper go?
//
//	Q0  Is it generic device access, useful to any test package?
//	      Yes -> an EdgeDevice method in evetest/edgedevice.go
//	Q1  Is it generally useful to any app test?
//	      Yes -> helpers_test.go
//	Q2  Would it still make sense in a test that never purges anything?
//	      Yes -> the helper file for the state it observes
//	      No  -> <topic>_helpers_test.go
//
// A new test scenario adds one <topic>_<scenario>_test.go and no helper file. A
// new topic (restart, delete, snapshot) adds its tests plus at most one
// <topic>_helpers_test.go and reuses the observation files unchanged. A new
// observation subject adds one app<Subject>_helpers_test.go.
package apps_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestAppsSuite drives application-lifecycle scenarios that are not
// specifically about networking (regression tests for zedmanager/volumemgr
// bugs, VNC console access, how configuration and data flow between the
// controller, EVE and a running application) -- kept separate from
// evetest/tests/networking's TestApplicationConnectivitySuite, which is
// already large and focused on network connectivity.
//
// Every subtest deploys at least one application and therefore shares the
// HYPERVISOR parameter -- the suite declares evetest.HypervisorParameter()
// once and each subtest reads it via evetest.GetHypervisorParameterValue(),
// except the two purge tests noted below.
//
// Subtests
// --------
//   - TestPurgeNeverActivatedApp -- regression test for a zedmanager bug
//     where purging an app that never activated (failed image download)
//     would leave it stuck instead of recovering.
//   - TestVNC -- VNC access to a VM app, a container app, and the container
//     app's shim VM console.
//   - TestAppInstanceMetadata -- app posts metadata to the link-local
//     metadata server; EVE reports it to the controller.
//   - TestAppUserData -- plain key=value user-data becomes container
//     environment; cloud-config write_files is applied once per user-data
//     version and survives an app restart.
//   - TestAppLogs -- application stdout is collected and delivered to the
//     controller, including after the app is stopped and started again.
//   - TestAppRestart -- controller-requested restarts (restart counter
//     bumps, no purge) bring the app back to RUNNING; regression test for
//     a stale QMP handler quitting the re-created domain.
//   - TestCPUPlacementOnePerCore -- an app asking for dedicated whole
//     physical cores gets one vCPU per distinct core, each pinned 1:1.
//   - TestCPUPlacementWholeCoreSMT -- the same, but both SMT siblings of each
//     core become vCPUs and the guest is told which vCPUs are siblings.
//   - TestCPUPlacementMultiApp -- whole-core-SMT, one-per-core and best-effort
//     apps deployed together: each placed as its policy asks, on disjoint CPUs
//     and disjoint physical cores, with housekeeping left intact.
//   - TestCPUPlacementStability -- the same set survives a reboot, a staggered
//     (start-delayed) start and a reverse restart order on the same host CPUs.
//   - TestCPUPlacementParkedSiblings -- the SMT sibling a one-per-core app leaves
//     unused is consumed by it, not spare: no other workload gets it in its
//     cpuset, the node does not advertise it as free, and nothing is ever
//     observed running on it.
//   - TestCPUPlacementNeedsRepack -- on a node fragmented by thread-granular
//     workloads (free threads, no free whole core) a whole-core app is refused
//     with cpu.placement.needs_repack rather than insufficient, and a repack
//     really does let it run.
//   - TestCPUPlacementFailsClosed -- every class of unsatisfiable placement
//     request (odd vCPUs with whole-core SMT, hard isolation tier on a node
//     without kernel isolation, invalid policy) is refused with its own
//     error_code at ERROR severity, never boots, and leaves the node's dedicated
//     CPU pool unchanged.
//   - TestCPUIsolatedPool -- on a node booted with isolcpus, the isolated cores
//     go to the app that asks for hard isolation and to nothing else: the other
//     workloads, and the node's free housekeeping capacity, stay off them.
//   - TestVMAppPurgeReplacesVMIRS -- a plain purge of a healthy app leaves
//     exactly one VMIRS, named for the new generation. Kubevirt only; skips
//     on any other hypervisor.
//   - TestVMAppPurgeAfterPowerCycle -- a purge issued while the device is
//     powered off, which is where a reboot lands in the middle of the purge
//     deterministically rather than by chance. Meaningful on every hypervisor.
//
// The two purge tests come last because they are the expensive ones: they
// assert on which generation of a workload exists, so each needs a device
// created from scratch (purgeDeviceRequirements) rather than the warm device
// the earlier subtests reuse.
//
// Neither declares hypervisor variants. The whole suite is run once per
// hypervisor (EVETEST_HYPERVISOR=kvm|kubevirt), so a variant here would run
// the same combination a second time; a test that cannot say anything on the
// hypervisor it was given skips instead.
func TestAppsSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestPurgeNeverActivatedApp,
		},
		evetest.TestCase{
			Test: TestVNC,
		},
		evetest.TestCase{
			Test: TestAppInstanceMetadata,
		},
		evetest.TestCase{
			Test: TestAppUserData,
		},
		evetest.TestCase{
			Test: TestAppLogs,
		},
		evetest.TestCase{
			Test: TestAppRestart,
		},
		evetest.TestCase{
			Test: TestCPUPlacementOnePerCore,
		},
		evetest.TestCase{
			Test: TestCPUPlacementWholeCoreSMT,
		},
		// Right after TestCPUPlacementWholeCoreSMT: it needs the same device
		// (8 CPUs, 2 threads per core), so the framework can reuse the VM.
		evetest.TestCase{
			Test: TestCPUPlacementMultiApp,
		},
		// Also needs the 8-CPU, 2-threads-per-core device, so it follows the
		// tests that already require one.
		evetest.TestCase{
			Test: TestCPUPlacementStability,
		},
		// Same device again.
		evetest.TestCase{
			Test: TestCPUPlacementParkedSiblings,
		},
		// Also the 8-CPU, 2-threads-per-core device: it needs SMT siblings to
		// fragment the node in the first place.
		evetest.TestCase{
			Test: TestCPUPlacementNeedsRepack,
		},
		// Same 8-CPU, 2-threads-per-core device: the whole-core-SMT holder
		// application it keeps running throughout needs real SMT siblings.
		evetest.TestCase{
			Test: TestCPUPlacementFailsClosed,
		},
		// Last of the CPU placement tests: it is the only one needing a device
		// booted with a different kernel command line (isolcpus), so it comes
		// after everything that shares the warm 8-CPU device.
		evetest.TestCase{
			Test: TestCPUIsolatedPool,
		},
		evetest.TestCase{
			Test: TestVMAppPurgeReplacesVMIRS,
		},
		evetest.TestCase{
			Test: TestVMAppPurgeAfterPowerCycle,
		},
	)
}
