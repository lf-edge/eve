// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package apps_test holds the EVE application-lifecycle tests.
//
// Helper layout. helpers_test.go holds the general app-lifecycle helpers shared
// by the whole package (device name, image and NI constants, app SSH auth,
// addLocalNI, singleVIFWithSSH, deleteAppAndWait, waitForAppSSH). The purge
// tests add helpers of their own, in files named for the STATE THEY OBSERVE
// rather than for the test that first needed them, each owning both its readers
// and its invariants:
//
//	fixtures_test.go        purge-suite device requirements and app config
//	deviceaccess_test.go    the only place that shells out to a device: kubectl,
//	                        cat, ls, test -e
//	appstate_test.go        pillar's own view of the app - pubsub and persisted
//	                        state keyed by app UUID
//	appworkload_test.go     where the app is running as the hypervisor sees it -
//	                        VMIRS objects, qemu domain state directories
//	appvolumes_test.go      the app's disk in all three forms - VolumeStatus,
//	                        PVC, file under /persist - and the storage invariants
//	<topic>_assertions_test.go
//	                        assertions meaningless outside that topic
//
// Where does a new helper go?
//
//	Q0  Is it generally useful to any app test?
//	      Yes -> helpers_test.go
//	Q1  Does it touch a device at all?
//	      No  -> fixtures_test.go
//	Q2  Does it shell out (ssh/kubectl/cat/ls)?
//	      Yes -> the raw call goes in deviceaccess_test.go; the caller goes to Q3
//	Q3  Would it still make sense in a test that never purges anything?
//	      Yes -> the subject file for what it observes
//	      No  -> <topic>_assertions_test.go
//
// A new test scenario adds one <topic>_<scenario>_test.go and no helper file. A
// new topic (restart, delete, snapshot) adds its tests plus at most one
// <topic>_assertions_test.go and reuses the subject files unchanged. A new
// observation subject adds one app<Subject>_test.go. A new ACCESS MECHANISM -
// another kubectl verb, virsh, a new path - adds no file at all; extend
// deviceaccess_test.go.
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
// once and every subtest reads it via evetest.GetHypervisorParameterValue().
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
	)
}

// TestVMAppPurgeSuite groups the app-purge tests: a plain purge
// (TestVMAppPurgeBaseline), a purge issued while the device is powered off
// (TestVMAppPurgeAfterPowerCycle - a deterministic reproduction of a
// reboot-during-purge bug), and a purge issued after the app's designated node
// has failed over (TestVMAppPurgeDuringFailover).
//
// It is separate from TestAppsSuite because these tests assert on which
// generation of a workload exists, so each one needs a device created from
// scratch (see purgeDeviceRequirements) rather than the warm device TestAppsSuite
// reuses across its subtests.
//
// The baseline and failover tests need a cluster and so are pinned to Kubevirt
// (eve-k). The power-cycle test runs twice, once per hypervisor: Kubevirt is
// where the duplicate-generation defect lives, and kvm is the control that
// localises it there - see that test's own comment for what each variant can
// and cannot assert.
func TestVMAppPurgeSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{Test: TestVMAppPurgeBaseline},
		evetest.TestCase{
			Test: TestVMAppPurgeAfterPowerCycle,
			Variants: []evetest.TestVariant{
				{
					Name: "TestVMAppPurgeAfterPowerCycleKubevirt",
					Parameters: []evetest.TestParameterValue{
						{Key: evetest.HypervisorParameterKey,
							Value: evetest.HypervisorKubevirt},
					},
				},
				{
					Name: "TestVMAppPurgeAfterPowerCycleKVM",
					Parameters: []evetest.TestParameterValue{
						{Key: evetest.HypervisorParameterKey,
							Value: evetest.HypervisorKVM},
					},
				},
			},
		},
		evetest.TestCase{Test: TestVMAppPurgeDuringFailover},
	)
}
