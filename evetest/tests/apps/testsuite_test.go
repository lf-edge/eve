// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

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
		evetest.TestCase{
			Test: TestAppRestart,
		},
	)
}
