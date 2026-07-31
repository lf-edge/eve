// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package apps_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestAppsSuite drives application-lifecycle scenarios that are not
// specifically about networking (regression tests for zedmanager/volumemgr
// bugs, VNC console access, etc.) -- kept separate from
// evetest/tests/networking's TestApplicationConnectivitySuite, which is
// already large and focused on network connectivity.
//
// Subtests
// --------
//   - TestPurgeNeverActivatedApp -- regression test for a zedmanager bug
//     where purging an app that never activated (failed image download)
//     would leave it stuck instead of recovering.
//   - TestVNC -- VNC access to a VM app, a container app, and the container
//     app's shim VM console.
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
	)
}
