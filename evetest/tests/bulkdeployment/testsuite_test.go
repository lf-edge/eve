// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package bulkdeployment_test holds the bulk-deployment test: a whole
// workload applied to one device in a single configuration change. It needs
// a powerful host, so it runs in a suite of its own, tagged
// evetest.TagHeavyTest, apart from the application tests in tests/apps.
//
// Helper layout: bulkdeploy_helpers_test.go holds what the test deploys and
// drives -- the test container and its credentials, the churn inside the
// containers, the real workload images and the wait for RUNNING -- and
// controlplane_helpers_test.go the observers of EVE's own control plane
// under load: the log signatures of an agent falling behind and of
// watchdog(8) arming, and a sampler of the eve cgroup's budget.
package bulkdeployment_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestBulkDeploymentSuite runs the bulk-deployment test.
//
// Subtests
// --------
//   - TestBulkAppDeployment -- a batch of 50 container apps applied in one
//     configuration change all reach RUNNING, and stay up through a
//     power cycle that restarts them all at once, without the device
//     rebooting on its own or any EVE service stalling long enough to arm
//     the watchdog; regression test for a well-provisioned server
//     resetting itself under a bulk deployment because EVE's own memory
//     and CPU budgets do not scale with the hardware. Needs a device of
//     at least 8 vCPUs, 32 GiB of RAM and 64 GiB of disk.
func TestBulkDeploymentSuite(test *testing.T) {
	evetest.Init(test, evetest.WithTags(evetest.TagHeavyTest))
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestBulkAppDeployment,
		},
	)
}
