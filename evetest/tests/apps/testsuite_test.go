// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package apps_test holds the EVE application-lifecycle tests.
//
// On master this package carries the full suite rewritten from Eden
// (restart, halt, purge, metadata, ...); on this branch only the load test
// below was backported, so the suite registers just that one.
//
// Subtests
// --------
//   - TestLotsOfApps -- deploys more app instances than volumemgr's worker
//     pool has slots and checks that all of them come up (regression test
//     for the pool-saturation fixes).
package apps_test

import (
	"testing"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
)

// TestAppsSuite drives the application-lifecycle scenarios in this package.
func TestAppsSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestLotsOfApps,
		},
	)
}

func appHasError(info *eveinfo.ZInfoApp) (string, bool) {
	stop := info.State == eveinfo.ZSwState_ERROR
	if stop {
		return "Application instance is in error state", true
	}
	return "", false
}
