// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package lps_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestLPSSuite is the entry point for Local Profile Server (LPS) tests.
// See https://github.com/lf-edge/eve-api/blob/main/PROFILE.md
//
// Subtests
// --------
//   - TestProfile -- device-level (GlobalProfile) and LPS-driven
//     (local profile) app filtering by ProfileList.
//   - TestRadioSilence -- LPS-driven radio-silence toggling, verified via
//     both the LPS and EVE's own ZedAgentStatus, including persistence of
//     the imposed state across a controller-driven reboot.
//   - TestAppLocalInfo -- LPS appinfo reporting and LPS-driven
//     COMMAND_PURGE/COMMAND_RESTART, alongside the equivalent
//     controller-driven operations (whose counters EVE sums with the
//     LPS-driven ones).
//   - TestDevLocalInfo -- LPS devinfo reporting and LPS-driven
//     COMMAND_SHUTDOWN/COMMAND_GRACEFUL_POWEROFF device commands.
//   - TestNetworkLocalChanges -- per-port AllowLocalModifications /
//     LPS network-config override behavior.
func TestLPSSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestProfile,
		},
		evetest.TestCase{
			Test: TestRadioSilence,
		},
		evetest.TestCase{
			Test: TestAppLocalInfo,
		},
		evetest.TestCase{
			Test: TestDevLocalInfo,
		},
		evetest.TestCase{
			Test: TestNetworkLocalChanges,
		},
	)
}
