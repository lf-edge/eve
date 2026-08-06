// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diag_test

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestDiagSuite drives the scenarios covering diag, EVE's on-device diagnostic
// summary. diag reports nothing through the EVE API, so these are the only
// tests that notice it losing a section, going silent, or reporting errors on a
// healthy device.
//
// The suite declares the HYPERVISOR parameter once; every subtest deploys an
// application to read the summary from the metadata server and reads the value
// via evetest.GetHypervisorParameterValue().
//
// Subtests
// --------
//   - TestDiagOutput -- the full summary on a healthy onboarded device, read
//     through GET /eve/v1/diag, plus a cross-check of the reported cluster
//     storage state against volumemgr's own publication.
func TestDiagSuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestDiagOutput,
		},
	)
}
