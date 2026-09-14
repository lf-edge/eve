// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestSecuritySuite drives every device-security scenario in this package.
//
// The package is backported from master together with the vault/attestation
// file-permission hardening; on this branch it carries a single scenario:
//
// Subtests
// --------
//   - TestAppVTPM -- per-app vTPM: the app's SWTPM instance runs unprivileged
//     with TPM-sealed state encryption, and the guest can consume the TPM.
func TestSecuritySuite(test *testing.T) {
	evetest.Init(test)
	defer func() { _ = evetest.Close() }()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestAppVTPM,
		},
	)
}
