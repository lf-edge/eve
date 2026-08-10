// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"testing"

	"github.com/lf-edge/eve/evetest"
)

// TestSecuritySuite drives every device-security scenario in this package.
//
// Subtests
// --------
//   - TestAppArmorEnabled -- kernel AppArmor status flag.
//   - TestVCom -- vcomlink (TPM-over-vsock) request/response from inside a VM app.
//   - TestControllerSigningCertChange -- rotation of the controller certificate
//     signing API responses; device must recover config processing on its own.
//   - TestControllerEncryptCertChange -- rotation of the controller ECDH
//     certificate; object-encrypted configuration must be migrated and survive.
func TestSecuritySuite(test *testing.T) {
	evetest.Init(test)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	evetest.RunTestSuite(
		evetest.TestCase{
			Test: TestAppArmorEnabled,
		},
		evetest.TestCase{
			Test: TestVCom,
		},
		evetest.TestCase{
			Test: TestControllerSigningCertChange,
		},
		evetest.TestCase{
			Test: TestControllerEncryptCertChange,
		},
	)
}
