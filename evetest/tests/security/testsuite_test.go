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
//   - TestAppVTPM -- per-app vTPM: the app's SWTPM instance runs unprivileged
//     with TPM-sealed state encryption, and the guest can consume the TPM.
//   - TestAppVTPMIdentitySurvivesReboots -- guest TPM NV identity across app
//     and device reboots.
//   - TestAppVTPMBackupRecoversPrimaryCorruption -- encrypted backup recovery.
//   - TestAppVTPMProtectedFailurePreservesState -- fail closed on bad protected state.
//   - TestAppVTPMCorruptStateRetention -- preserve bad bytes, reset, and prune archives.
//   - TestAppVTPMIsolation -- two apps have separate state and purge boundaries.
//   - TestAppVTPMProtectedKeyPath -- SHA256 mode and AppArmor access.
//   - TestAppVTPMLegacyKeyWithoutSHA256 -- NV-only mode on a no-SHA256 TPM.
//   - TestAppVTPMLogForwardingAndRotation -- real guest logging and bounded rotation.
//   - TestAppVTPMLegacyToPCRMigration -- upgrade from a legacy-key fixture.
//   - TestControllerSigningCertChange -- rotation of the controller certificate
//     signing API responses; device must recover config processing on its own.
//   - TestControllerEncryptCertChange -- rotation of the controller ECDH
//     certificate; object-encrypted configuration must be migrated and survive.
//   - TestVaultKeyModeRecovery -- the vault still opens when the file recording
//     which key derivation it was created with names the wrong one; run once per
//     /persist filesystem, since ext4 and ZFS are separate vault handlers.
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
			Test: TestAppVTPM,
		},
		evetest.TestCase{Test: TestAppVTPMIdentitySurvivesReboots},
		evetest.TestCase{Test: TestAppVTPMBackupRecoversPrimaryCorruption},
		evetest.TestCase{Test: TestAppVTPMProtectedFailurePreservesState},
		evetest.TestCase{Test: TestAppVTPMCorruptStateRetention},
		evetest.TestCase{Test: TestAppVTPMIsolation},
		evetest.TestCase{Test: TestAppVTPMProtectedKeyPath},
		evetest.TestCase{Test: TestAppVTPMLegacyKeyWithoutSHA256},
		evetest.TestCase{Test: TestAppVTPMLogForwardingAndRotation},
		evetest.TestCase{Test: TestAppVTPMLegacyToPCRMigration},
		evetest.TestCase{
			Test: TestControllerSigningCertChange,
		},
		evetest.TestCase{
			Test: TestControllerEncryptCertChange,
		},
		// Last: the filesystem is part of the device requirements, so neither
		// variant can share the device the tests above reuse, and their
		// placement relative to those does not affect that reuse.
		evetest.TestCase{
			Test: TestVaultKeyModeRecovery,
			Variants: []evetest.TestVariant{
				{
					Name: "TestVaultKeyModeRecoveryOnExt4",
					Parameters: []evetest.TestParameterValue{
						{
							Key:   evetest.FilesystemParameterKey,
							Value: evetest.FilesystemEXT4,
						},
					},
				},
				{
					Name: "TestVaultKeyModeRecoveryOnZFS",
					Parameters: []evetest.TestParameterValue{
						{
							Key:   evetest.FilesystemParameterKey,
							Value: evetest.FilesystemZFS,
						},
					},
				},
			},
		},
	)
}
