// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test rotation of the controller certificate that signs API responses.

package security

import (
	"fmt"
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	evecerts "github.com/lf-edge/eve-api/go/certs"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestControllerSigningCertChange verifies that a device recovers on its own when
// the controller rotates the certificate and private key it uses to sign the
// AuthContainer wrapping every API response. After the rotation every API response
// fails verification on the device until it refetches /certs, and nothing tells it
// to do so other than the failure itself.
//
// A signing-cert rotation must leave object-level encryption alone: evetest cipher
// contexts are derived from the controller's ECDH certificate, never from the
// signing one. See TestControllerEncryptCertChange for that side.
//
// Phases / assertions
// -------------------
//  1. setup-done -> config-applied.
//  2. app-1-running: baseline proof that object-encrypted user data decrypts.
//  3. signing-cert-rotated-1: the confirmed ApplyConfig is the assertion that can
//     fail. LastProcessedConfig must reach the timestamp of a config created after
//     the rotation, which the device can only report once it has verified an
//     AuthContainer signed with the new key.
//  4. signing-cert-rotated-2: same code path, but over state a rotation itself
//     produced -- the installed certificate no longer matches controllercerts.bak.
//     A stale cached serverSigningCertHash shows up here, not in phase 3.
//  5. app-2-running: a cipher block minted after both rotations. Reaching RUNNING
//     proves nothing about decryption, see assertCipherDecryptionSucceeded.
//  6. device-rebooted -> apps-running-after-reboot: the ControllerCert publication
//     is ephemeral (/run) and the reboot wiped it, so both certificates must be
//     there again. Not a checkpoint check -- zedagent refetches /certs
//     unconditionally at startup, so a corrupt checkpoint passes too. The marker
//     reads prove the recreated containers decrypted their blocks again.
//  7. Delete both applications and wait until the device reports them gone.
//
// Test params: HYPERVISOR (defaults to KVM).
// Suite placement: TestSecuritySuite.
func TestControllerSigningCertChange(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	// Define configurable parameters available for the test.
	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)

	// Get parameter values set for this test execution.
	hypervisor := evetest.GetHypervisorParameterValue()

	// Set up the test harness and specify the test prerequisites.
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:           devName,
			WithHypervisor: hypervisor,
			// Decryption then runs through the TPM (evetpm.getDecryptKey), and it
			// matches the other tests in the suite, so the device VM is reused.
			WithTPM:           true,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	evetest.Checkpoint("setup-done")

	log := evetest.Logger()
	devConfig, niUUID := singleMgmtPortWithLocalNI(device, hypervisor)
	evetest.Checkpoint("config-applied")

	// Phase 2: baseline, before any certificate change.
	const firstAppMarker = "before-signing-cert-rotation"
	firstAppUUID := deployEncryptedUserDataApp(t, device, devConfig, niUUID,
		"signing-cert-app1", 2222, firstAppMarker)
	evetest.Checkpoint("app-1-running")

	// Phases 3 and 4.
	for rotation := 1; rotation <= 2; rotation++ {
		log.Infof("Rotating the controller signing certificate (%d of 2)...", rotation)
		evetest.RotateControllerSigningCert()

		// Config processing must resume with no nudge but the verification failure.
		device.ApplyConfig(devConfig, true, true)
		assertDeviceHasControllerCert(t, device,
			evecerts.ZCertType_CERT_TYPE_CONTROLLER_SIGNING,
			evetest.GetControllerSigningCertPEM())
		evetest.Checkpoint(fmt.Sprintf("signing-cert-rotated-%d", rotation))
	}
	assertCipherDecryptionSucceeded(t, device)

	// Phase 5: a cipher block created after both rotations.
	const secondAppMarker = "after-signing-cert-rotation"
	secondAppUUID := deployEncryptedUserDataApp(t, device, devConfig, niUUID,
		"signing-cert-app2", 2223, secondAppMarker)
	evetest.Checkpoint("app-2-running")

	// Phase 6: the device must repopulate its ephemeral controller certificates.
	log.Infof("Rebooting the device...")
	device.SoftReboot(true)
	evetest.Checkpoint("device-rebooted")

	assertDeviceHasControllerCert(t, device,
		evecerts.ZCertType_CERT_TYPE_CONTROLLER_SIGNING,
		evetest.GetControllerSigningCertPEM())
	assertDeviceHasControllerCert(t, device,
		evecerts.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE,
		evetest.GetControllerEncryptCertPEM())

	device.WaitUntilAppIsRunning(firstAppUUID, appRunningTimeout)
	assertUserDataDecrypted(t, device, firstAppUUID, firstAppMarker)
	device.WaitUntilAppIsRunning(secondAppUUID, appRunningTimeout)
	assertUserDataDecrypted(t, device, secondAppUUID, secondAppMarker)
	evetest.Checkpoint("apps-running-after-reboot")

	// Phase 7: clean up.
	deleteAppAndWait(t, device, devConfig, firstAppUUID)
	deleteAppAndWait(t, device, devConfig, secondAppUUID)
}
