// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test rotation of the controller ECDH certificate used for object encryption.

package security

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	uuid "github.com/satori/go.uuid"

	evecerts "github.com/lf-edge/eve-api/go/certs"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestControllerEncryptCertChange verifies that object-level encryption survives a
// rotation of the controller's ECDH certificate -- the certificate every evetest
// cipher context is derived from, and the one EVE needs in order to decrypt user
// data, datastore credentials, WiFi and cellular secrets and the join token. The
// rotation also migrates deployed state: the harness re-encrypts the running
// configuration's cipher blocks and re-applies it.
//
// Unlike the signing certificate, the ECDH certificate is not part of the
// AuthContainer, so rotating raises no verification failure and no self-triggered
// recovery; the /certs refetch is driven by controllercert_confighash instead. See
// RotateControllerEncryptCert for the ordering and controller version implied.
//
// Phases / assertions
// -------------------
//  1. setup-done -> config-applied.
//  2. app-1-running: baseline proof that the block decrypts with the pre-rotation
//     certificate. Reaching RUNNING proves nothing about decryption, see
//     assertCipherDecryptionSucceeded.
//  3. encrypt-cert-rotated-1: the migration must not break the deployed
//     application, see assertAppsNotDisruptedByRotation.
//  4. app-2-running: a block encrypted against the new key from the start, so the
//     marker read is the primary proof that the device got the new certificate and
//     can use it -- no fallback to a retained old one produces that marker.
//  5. encrypt-cert-rotated-2: decryption now needs a keypair a rotation itself
//     installed, so a controller that mixed up which keypair it retired fails here
//     and not in phase 3. A third application would only repeat phase 4.
//  6. device-rebooted -> apps-running-after-reboot: the ControllerCert publication
//     is ephemeral (/run) and the reboot wiped it, so the ECDH certificate must be
//     there again before anything decrypts. Not a checkpoint check -- zedagent
//     refetches /certs unconditionally at startup. The marker reads then prove the
//     recreated containers decrypted their blocks again.
//  7. Delete both applications and wait until the device reports them gone.
//
// Test params: HYPERVISOR (defaults to KVM).
// Suite placement: TestSecuritySuite.
func TestControllerEncryptCertChange(test *testing.T) {
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
			// Load-bearing: the rotated controller point is fed to the TPM's ECDH
			// rather than to a software one (evetpm.getDecryptKey), so with TPM off
			// this test covers a different path. Also keeps the VM reusable.
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

	// Phase 2: encrypted against the pre-rotation certificate.
	markers := []string{
		"before-encrypt-cert-rotation",
		"after-first-encrypt-cert-rotation",
	}
	appUUIDs := []uuid.UUID{
		deployEncryptedUserDataApp(t, device, devConfig, niUUID,
			"encrypt-cert-app1", 2222, markers[0]),
	}
	bootTimes := []time.Time{appBootTime(t, device, appUUIDs[0])}
	evetest.Checkpoint("app-1-running")

	// Phase 3: first rotation. RotateControllerEncryptCert blocks until the device
	// publishes the new certificate, hence no ControllerCert assertion here.
	log.Infof("Rotating the controller ECDH certificate (1 of 2)...")
	evetest.RotateControllerEncryptCert(devConfig)
	assertAppsNotDisruptedByRotation(t, device, appUUIDs, markers, bootTimes)
	assertCipherDecryptionSucceeded(t, device)
	evetest.Checkpoint("encrypt-cert-rotated-1")

	// Phase 4: a block encrypted against the new key from the start.
	appUUIDs = append(appUUIDs, deployEncryptedUserDataApp(t, device, devConfig,
		niUUID, "encrypt-cert-app2", 2223, markers[1]))
	bootTimes = append(bootTimes, appBootTime(t, device, appUUIDs[1]))
	evetest.Checkpoint("app-2-running")

	// Phase 5: second rotation, decrypting with a keypair a rotation installed.
	log.Infof("Rotating the controller ECDH certificate (2 of 2)...")
	evetest.RotateControllerEncryptCert(devConfig)
	assertAppsNotDisruptedByRotation(t, device, appUUIDs, markers, bootTimes)
	assertCipherDecryptionSucceeded(t, device)
	evetest.Checkpoint("encrypt-cert-rotated-2")

	// Phase 6: after the reboot the device only knows the current certificate.
	log.Infof("Rebooting the device...")
	device.SoftReboot(true)
	evetest.Checkpoint("device-rebooted")

	assertDeviceHasControllerCert(t, device,
		evecerts.ZCertType_CERT_TYPE_CONTROLLER_ECDH_EXCHANGE,
		evetest.GetControllerEncryptCertPEM())

	for i, appUUID := range appUUIDs {
		device.WaitUntilAppIsRunning(appUUID, appRunningTimeout)
		assertUserDataDecrypted(t, device, appUUID, markers[i])
	}
	evetest.Checkpoint("apps-running-after-reboot")

	// Phase 7: clean up.
	for _, appUUID := range appUUIDs {
		deleteAppAndWait(t, device, devConfig, appUUID)
	}
}

// assertAppsNotDisruptedByRotation asserts that applications deployed before a
// certificate rotation were not restarted by it. markers and bootTimes hold one
// entry per application, in the same order as appUUIDs.
//
// The boot time is what proves it. For an already-activated domain domainmgr never
// re-runs configToStatus: the marker read returns the environment planted at the
// pre-rotation create whatever the migration did to the block, and only proves the
// container is alive.
//
// The SSH round trip runs first, so any disruption has had time to reach the
// controller before the reported state is read.
func assertAppsNotDisruptedByRotation(t *WithT, device *evetest.EdgeDevice,
	appUUIDs []uuid.UUID, markers []string, bootTimes []time.Time) {

	for i, appUUID := range appUUIDs {
		assertUserDataDecrypted(t, device, appUUID, markers[i])
		info := device.GetAppInfo(appUUID)
		t.Expect(info).ToNot(BeNil())
		t.Expect(info.GetState()).To(Equal(eveinfo.ZSwState_RUNNING))
		t.Expect(info.GetAppErr()).To(BeEmpty())
		t.Expect(info.GetBootTime().AsTime()).To(BeTemporally("==", bootTimes[i]),
			"the rotation recreated application %v", appUUID)
	}
}
