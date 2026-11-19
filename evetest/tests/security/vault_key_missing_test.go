// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test what a device does with its vault when the TPM will not unseal the vault
// key and the controller has no copy of it.

package security

import (
	"bytes"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// Sentinel that allows vaultmgr to wipe and recreate a vault nothing can
	// unlock. storage-init drops it when it creates /persist, and EVE removes
	// it once the device has something to lose: after the first successful
	// vault key escrow, or the first volume.
	vaultCleanupSentinel = pillartypes.PersistStatusDir + "/allow-vault-clean"

	// Inert file put on the CONFIG partition to change PCR14 (see
	// writeConfigPartitionFile).
	pcr14BumpFile = "evetest-pcr14-bump"

	// Written into the vault to tell the original vault from a recreated one.
	keyMissingMarkerFile    = pillartypes.SealedDirName + "/evetest-key-missing-marker"
	keyMissingMarkerContent = "key-missing-marker"
	// Written into the recreated vault, to check that its key was escrowed.
	recreatedMarkerFile    = pillartypes.SealedDirName + "/evetest-recreated-marker"
	recreatedMarkerContent = "recreated-vault-marker"

	msgCleanupNotAllowed = "Vault cleanup is not allowed"
	msgEmptyKey          = "Processing empty EncryptedVaultKeyFromController"
	msgVaultRemoved      = "default vault removed"
	msgVaultRecreated    = pillartypes.DefaultVaultName + " re-created"
)

// TestVaultWithoutControllerKey checks what a device does with its vault when
// the local TPM unseal fails and the controller has no vault key to give it
// either.
//
// A device seals its vault key into the TPM against a set of PCRs and also
// escrows it with the controller. When the PCRs change (a firmware update, a
// change to /config), the local unseal fails and the device asks the controller
// for the escrowed key. Two plausible situations leave the controller with no
// key to give:
//
//   - The controller lost it, for example after its database was restored from
//     a backup older than the escrow, or migrated without the escrowed keys.
//     The device has been in use and its vault may hold application data.
//     Wiping it would destroy that data, so vaultmgr must leave the vault
//     locked and wait: once the key is back on the controller, the vault opens
//     with it.
//   - The device never escrowed it, because it rebooted or lost power soon
//     after installation and onboarding, before its first escrow. Onboarding
//     writes the device certificate into /config, so on such a device the next
//     boot's unseal fails too. Its vault holds nothing of value yet, so
//     vaultmgr removes it and creates an empty one in its place, and the device
//     carries on rather than staying locked forever.
//
// vaultmgr tells the two apart by /persist/status/allow-vault-clean: created
// with a new /persist, and removed after the first successful key escrow or the
// first volume.
//
// Fault injection
// ---------------
//   - Local unseal failure: an inert file is written to the CONFIG partition.
//     measure-config hashes every /config file into PCR14, which is part of the
//     sealing policy, so after a reboot the sealed key no longer unseals, as
//     with any other change to the device's /config.
//   - Controller that lost the key: the controller is made to forget the key
//     the device escrowed (SetEscrowedVaultKey(nil)).
//   - Device that never escrowed: on top of the controller forgetting the key,
//     the cleanup sentinel is put back in /persist/status, which is the state
//     of a device between installation and its first escrow.
//
// What vaultmgr decided is read from the device logs published to the
// controller, filtered to records logged after the reboot was requested.
//
// Phases / assertions
// -------------------
//  1. setup-done: the vault is open, the device has completed this boot's
//     attestation, so the controller holds the escrowed key and no escrow is
//     still pending that would put it back after the test removes it, and the
//     cleanup sentinel is gone. A marker file is written into the vault. The
//     seal does not need to have settled after onboarding (settleVaultSeal):
//     every phase below changes PCR14 itself, and none expects a local unlock.
//  2. rebooted-without-escrowed-key: the controller lost the key. With PCR14
//     changed and the controller's key removed, the device reports the vault in
//     error and not unlocked, and logs that the cleanup is not allowed. That
//     the vault was not removed is checked in phase 3, by reading the marker
//     back.
//  3. rebooted-with-escrowed-key-restored: the controller has the key back (its
//     database was repaired). The vault is unlocked with the controller key and
//     the marker reads back: the data survived.
//  4. rebooted-as-never-escrowed: the device never escrowed. With PCR14 changed
//     again, the controller's key removed and the cleanup sentinel back, the
//     device removes the vault and creates a new one: it reports the vault open
//     with unlock method RECREATED, the marker is gone, and the new key is
//     escrowed with the controller.
//  5. rebooted-with-config-restored: with the CONFIG file removed (PCR14
//     changes once more), the recreated vault is unlocked with the controller
//     key, and a marker written into it after phase 4 reads back: the new key's
//     escrow is usable.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- not needed by the test itself, but it is
//     the one the rest of the suite uses, so the SDN and EVE VMs are reused.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//   - FILESYSTEM (ext4|zfs, defaults to ext4): ext4 and ZFS have separate vault
//     handlers, each with its own way of removing the vault.
//
// Suite placement: TestSecuritySuite, with one variant per filesystem, next to
// TestVaultKeyModeRecovery, whose devices it shares.
func TestVaultWithoutControllerKey(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
		evetest.FilesystemParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:           devName,
			WithHypervisor: hypervisor,
			// Without a TPM there is no sealed key and no escrow.
			WithTPM:           true,
			WithFilesystem:    filesystem,
			DeviceReusePolicy: evetest.ResetDeviceConfig,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
	)
	device := evetest.GetEdgeDevice(devName)
	if hypervisor == evetest.HypervisorKubevirt {
		device.WaitForClusterNodeIsReady(clusterNodeReadyTimeout)
	}
	log := evetest.Logger()

	// Phase 1.
	device.ApplyConfig(vaultMgmtPortConfig(), true, true)
	waitForVaultOpen(t, device, filesystem, "before the test")

	waitForEscrowThisBoot(t, device)
	originalKey := device.GetEscrowedVaultKey()
	t.Expect(originalKey).ToNot(BeEmpty(),
		"the device must escrow its vault key with the controller")
	t.Expect(pathExists(t, device, vaultCleanupSentinel)).To(BeFalse(),
		"the vault key was escrowed, so %s must be gone; with it in place phase 2 "+
			"would wipe the vault", vaultCleanupSentinel)

	// If the test fails half-way, leave the device and the controller in a
	// state the next test can unlock the vault from: the controller has a key
	// and /config is back to what the vault was sealed against.
	restored := false
	defer func() {
		if restored {
			return
		}
		log.Warnf("Restoring the CONFIG partition and the escrowed vault key...")
		if len(device.GetEscrowedVaultKey()) == 0 {
			device.SetEscrowedVaultKey(originalKey)
		}
		_, _, _ = device.RunShellScript("rm -f "+vaultCleanupSentinel, shellCmdTimeout, 0)
		_, _, _ = device.RunShellScript(configPartitionScript(pcr14BumpFile, ""),
			shellCmdTimeout, 0)
	}()

	runInPillar(t, device,
		"sh -c 'printf %s "+keyMissingMarkerContent+" > "+keyMissingMarkerFile+"'")
	device.SyncDisks()
	evetest.Checkpoint("setup-done")

	// Phase 2.
	log.Infof("Removing the escrowed vault key and changing PCR14...")
	device.SetEscrowedVaultKey(nil)
	writeConfigPartitionFile(t, device, pcr14BumpFile, "1")
	rebootedAt := time.Now()
	device.RequestReboot(false, true)
	evetest.Checkpoint("rebooted-without-escrowed-key")

	waitForVaultmgrLog(t, device, msgCleanupNotAllowed, rebootedAt,
		"with the key escrowed before, an empty key from the controller must not "+
			"allow the vault to be wiped")
	expectVaultReported(t, device,
		eveinfo.DataSecAtRestStatus_DATASEC_AT_REST_ERROR,
		eveinfo.VaultUnlockMethod_VAULT_UNLOCK_METHOD_UNSPECIFIED,
		"while the TPM will not unseal the key and the controller has none")
	t.Expect(device.GetEscrowedVaultKey()).To(BeEmpty(),
		"a device that cannot open its vault has no key to escrow")

	// Phase 3.
	log.Infof("Giving the escrowed vault key back to the controller...")
	device.SetEscrowedVaultKey(originalKey)
	device.RequestReboot(false, true)
	evetest.Checkpoint("rebooted-with-escrowed-key-restored")

	waitForVaultOpen(t, device, filesystem, "with the escrowed key restored")
	expectVaultReported(t, device,
		eveinfo.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
		eveinfo.VaultUnlockMethod_VAULT_UNLOCK_METHOD_CONTROLLER_KEY,
		"with the escrowed key restored")
	marker := runInPillar(t, device, "cat "+keyMissingMarkerFile)
	t.Expect(strings.TrimSpace(marker)).To(Equal(keyMissingMarkerContent),
		"the vault left locked in phase 2 must still hold its data")

	// Phase 4. The vault was re-sealed against PCR14 with the "1" file, so
	// changing its content makes the local unseal fail again.
	waitForEscrowThisBoot(t, device)
	keyBefore := device.GetEscrowedVaultKey()
	t.Expect(keyBefore).ToNot(BeEmpty(),
		"the device must escrow its vault key again after unlocking it")
	log.Infof("Removing the escrowed vault key, changing PCR14 and allowing the " +
		"vault cleanup, as on a device that never escrowed its key...")
	device.SetEscrowedVaultKey(nil)
	writeConfigPartitionFile(t, device, pcr14BumpFile, "2")
	_, stderr, err := device.RunShellScript(
		"touch "+vaultCleanupSentinel, shellCmdTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(),
		"failed to create %s (stderr: %s)", vaultCleanupSentinel, stderr)
	device.SyncDisks()
	rebootedAt = time.Now()
	device.RequestReboot(false, true)
	evetest.Checkpoint("rebooted-as-never-escrowed")

	waitForVaultmgrLog(t, device, msgEmptyKey, rebootedAt,
		"the empty key from the controller must be processed")
	waitForVaultmgrLog(t, device, msgVaultRemoved, rebootedAt,
		"the vault nothing can unlock must be removed")
	waitForVaultmgrLog(t, device, msgVaultRecreated, rebootedAt,
		"a new vault must be created in its place")
	waitForVaultOpen(t, device, filesystem, "after it was recreated")
	expectVaultReported(t, device,
		eveinfo.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
		eveinfo.VaultUnlockMethod_VAULT_UNLOCK_METHOD_RECREATED,
		"after it was recreated")
	t.Expect(pathExists(t, device, keyMissingMarkerFile)).To(BeFalse(),
		"the recreated vault must be a new, empty one")
	t.Eventually(func() []byte {
		return device.GetEscrowedVaultKey()
	}, vaultOpenTimeout, pollingInterval).ShouldNot(BeEmpty(),
		"the key of the recreated vault must be escrowed with the controller")
	t.Expect(bytes.Equal(device.GetEscrowedVaultKey(), keyBefore)).To(BeFalse(),
		"the controller must hold the key of the new vault, not the old one")
	t.Eventually(func() bool {
		return pathExists(t, device, vaultCleanupSentinel)
	}, vaultOpenTimeout, pollingInterval).Should(BeFalse(),
		"once the new key is escrowed the vault must not be wiped again")

	// Phase 5.
	runInPillar(t, device,
		"sh -c 'printf %s "+recreatedMarkerContent+" > "+recreatedMarkerFile+"'")
	device.SyncDisks()
	log.Infof("Removing the file from the CONFIG partition...")
	writeConfigPartitionFile(t, device, pcr14BumpFile, "")
	device.RequestReboot(false, true)
	evetest.Checkpoint("rebooted-with-config-restored")

	waitForVaultOpen(t, device, filesystem, "with the CONFIG partition restored")
	expectVaultReported(t, device,
		eveinfo.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED,
		eveinfo.VaultUnlockMethod_VAULT_UNLOCK_METHOD_CONTROLLER_KEY,
		"with the CONFIG partition restored")
	marker = runInPillar(t, device, "cat "+recreatedMarkerFile)
	t.Expect(strings.TrimSpace(marker)).To(Equal(recreatedMarkerContent),
		"the recreated vault must open with the key it escrowed")

	runInPillar(t, device, "rm -f "+recreatedMarkerFile)
	restored = true
}
