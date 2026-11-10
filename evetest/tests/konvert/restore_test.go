// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"

	"github.com/lf-edge/eve/evetest"
)

// TestPersistWipeRestore asserts a device survives losing /persist outright,
// recovering its identity and its last known configuration with no controller
// to ask.
//
// Before the conversion repartitions a boot disk it copies the files a device
// cannot be itself without -- its UUID, its certificates, its last
// configuration -- onto the CONFIG partition, and restores them at early boot
// if /persist comes back empty. This is that fail-safe on its own: no shrink is
// run, /persist is simply destroyed, and the question is whether the device
// comes back as itself.
//
// The load-bearing assertion is not that files reappeared but that a
// controller-encrypted credential can still be decrypted, offline, from the
// restored key. That is a much stronger statement: it means the certificate
// came back intact and usable, the last configuration came back and was
// re-applied, and the two still belong together. Files can be restored empty or
// mismatched and satisfy every other check.
//
// Offline is essential. A device that can reach its controller is simply told
// everything again, so the whole test would pass on a device that recovered
// nothing. The controller is cut off at the network before the device comes
// back up.
//
// Phases:
//  1. Configure an encrypted wireless credential and confirm it decrypts.
//  2. Snapshot the identity, and back it up to the CONFIG partition.
//  3. Cut off the controller, destroy /persist, and boot.
//  4. Assert the identity came back and the credential decrypts again, and
//     that storage-init cleaned up and left the failure marker.
//  5. Reconnect the controller and assert a kvm→k update is declined on that
//     marker.
//
// RESIZE_FAILURE selects how the offline resize the backup arms fails: for
// real, so resize_abort writes the marker, or simulated by a planted marker so
// that only the restore runs.
//
// Needs an EVE build carrying the conversion (lf-edge/eve#6036, #6063), a TPM,
// and a provider that can edit the device's disk.
func TestPersistWipeRestore(test *testing.T) {
	runRestoreTest(test, damagePersistWipe)
}

// TestBackupCorruptRestore asserts the same recovery when /persist is not lost
// but partly corrupted.
//
// Partial corruption is the harder case, and the one a naive restore gets
// wrong. An empty /persist is unambiguous -- restore everything. A /persist
// full of half-written files is not: the restore has to judge each file on
// whether it is still valid for its own type, replacing the certificates and
// JSON it can tell are broken, while the files it has no validator for fall
// back to the copies pillar keeps alongside them. Restoring too little strands
// the device; restoring too much discards state it did not need to.
//
// The .bak fallbacks are deliberately left intact, because they are what the
// no-validator files recover from.
//
// Same assertions as the wipe: identity back, and the encrypted credential
// decrypted offline from the restored key. Since /persist survives, the vault
// must also reopen from the TPM with its contents.
//
// Needs an EVE build carrying the conversion (lf-edge/eve#6036, #6063) and a
// TPM. Unlike the wipe, the damage is done on the running device, so no disk
// editing is required.
func TestBackupCorruptRestore(test *testing.T) {
	runRestoreTest(test, damagePersistCorrupt)
}

// TestVaultConfigLossRestore asserts the vault reopens, with no controller,
// when the record of how its key is derived is lost on a surviving /persist.
//
// That record says whether the vault key is the TPM key alone or merged with a
// build-time constant. A power cut during the resize's relocation of /persist
// has torn it before, and the vault then stayed locked on every boot. It is in
// the backup set, so the restore has to put it back before vaultmgr reads it.
//
// vaultmgr also falls back to the other derivation when its first guess fails,
// so a reopened vault alone does not prove the restore ran. The test also
// checks that the recovery boot's vaultmgr found the recorded mode and did not
// have to guess.
//
// Needs an EVE build carrying the conversion and the vault-metadata backup, and
// a TPM.
func TestVaultConfigLossRestore(test *testing.T) {
	runRestoreTest(test, damageVaultConfig)
}

// TestFscryptMetadataLossRestore asserts the vault reopens, with no controller,
// when its fscrypt policy is lost and its protector is torn on a surviving
// /persist.
//
// The policy and protector hold the only copies of the wrapped vault key, so
// without them the vault cannot be opened by any key. An fsck after a power cut
// during the resize has orphaned them into lost+found before. The removed policy
// exercises the missing-file restore. The protector, cut to half its length,
// is still non-empty, so only the restore's protobuf validity check catches it.
//
// Needs an EVE build carrying the conversion, the vault-metadata backup and
// the fscrypt validity check, and a TPM.
func TestFscryptMetadataLossRestore(test *testing.T) {
	runRestoreTest(test, damageFscryptMetadata)
}

// persistDamage is how a restore test breaks /persist. It returns once the
// device is back up with the damage in place.
type persistDamage struct {
	name string
	// needsDiskEditing is true for damage that can only be done with the device
	// powered off.
	needsDiskEditing bool
	// recreatesPersist is true for damage storage-init repairs by reformatting
	// /persist, which the restore records as persist_recreated.
	recreatesPersist bool
	// backedUp lists path prefixes, relative to /persist, the backup must hold
	// for the damage to be recoverable at all.
	backedUp []string
	apply    func(t Gomega, device *evetest.EdgeDevice)
}

// damagePersistWipe destroys the filesystem on /persist while the device is
// off, so that EVE reformats it empty on the next boot.
//
// Done to the partition rather than by deleting files: the fail-safe is meant
// to survive a filesystem that is gone, and emptying it from inside would leave
// the filesystem itself -- and everything EVE infers from finding one -- intact.
var damagePersistWipe = persistDamage{
	name:             "wiping /persist",
	needsDiskEditing: true,
	recreatesPersist: true,
	apply: func(t Gomega, device *evetest.EdgeDevice) {
		device.SyncDisks()
		device.PowerOff()
		device.DestroyPartitionFilesystem("P3")
		// Not waiting on the reboot signal: the device comes back to a
		// controller it cannot reach, so nothing will be reported to watch for.
		device.PowerOn(false)
		waitDeviceResponds(t, device)
	},
}

// damagePersistCorrupt truncates each critical file on /persist to half its
// length on the running device, then reboots.
//
// Truncated in place rather than replaced with garbage, because that is what a
// torn write looks like: a file that starts out correct and stops. The .bak
// copies are left alone -- they are the fallback the files without a validator
// recover through, and destroying them would test a different, unrecoverable
// scenario.
var damagePersistCorrupt = persistDamage{
	name:             "corrupting the files on /persist",
	needsDiskEditing: false,
	apply: func(t Gomega, device *evetest.EdgeDevice) {
		const script = `set -u
TRUNCATED=0
LC_SZ=$(stat -c%s /persist/checkpoint/lastconfig 2>/dev/null || echo 0)
for f in checkpoint/lastconfig checkpoint/controllercerts \
         certs/ecdh.cert.pem certs/attest.cert.pem certs/ek.cert.pem \
         status/nim/DevicePortConfigList/global.json \
         status/zedclient/OnboardingStatus/global.json; do
    p=/persist/$f
    [ -f "$p" ] || { echo "absent, skipping: $f"; continue; }
    size=$(stat -c%s "$p")
    if truncate -s $((size / 2)) "$p"; then
        echo "truncated $f: $size -> $((size / 2))"
        TRUNCATED=$((TRUNCATED + 1))
    else
        echo "FAIL: could not truncate $f"; exit 1
    fi
done
for b in checkpoint/lastconfig.bak checkpoint/controllercerts.bak; do
    [ -f /persist/$b ] && echo "kept intact: $b" || echo "WARN: no fallback: $b"
done
sync
[ "$TRUNCATED" -ge 1 ] || { echo "FAIL: nothing was truncated"; exit 1; }
# lastconfig has no validator, so it recovers from its .bak; without both a
# truncated lastconfig and a .bak at least as new, that path is not exercised.
[ "$LC_SZ" -gt 0 ] || { echo "FAIL: lastconfig was not there to truncate"; exit 1; }
BAK_SZ=$(stat -c%s /persist/checkpoint/lastconfig.bak 2>/dev/null || echo 0)
[ "$BAK_SZ" -ge "$LC_SZ" ] || { echo "FAIL: lastconfig.bak ($BAK_SZ B) is older than lastconfig ($LC_SZ B)"; exit 1; }
echo "CORRUPTED=$TRUNCATED"`
		out, err := runEVEWithTimeout(device, script, 3*time.Minute)
		t.Expect(err).NotTo(HaveOccurred(), "could not corrupt /persist:\n%s", out)
		t.Expect(out).To(ContainSubstring("CORRUPTED="),
			"could not corrupt /persist:\n%s", out)
		evetest.Logger().Infof("corruption: %s", out)
		device.SyncDisks()
		device.PowerOff()
		device.PowerOn(false)
		waitDeviceResponds(t, device)
	},
}

// damageVaultConfig deletes the vault's key-derivation record on the running
// device, then cuts its power.
//
// The power cut is what keeps vaultmgr from writing the record back: it holds
// the record in memory and republishes it only when it opens or creates a
// vault. On the next boot the restore runs from storage-init, before vaultmgr
// starts.
var damageVaultConfig = persistDamage{
	name:     "deleting the vault key-derivation record",
	backedUp: []string{vaultConfigRel},
	apply: func(t Gomega, device *evetest.EdgeDevice) {
		const script = `set -u
f=/persist/` + vaultConfigRel + `
# Merged-key vaults predate this layout; the record must name the TPM-only key
# that a guess from the vault's existence would get wrong.
grep -q '"TpmKeyOnly":true' "$f" || { echo "FAIL: $f is not a TPM-only record: $(cat "$f" 2>&1)"; exit 1; }
rm -f "$f"
sync
[ -e "$f" ] && { echo "FAIL: $f is still there"; exit 1; }
echo "DAMAGED=$f"`
		damageThenPowerCycle(t, device, script)
	},
}

// damageFscryptMetadata deletes every fscrypt policy and cuts every protector
// to half its length on the running device, then cuts its power.
//
// The kernel holds the vault key once the vault is open, so nothing on the
// running device touches the metadata again.
var damageFscryptMetadata = persistDamage{
	name:     "deleting the fscrypt policies and tearing the protectors",
	backedUp: []string{".fscrypt/policies/", ".fscrypt/protectors/"},
	apply: func(t Gomega, device *evetest.EdgeDevice) {
		const script = `set -u
POLICIES=0
PROTECTORS=0
for f in /persist/.fscrypt/policies/*; do
    [ -f "$f" ] || continue
    rm -f "$f" || { echo "FAIL: could not remove $f"; exit 1; }
    echo "removed $f"
    POLICIES=$((POLICIES + 1))
done
for f in /persist/.fscrypt/protectors/*; do
    [ -f "$f" ] || continue
    size=$(stat -c%s "$f")
    truncate -s $((size / 2)) "$f" || { echo "FAIL: could not truncate $f"; exit 1; }
    echo "truncated $f: $size -> $((size / 2))"
    PROTECTORS=$((PROTECTORS + 1))
done
sync
[ "$POLICIES" -ge 1 ] && [ "$PROTECTORS" -ge 1 ] \
    || { echo "FAIL: policies=$POLICIES protectors=$PROTECTORS"; exit 1; }
echo "DAMAGED=policies:$POLICIES,protectors:$PROTECTORS"`
		damageThenPowerCycle(t, device, script)
	},
}

// damageThenPowerCycle runs a damage script on the running device and, once it
// reports DAMAGED=, cuts the power and brings the device back up.
func damageThenPowerCycle(t Gomega, device *evetest.EdgeDevice, script string) {
	out, err := runEVEWithTimeout(device, script, 3*time.Minute)
	t.Expect(err).NotTo(HaveOccurred(), "could not damage /persist:\n%s", out)
	t.Expect(out).To(ContainSubstring("DAMAGED="), "could not damage /persist:\n%s", out)
	evetest.Logger().Infof("damage: %s", out)
	powerCycle(t, device)
}

// powerCycle cuts the device's power and brings it back up, which needs no
// controller.
func powerCycle(t Gomega, device *evetest.EdgeDevice) {
	device.SyncDisks()
	device.PowerOff()
	device.PowerOn(false)
	waitDeviceResponds(t, device)
}

// runRestoreTest is the body the restore tests share; they differ only in how
// /persist is broken.
func runRestoreTest(test *testing.T, damage persistDamage) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	defineSharedParameters(restoreParameterDefinitions()...)
	p := resolveDeviceParams(t)
	requirePinnedInitialVersion(t, p)
	t.Expect(p.withTPM).To(BeTrue(),
		"this test needs a TPM: the key that must survive is TPM-resident")
	mode := evetest.GetTestParameter[string](resizeFailureParamKey)
	t.Expect(mode).To(BeElementOf(resizeFailureReal, resizeFailureSimulated),
		"%s must be %q or %q", resizeFailureParamKey, resizeFailureReal, resizeFailureSimulated)

	var extra []evetest.Requirement
	if damage.needsDiskEditing {
		extra = append(extra, evetest.RequireCapabilities{
			Capabilities: []api.Capability{api.Capability_CAPABILITY_EDIT_DEVICE_DISK},
		})
	}
	device := setupDevice(t, p, evetest.FilesystemEXT4, nil,
		evetest.CreateFromScratchWithLiveImage, extra...)
	log := evetest.Logger()

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	applyMgmtNetwork(device, devConfig)
	devConfig.SetConfigProperties(shortBaseImageCooldown())
	device.ApplyConfig(devConfig, true, true)

	// The restore code ships with the conversion, so the device has to be on a
	// build that carries it before anything is broken.
	log.Infof("landing the restore code at %s", p.targetVersion)
	device.UpgradeEVE(p.targetVersion, evetest.HypervisorKVM,
		evetest.BaseOSDatastoreHTTP, true, false)
	evetest.Checkpoint("restore-code-landed")

	// Phase 1. Confirmed working before the damage, so that a failure afterwards
	// is the restore's and not a credential that never decrypted at all.
	log.Infof("configuring an encrypted wireless credential")
	addEncryptedWiFiPort(devConfig)
	device.ApplyConfig(devConfig, true, true)
	assertWiFiCredentialsDecrypted(t, device, 5*time.Minute)
	evetest.Checkpoint("credential-decrypts")

	// When /persist survives, so must the vault, and it can only be opened with
	// no controller if the TPM seal has settled on this build.
	keepsVault := !damage.recreatesPersist
	var vaultBefore vaultConfigLogCounts
	if keepsVault {
		settleVaultLocal(t, device)
		writeMarkerFile(t, device, vaultMarkerPath, vaultMarkerText)
		vaultBefore = countVaultConfigLog(t, device)
	}

	// Phase 2.
	running := readRunningVersion(t, device)
	deviceUUID := readDeviceUUID(t, device)
	identity := snapshotIdentity(t, device)
	log.Infof("device UUID before the damage: %s", deviceUUID)
	log.Infof("backing identity up to the CONFIG partition (%s resize failure)", mode)
	simulatedRelease := ""
	if mode == resizeFailureSimulated {
		simulatedRelease = running
	}
	backup := backupIdentityToConfig(t, device, simulatedRelease)
	for _, prefix := range damage.backedUp {
		t.Expect(backup).To(ContainSubstring("BACKED-UP "+prefix),
			"the backup does not hold %s, so the damage cannot be recovered", prefix)
	}
	portConfig := readPortConfig(t, device)
	evetest.Checkpoint("identity-backed-up")

	// Phase 3. The controller goes away first: the device must come back up
	// with no way to be told anything, or it would be handed back what it was
	// supposed to recover.
	isolateFromController(restoreBaseNetworkModel)
	isolated := true
	defer func() {
		if isolated {
			restoreControllerAccess(t, device, restoreBaseNetworkModel)
		}
	}()

	log.Infof("%s", damage.name)
	damage.apply(t, device)
	assertControllerUnreachable(t, device)
	evetest.Checkpoint("damaged-and-rebooted")

	// Phase 4.
	restoreOK := false
	defer func() {
		if !restoreOK {
			dumpRestoreState(device)
		}
	}()
	log.Infof("the device must have recovered its identity offline")
	assertDeviceUUIDUnchanged(t, device, deviceUUID)
	assertIdentityRestored(t, device, identity, portConfig)
	log.Infof("and must decrypt the credential from the restored key, still offline")
	assertWiFiCredentialsDecrypted(t, device, 8*time.Minute)
	log.Infof("storage-init must have cleaned up and left the failure marker")
	step := assertResizeBookkeeping(t, device, mode, running, damage.recreatesPersist)
	if keepsVault {
		// The marker moves PCR14 away from the sealing boot, so the vault can
		// only unseal from the TPM on a boot without it.
		log.Infof("and, on a boot without the marker, must reopen the vault it had from the TPM, still offline")
		moveFailureMarker(t, device, false)
		powerCycle(t, device)
		assertVaultReopened(t, device, vaultBefore)
		moveFailureMarker(t, device, true)
	}
	restoreOK = true
	evetest.Checkpoint("recovered-offline")

	// Phase 5. The marker is what stops a conversion from re-arming a resize
	// that already failed under this release, so a kvm→k update must now be
	// declined for that reason, saying whether /persist was lost.
	restoreControllerAccess(t, device, restoreBaseNetworkModel)
	isolated = false
	log.Infof("a kvm→k update must be declined on the failure marker")
	device.RequestRefusedEVEUpgrade(p.targetVersion, evetest.HypervisorKubevirt,
		evetest.BaseOSDatastoreHTTP)
	cause := "/persist preserved"
	if damage.recreatesPersist {
		cause = "/persist was recreated"
	}
	assertConversionDeclined(t, device, running,
		"boot-disk conversion failed ("+step+", ", cause)
	evetest.Checkpoint("conversion-declined-on-marker")
}
