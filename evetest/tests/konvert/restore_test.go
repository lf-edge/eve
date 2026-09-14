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
//  4. Assert the identity came back and the credential decrypts again.
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
// decrypted offline from the restored key.
//
// Needs an EVE build carrying the conversion (lf-edge/eve#6036, #6063) and a
// TPM. Unlike the wipe, the damage is done on the running device, so no disk
// editing is required.
func TestBackupCorruptRestore(test *testing.T) {
	runRestoreTest(test, damagePersistCorrupt)
}

// persistDamage is how a restore test breaks /persist. It returns once the
// device is back up with the damage in place.
type persistDamage struct {
	name string
	// needsDiskEditing is true for damage that can only be done with the device
	// powered off.
	needsDiskEditing bool
	apply            func(t Gomega, device *evetest.EdgeDevice)
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

// runRestoreTest is the body both restore tests share; they differ only in how
// /persist is broken.
func runRestoreTest(test *testing.T, damage persistDamage) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	defineSharedParameters()
	p := resolveDeviceParams(t)
	requirePinnedInitialVersion(t, p)
	t.Expect(p.withTPM).To(BeTrue(),
		"this test needs a TPM: the key that must survive is TPM-resident")

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

	// Phase 2.
	deviceUUID := readDeviceUUID(t, device)
	identity := snapshotIdentity(t, device)
	log.Infof("device UUID before the damage: %s", deviceUUID)
	log.Infof("backing identity up to the CONFIG partition")
	backupIdentityToConfig(t, device)
	evetest.Checkpoint("identity-backed-up")

	// Phase 3. The controller goes away first: the device must come back up
	// with no way to be told anything, or it would be handed back what it was
	// supposed to recover.
	isolateFromController(restoreBaseNetworkModel)
	defer restoreControllerAccess(t, device, restoreBaseNetworkModel)

	log.Infof("%s", damage.name)
	damage.apply(t, device)
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
	assertIdentityRestored(t, device, identity)
	log.Infof("and must decrypt the credential from the restored key, still offline")
	assertWiFiCredentialsDecrypted(t, device, 8*time.Minute)
	restoreOK = true
	evetest.Checkpoint("recovered-offline")
}
