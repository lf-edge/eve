// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"fmt"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"google.golang.org/protobuf/proto"

	evecommon "github.com/lf-edge/eve-api/go/evecommon"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// The wireless port used to prove an encrypted credential can be decrypted
// after a restore.
//
// A device-network credential rather than, say, application user-data: network
// credentials are decrypted by nim while it reconciles the port configuration,
// which happens on every boot and needs neither a controller nor a running
// application. Application user-data is only decrypted when a domain is
// instantiated, which on a wiped device cannot happen -- the image is gone too.
const (
	restoreWiFiPort = "wlan0"
	restoreWiFiSSID = "konvert-restore-ssid"
	// restoreWiFiIdentity is the EAP identity. It is what makes the credential
	// an encrypted one: evetest builds a CipherBlock for a WiFi network only
	// when an identity is set, and sends the network unauthenticated otherwise.
	restoreWiFiIdentity = "konvert-restore-identity"
	// restoreWiFiPassword is the secret that has to survive. Its value is never
	// used to associate with a radio here -- only to be encrypted by the
	// controller and decrypted again afterwards -- so any opaque secret does.
	restoreWiFiPassword = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// resizeTargetSize is the boot-disk size the backup is taken against. These
// tests never run a real resize, so it only has to be a size the tool accepts.
const resizeTargetSize = "78G"

// backupScriptPath is where the backup script is staged for pillar to run. On
// /persist because that is visible from both the host and the pillar container;
// removed again as soon as it has run.
const backupScriptPath = "/persist/konvert-restore-backup.sh"

// addEncryptedWiFiPort adds a wireless port whose credentials the controller
// encrypts, which is the thing a restore has to be able to decrypt afterwards.
//
// The radio need not exist. What is being tested is that the credential can be
// unwrapped from the restored key, and nim tries to decrypt it while
// reconciling the port whether or not any hardware answers.
func addEncryptedWiFiPort(devConfig *evetest.EdgeDeviceConfig) {
	wifiNet := devConfig.AddNetwork(evetest.WiFiNetworkConfig{
		DHCPNetworkConfig: evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4,
		},
		SSID: restoreWiFiSSID,
		// EAP rather than PSK: the identity and password travel together in the
		// CipherBlock, which is the object the restore has to be able to unwrap.
		KeyScheme: evecommon.WiFiKeyScheme_WPAEAP,
		Identity:  restoreWiFiIdentity,
		Password:  restoreWiFiPassword,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  restoreWiFiPort,
		PhysicalLabel: restoreWiFiPort,
		InterfaceName: restoreWiFiPort,
		WirelessType:  evecommon.WirelessType_WiFi,
		NetworkUUID:   wifiNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		// Costlier than the wired port, so the device keeps talking to its
		// controller over ethernet and the wireless port is only ever
		// configured -- which is all this needs.
		Cost: 10,
	})
}

// assertWiFiCredentialsDecrypted asserts the device holds the wireless port's
// configuration and was able to decrypt its credentials.
//
// Both halves are needed. The port configuration proves the last known
// configuration was recovered and re-applied; the decrypted cipher block proves
// the key that unwraps it was recovered too. Either alone would pass on a
// device that had lost the other.
func assertWiFiCredentialsDecrypted(t Gomega, device *evetest.EdgeDevice, timeout time.Duration) {
	t.Eventually(func(g Gomega) {
		portConfig, err := runEVE(device, catGlob(devicePortConfigDir+"/*.json"))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(portConfig).To(ContainSubstring(restoreWiFiSSID),
			"the device does not have the wireless port configuration back; %s holds:\n%s",
			devicePortConfigDir, describeDir(device, devicePortConfigDir))

		cipherStatus, err := runEVE(device, catGlob(cipherBlockStatusDir+"/*.json"))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(anyCipherBlockDecrypted(cipherStatus)).To(BeTrue(),
			"no cipher block was decrypted successfully; %s holds:\n%s\n%s",
			cipherBlockStatusDir, describeDir(device, cipherBlockStatusDir), cipherStatus)
	}, timeout, 15*time.Second).Should(Succeed())
}

// Where the two agents publish what this assertion reads. Both are ephemeral
// publications, so they live under /run rather than /persist.
const (
	devicePortConfigDir  = "/run/zedagent/DevicePortConfig"
	cipherBlockStatusDir = "/run/nim/CipherBlockStatus"
)

// catGlob builds a command that prints every file matching a glob and succeeds
// with no output when nothing matches.
//
// A bare `cat <glob>` exits 1 in that case, which reports an absent file as an
// SSH failure and buries the assertion the caller actually wrote.
func catGlob(pattern string) string {
	return `eve exec pillar sh -c "cat ` + pattern + ` 2>/dev/null || true"`
}

// describeDir lists a pubsub directory, so that a failure says what the device
// does have rather than only what it was missing.
func describeDir(device *evetest.EdgeDevice, dir string) string {
	out, err := runEVE(device, `eve exec pillar sh -c "ls -la `+dir+` 2>&1 || true"`)
	if err != nil {
		return fmt.Sprintf("(could not list %s: %v)", dir, err)
	}
	return out
}

// anyCipherBlockDecrypted reports whether at least one cipher block was
// unwrapped without error.
func anyCipherBlockDecrypted(raw string) bool {
	for _, status := range decodeJSONStream(raw) {
		isCipher, _ := status["IsCipher"].(bool)
		errMsg, _ := status["Error"].(string)
		if isCipher && errMsg == "" {
			return true
		}
	}
	return false
}

// backupIdentityToConfig copies the identity and connectivity files onto the
// CONFIG partition, and arms the flag that makes early boot restore them.
//
// Retried until the backup demonstrably contains the wireless credential and an
// ecdh certificate, rather than run once and trusted: the checkpoint is written
// asynchronously, so a backup taken too early captures a configuration that
// predates the credential and the restore afterwards would be judged against
// something that was never in it.
func backupIdentityToConfig(t Gomega, device *evetest.EdgeDevice) {
	script := fmt.Sprintf(`set -u
CFGP=$(findfs PARTLABEL=CONFIG) || { echo "FAIL: no CONFIG partition"; exit 1; }
mkdir -p /tmp/restore-cfg
mountpoint -q /tmp/restore-cfg || mount -t vfat -o rw,iocharset=iso8859-1 "$CFGP" /tmp/restore-cfg \
    || { echo "FAIL: could not mount CONFIG"; exit 1; }
LC=/tmp/restore-cfg/backup-persist/checkpoint/lastconfig
rc=0
i=0
while [ $i -lt 18 ]; do
    i=$((i+1))
    /usr/bin/storage-resizer backup --persist /persist \
        --backup-dir /tmp/restore-cfg/backup-persist \
        --flag-file /tmp/restore-cfg/repartition-inprogress \
        --target %s > /tmp/restore-backup.out 2>&1
    rc=$?
    if [ -f "$LC" ] && tr -d '\0' < "$LC" | grep -q %q \
       && ls /tmp/restore-cfg/backup-persist/certs/ecdh.*.pem >/dev/null 2>&1; then
        echo "BACKUP-OK after $i attempt(s)"
        break
    fi
    sync; sleep 10
done
if [ ! -f "$LC" ] || ! tr -d '\0' < "$LC" | grep -q %q; then
    echo "FAIL: the backup never captured the wireless credential"
    echo "--- storage-resizer backup (rc=$rc) ---"
    cat /tmp/restore-backup.out 2>&1
    echo "--- /persist/checkpoint ---"
    ls -la /persist/checkpoint 2>&1
    echo "--- backup dir ---"
    ls -laR /tmp/restore-cfg/backup-persist 2>&1
    umount /tmp/restore-cfg 2>/dev/null
    exit 1
fi
# Pillar rotates the previous primary into .bak, so the fallback still predates
# the credential; the corruption step keeps .bak intact and expects to recover
# from it, which only works if it is at least as new as what it replaces.
cp /persist/checkpoint/lastconfig /persist/checkpoint/lastconfig.bak 2>/dev/null || true
sync
umount /tmp/restore-cfg 2>/dev/null
echo "BACKUP-DONE"`, resizeTargetSize, restoreWiFiSSID, restoreWiFiSSID)

	// Run inside pillar: storage-resizer ships in that container, and the
	// CONFIG mount has to live in the same mount namespace as the tool writing
	// through it. Handed over as a file on /persist, which both the host and
	// pillar see, rather than quoted into `sh -c`.
	wrapper := fmt.Sprintf(`set -u
cat > %s <<'KONVERT_BACKUP_EOS'
%s
KONVERT_BACKUP_EOS
eve exec pillar sh %s
rc=$?
rm -f %s
exit $rc`, backupScriptPath, script, backupScriptPath, backupScriptPath)

	out, err := runEVEWithTimeout(device, wrapper, 8*time.Minute)
	t.Expect(err).NotTo(HaveOccurred(), "the identity backup failed:\n%s", out)
	t.Expect(out).To(ContainSubstring("BACKUP-DONE"), "the identity backup failed:\n%s", out)
	evetest.Logger().Infof("identity backup: %s", strings.TrimSpace(out))
	device.SyncDisks()
}

// isolateFromController drops every packet from the device to the controller,
// so that what happens next has to happen without one.
//
// This is the point of both restore tests: a device that can reach its
// controller can simply be told everything again, which proves nothing about
// what it recovered on its own. Done with a firewall rule rather than by
// stopping the controller, so only this device is affected and the harness
// keeps working.
//
// The network model is deep-copied first: the models are package-level values
// shared with every other test in the process.
func isolateFromController(baseModel *api.NetworkModel) {
	isolated := proto.CloneOf(baseModel)
	if isolated.Firewall == nil {
		isolated.Firewall = &api.Firewall{}
	}
	isolated.Firewall.Rules = append(isolated.Firewall.Rules, &api.FwRule{
		SrcSubnet: "0.0.0.0/0",
		DstSubnet: evetest.GetControllerIPv4().String() + "/32",
		Action:    api.FwAction_FW_DROP,
	})
	evetest.Logger().Infof("cutting the device off from the controller at %s",
		evetest.GetControllerIPv4())
	evetest.UpdateNetworkModel(isolated)
}

// restoreControllerAccess puts the network back the way it was and waits for the
// device to check in again.
//
// The wait is not tidiness. Reboots are counted from what the device reports,
// and while it was isolated it could report nothing; the harness audits the
// count as it tears down, so returning before the device has been heard from
// would race that audit and fail the run over a reboot the test asked for.
func restoreControllerAccess(t Gomega, device *evetest.EdgeDevice, baseModel *api.NetworkModel) {
	evetest.Logger().Infof("restoring the device's path to the controller")
	evetest.UpdateNetworkModel(proto.CloneOf(baseModel))

	updates, stop := device.WatchDeviceInfo()
	defer stop()
	t.Eventually(updates, 10*time.Minute).Should(Receive(),
		"the device did not report to the controller after its path was restored")
}

// restoreBaseNetworkModel is the model both restore tests start from and return
// to.
var restoreBaseNetworkModel = netmodels.SingleEthWithDHCP

// snapshotIdentity records the identity files whose loss would cost the device
// its identity and its way back to a controller.
//
// Recorded by content, not by presence: a file restored empty, or recreated
// blank, would satisfy an existence check and still leave the device unable to
// talk to anything.
func snapshotIdentity(t Gomega, device *evetest.EdgeDevice) map[string]string {
	snapshot := make(map[string]string, len(identityFiles))
	for _, path := range identityFiles {
		var sum string
		t.Eventually(func(g Gomega) {
			out, err := runEVE(device,
				"eve exec pillar sh -c 'sha256sum "+path+" 2>/dev/null || echo MISSING'")
			g.Expect(err).NotTo(HaveOccurred())
			fields := strings.Fields(strings.TrimSpace(out))
			g.Expect(fields).NotTo(BeEmpty(), "could not read %s", path)
			sum = fields[0]
		}, 2*time.Minute, 5*time.Second).Should(Succeed())
		snapshot[path] = sum
	}
	return snapshot
}

// identityFiles are what a device needs to still be itself after /persist is
// lost or damaged. They are compared byte for byte because nothing on the
// device rewrites them: a difference means the restore produced something other
// than what it saved.
var identityFiles = []string{
	"/persist/status/uuid",
	"/persist/certs/device.cert.pem",
	"/persist/certs/ecdh.cert.pem",
	"/persist/status/zedclient/OnboardingStatus/global.json",
}

// dpcListPath is the port-configuration list, which is restored but cannot be
// compared by content: nim rewrites it as it tests ports, so the copy on disk
// is overtaken as soon as the device runs, and a byte difference is "an
// ordinary newer version" rather than a failed restore (pkg/pillar/docs/
// diskconvert.md). Whether the configuration really came back is settled by the
// credential assertion in phase 4, which needs it to be both present and valid.
const dpcListPath = "/persist/status/nim/DevicePortConfigList/global.json"

// assertPortConfigRestored asserts the port-configuration list came back at all.
func assertPortConfigRestored(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, catGlob(dpcListPath))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).NotTo(BeEmpty(),
			"the port-configuration list did not come back: %s", dpcListPath)
	}, 5*time.Minute, 15*time.Second).Should(Succeed())
}

// assertIdentityRestored asserts every identity file came back with the content
// it had. Files that were absent to begin with are skipped, since there is
// nothing for them to come back as.
func assertIdentityRestored(t Gomega, device *evetest.EdgeDevice, before map[string]string) {
	after := snapshotIdentity(t, device)
	for path, want := range before {
		if want == "MISSING" {
			continue
		}
		t.Expect(after[path]).To(Equal(want),
			"%s did not come back with the content it had", path)
	}
	assertPortConfigRestored(t, device)
}

// assertDeviceUUIDUnchanged asserts the device kept the identity it was
// onboarded with, which is the difference between recovering and starting over.
func assertDeviceUUIDUnchanged(t Gomega, device *evetest.EdgeDevice, before string) {
	after := readDeviceUUID(t, device)
	t.Expect(after).To(Equal(before),
		"the device came back with a different UUID, so it did not recover its identity")
}

// readDeviceUUID returns the UUID the device is running as.
func readDeviceUUID(t Gomega, device *evetest.EdgeDevice) string {
	var id string
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, "cat /persist/status/uuid")
		g.Expect(err).NotTo(HaveOccurred())
		id = strings.TrimSpace(out)
		g.Expect(id).NotTo(BeEmpty(), "the device reports no UUID")
	}, 5*time.Minute, 10*time.Second).Should(Succeed())
	return id
}
