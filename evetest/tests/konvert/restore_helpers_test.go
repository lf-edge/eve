// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"encoding/json"
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

// resizeTargetSize is the boot-disk size the backup is taken against. It is
// larger than the disk, so in resizeFailureReal mode the offline grow that
// follows the shrink finds no room and aborts.
const resizeTargetSize = "78G"

// How a restore test's offline resize fails, which decides who writes
// resize-failed.json. In resizeFailureReal the backup arms a resize that runs
// on the next boot and aborts, and storage-resize.sh's resize_abort writes the
// marker and reboots. In resizeFailureSimulated the test writes the marker
// itself, naming the running release, so the resize is skipped and only the
// restore runs.
const (
	resizeFailureReal      = "real"
	resizeFailureSimulated = "simulated"
	// simulatedFailureStep is the step the simulated marker names.
	simulatedFailureStep = "restore-test"
)

// restoreParameterDefinitions declares the axis the restore tests add.
func restoreParameterDefinitions() []evetest.TestParameterDefinition {
	return []evetest.TestParameterDefinition{
		{
			Key:          resizeFailureParamKey,
			DefaultValue: resizeFailureReal,
			Description: evetest.TestParameterDescription{
				Summary:       "Whether the offline resize really aborts or a failure marker is planted",
				Default:       resizeFailureReal,
				AllowedValues: resizeFailureReal + "|" + resizeFailureSimulated,
			},
		},
	}
}

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
		// Not a management port, so a port with no radio behind it is never
		// chosen to reach the controller on the offline boot; it only has to
		// be configured, which is all this needs.
		Usage: evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		Cost:  10,
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
//
// With simulatedRelease set, it also writes a resize-failed.json naming that
// release, which is what makes storage-init skip the resize the flag arms.
func backupIdentityToConfig(t Gomega, device *evetest.EdgeDevice, simulatedRelease string) {
	marker := ""
	if simulatedRelease != "" {
		marker = fmt.Sprintf(`printf '{"eve_release":"%s","step":"%s","rc":"0","ts":"restore"}' > /tmp/restore-cfg/resize-failed.json`,
			simulatedRelease, simulatedFailureStep)
	}
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
if [ ! -f "$LC" ] || ! tr -d '\0' < "$LC" | grep -q %q \
   || ! ls /tmp/restore-cfg/backup-persist/certs/ecdh.*.pem >/dev/null 2>&1; then
    echo "FAIL: the backup never captured the wireless credential and an ecdh certificate"
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
cp /persist/checkpoint/lastconfig /persist/checkpoint/lastconfig.bak \
    || { echo "FAIL: could not refresh lastconfig.bak"; umount /tmp/restore-cfg; exit 1; }
tr -d '\0' < /persist/checkpoint/lastconfig.bak | grep -q %q \
    || { echo "FAIL: the refreshed lastconfig.bak lacks the wireless credential"; umount /tmp/restore-cfg; exit 1; }
%s
sync
umount /tmp/restore-cfg 2>/dev/null
echo "BACKUP-DONE"`, resizeTargetSize, restoreWiFiSSID, restoreWiFiSSID, restoreWiFiSSID, marker)

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
	"/persist/certs/ecdh.cert.pem",
	"/persist/certs/attest.cert.pem",
	"/persist/certs/ek.cert.pem",
	"/persist/status/zedclient/OnboardingStatus/global.json",
}

// dpcListPath is the port-configuration list. nim rewrites it as it tests
// ports, so it is compared with the fields nim updates stripped
// (normalizedPortConfig) rather than byte for byte.
const dpcListPath = "/persist/status/nim/DevicePortConfigList/global.json"

// Fields of pillar's DevicePortConfig and NetworkPortConfig (types/dpc.go,
// with the embedded TestResults of types/conntest.go) that change without the
// configuration changing: test results, the state machine, and TimePriority and
// ConfigSource, which zedagent re-stamps when it re-applies a checkpointed
// configuration offline.
var (
	volatileDPCFields  = []string{"State", "LastFailed", "LastSucceeded", "LastError", "LastWarning", "LastIPAndDNS", "TimePriority"}
	volatilePortFields = []string{"LastFailed", "LastSucceeded", "LastError", "LastWarning", "ConfigSource"}
)

// readPortConfig returns the port-configuration list with its volatile fields
// stripped, as canonical JSON, or "" while there is none.
func readPortConfig(t Gomega, device *evetest.EdgeDevice) string {
	out, err := runEVE(device, catGlob(dpcListPath))
	t.Expect(err).NotTo(HaveOccurred())
	lists := decodeJSONStream(out)
	if len(lists) == 0 {
		return ""
	}
	return normalizedPortConfig(lists[0])
}

// normalizedPortConfig strips a DevicePortConfigList of the fields that change
// on their own and returns it as JSON with sorted keys.
func normalizedPortConfig(list map[string]any) string {
	delete(list, "CurrentIndex")
	dpcs, _ := list["PortConfigList"].([]any)
	for _, d := range dpcs {
		dpc, _ := d.(map[string]any)
		for _, k := range volatileDPCFields {
			delete(dpc, k)
		}
		ports, _ := dpc["Ports"].([]any)
		for _, p := range ports {
			port, _ := p.(map[string]any)
			for _, k := range volatilePortFields {
				delete(port, k)
			}
		}
	}
	b, _ := json.Marshal(list)
	return string(b)
}

// assertPortConfigRestored asserts the port-configuration list came back with
// the configuration it held before the damage.
func assertPortConfigRestored(t Gomega, device *evetest.EdgeDevice, before string) {
	t.Expect(before).NotTo(BeEmpty(), "there was no port-configuration list before the damage")
	var after string
	t.Eventually(func(g Gomega) {
		after = readPortConfig(g, device)
		g.Expect(after).NotTo(BeEmpty(),
			"the port-configuration list did not come back: %s", dpcListPath)
	}, 5*time.Minute, 15*time.Second).Should(Succeed())
	t.Expect(after).To(Equal(before),
		"the port-configuration list came back with a different configuration")
}

// assertIdentityRestored asserts every identity file came back with the content
// it had. Files that were absent to begin with are skipped, since there is
// nothing for them to come back as.
func assertIdentityRestored(t Gomega, device *evetest.EdgeDevice, before map[string]string,
	portConfigBefore string) {
	after := snapshotIdentity(t, device)
	for path, want := range before {
		if want == "MISSING" {
			continue
		}
		t.Expect(after[path]).To(Equal(want),
			"%s did not come back with the content it had", path)
	}
	assertPortConfigRestored(t, device, portConfigBefore)
}

// assertControllerUnreachable asserts the device cannot reach its controller.
// It is the positive control for isolateFromController: a path that leaked
// would let the device be told everything again and pass the restore tests
// having recovered nothing.
//
// The ping needs the pillar container, which may still be starting, so it is
// retried until it runs.
func assertControllerUnreachable(t Gomega, device *evetest.EdgeDevice) {
	var out string
	t.Eventually(func(g Gomega) {
		var err error
		// curl fails when it cannot connect, having printed 000 all the same.
		out, err = runEVE(device, pingController+"; true")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).To(MatchRegexp(`[0-9]{3}$`),
			"the ping did not run")
	}, 5*time.Minute, 10*time.Second).Should(Succeed())
	t.Expect(strings.TrimSpace(out)).NotTo(HaveSuffix("200"),
		"the device still reaches its controller, so the restore would not be offline")
}

// assertResizeBookkeeping asserts storage-init finished with the conversion's
// bookkeeping on the CONFIG partition: the repartition flag and the backup are
// gone, and resize-failed.json is left for baseosmgr, naming the running
// release, the failed step, and whether /persist was recreated. It returns the
// marker's step. The leftovers are checked on /config, where storage-init
// mirrors its removals; the marker is read from the partition, because the
// restore stamps persist_recreated there only and the RAM copy keeps the
// unstamped marker until the next boot. baseosmgr reads the partition too.
func assertResizeBookkeeping(t Gomega, device *evetest.EdgeDevice, mode, running string,
	wantRecreated bool) string {
	out, err := runEVE(device, `for f in repartition-inprogress backup-persist; do `+
		`[ -e /config/$f ] && echo "LEFT $f"; done; true`)
	t.Expect(err).NotTo(HaveOccurred())
	t.Expect(strings.TrimSpace(out)).To(BeEmpty(), "restore did not clean up:\n%s", out)

	raw := readConfigPartitionFile(t, device, "resize-failed.json")
	t.Expect(raw).NotTo(Equal("NONE"), "no resize-failed.json is left for baseosmgr")
	var marker struct {
		EveRelease       string `json:"eve_release"`
		Step             string `json:"step"`
		PersistRecreated bool   `json:"persist_recreated"`
	}
	t.Expect(json.Unmarshal([]byte(raw), &marker)).To(Succeed(), "resize-failed.json: %s", raw)
	evetest.Logger().Infof("resize-failed.json: %s", raw)
	t.Expect(marker.EveRelease).To(Equal(running), "the marker names another release: %s", raw)
	if mode == resizeFailureSimulated {
		t.Expect(marker.Step).To(Equal(simulatedFailureStep),
			"the planted marker was replaced, so the resize ran: %s", raw)
	} else {
		t.Expect(marker.Step).To(BeElementOf("shrink", "grow"),
			"the marker is not resize_abort's: %s", raw)
	}
	t.Expect(marker.PersistRecreated).To(Equal(wantRecreated),
		"persist_recreated does not match whether /persist was recreated: %s", raw)
	return marker.Step
}

// readConfigPartitionFile returns the contents of name on the CONFIG partition,
// mounted read-only for the read, or "NONE" when there is no such file.
func readConfigPartitionFile(t Gomega, device *evetest.EdgeDevice, name string) string {
	out, err := runEVE(device, fmt.Sprintf(`set -u
CFGP=$(findfs PARTLABEL=CONFIG) || { echo "FAIL: no CONFIG partition"; exit 1; }
M=/tmp/konvert-cfg-ro; mkdir -p "$M"
mount -t vfat -o ro,iocharset=iso8859-1 "$CFGP" "$M" || { echo "FAIL: could not mount CONFIG"; exit 1; }
cat "$M/%s" 2>/dev/null || echo NONE
umount "$M"; rmdir "$M"`, name))
	t.Expect(err).NotTo(HaveOccurred(), "reading %s from the CONFIG partition failed: %s", name, out)
	return strings.TrimSpace(out)
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
