// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Helpers observing and changing the state the vault key depends on.

package security

import (
	"fmt"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/matchers"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// configPartitionScript returns a shell script that writes content into name
// on the CONFIG partition, or removes name when content is empty.
func configPartitionScript(name, content string) string {
	op := fmt.Sprintf(`printf %%s '%s' > "$M/%s"`, content, name)
	if content == "" {
		op = fmt.Sprintf(`rm -f "$M/%s"`, name)
	}
	return fmt.Sprintf(`set -u
CFGP=$(findfs PARTLABEL=CONFIG) || { echo "FAIL: no CONFIG partition"; exit 1; }
M=/tmp/evetest-cfg-rw; mkdir -p "$M"
mount -t vfat -o rw,iocharset=iso8859-1 "$CFGP" "$M" || { echo "FAIL: could not mount CONFIG"; exit 1; }
rc=1
%s && sync && rc=0
umount "$M"; rmdir "$M"
[ $rc = 0 ] && echo DONE`, op)
}

// writeConfigPartitionFile writes content into name on the CONFIG partition, or
// removes name when content is empty.
//
// The running /config is a read-only RAM copy of the partition made at boot, so
// the change takes effect on the next boot. measure-config then hashes every
// file under /config into PCR14, which the vault key is sealed against, so any
// change made here makes the next boot's local TPM unseal fail.
func writeConfigPartitionFile(t *WithT, device *evetest.EdgeDevice,
	name, content string) {
	out, stderr, err := device.RunShellScript(
		configPartitionScript(name, content), shellCmdTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(),
		"changing %s on the CONFIG partition failed:\n%s%s", name, out, stderr)
	t.Expect(out).To(ContainSubstring("DONE"),
		"changing %s on the CONFIG partition failed:\n%s%s", name, out, stderr)
}

// pathExists reports whether path exists in the pillar container.
func pathExists(t *WithT, device *evetest.EdgeDevice, path string) bool {
	out := runInPillar(t, device,
		"sh -c 'if test -e "+path+"; then echo yes; else echo no; fi'")
	return strings.TrimSpace(out) == "yes"
}

// vaultmgrLogTimeout bounds how long a vaultmgr record takes to reach the
// controller. The device uploads its log backlog within seconds of booting, but
// records are batched, which has delayed them by up to about 40s.
const vaultmgrLogTimeout = 5 * time.Minute

// waitForVaultmgrLog waits until the controller has received a vaultmgr record
// containing substr and logged at or after since, and returns it. since is
// compared with the device's timestamps, so it relies on the host and device
// clocks agreeing, as RequestReboot does.
func waitForVaultmgrLog(t *WithT, device *evetest.EdgeDevice, substr string,
	since time.Time, description string) evetest.LogMsg {
	match := evetest.LogMsgMatch{
		Source:          "vaultmgr",
		MsgHasSubstring: substr,
		NotBefore:       since,
	}
	// Subscribe before reading what the controller already has, so that no
	// record arriving in between is missed.
	logs, stop := device.WatchLogs(match)
	defer stop()
	if received := device.GetLogs(match); len(received) > 0 {
		return received[0]
	}
	var msg evetest.LogMsg
	t.Eventually(logs, vaultmgrLogTimeout).Should(Receive(&msg),
		"%s (no vaultmgr log record containing %q logged since %s)",
		description, substr, since.Format(time.RFC3339))
	return msg
}

// defaultVaultInfo returns what the device info reports about the default
// vault, or nil if it reports nothing about it.
func defaultVaultInfo(devInfo *eveinfo.ZInfoDevice) *eveinfo.VaultInfo {
	for _, vault := range devInfo.GetDataSecAtRestInfo().GetVaultList() {
		if vault.GetName() == pillartypes.DefaultVaultName {
			return vault
		}
	}
	return nil
}

// expectVaultReported waits until the device reports the default vault with
// the given status and unlock method.
func expectVaultReported(t *WithT, device *evetest.EdgeDevice,
	status eveinfo.DataSecAtRestStatus, method eveinfo.VaultUnlockMethod,
	when string) {
	matches := func(devInfo *eveinfo.ZInfoDevice) bool {
		vault := defaultVaultInfo(devInfo)
		return vault != nil && vault.GetStatus() == status &&
			vault.GetUnlockMethod() == method
	}
	// Subscribe before reading the latest report, so that no report in
	// between is missed.
	updates, stop := device.WatchDeviceInfo()
	defer stop()
	if matches(device.GetDeviceInfo()) {
		return
	}
	t.Eventually(updates, vaultOpenTimeout).Should(Receive(
		matchers.SatisfyPredicate(
			fmt.Sprintf("Device reports the vault %s and unlocked by %s %s",
				status, method, when),
			matches)),
		"last reported vault: %v", defaultVaultInfo(device.GetDeviceInfo()))
}

// waitForEscrowThisBoot waits until the device reports its attestation
// complete on the current boot. The device escrows its vault key as the last
// step of attestation, so from then on the controller holds the key of this
// boot and the device will not send it again until it reboots. Until then, a
// key removed from the controller is put back by the pending escrow.
func waitForEscrowThisBoot(t *WithT, device *evetest.EdgeDevice) {
	// Subscribe before reading the latest report, so that no report in
	// between is missed.
	updates, stop := device.WatchDeviceInfo()
	defer stop()
	latest := device.GetDeviceInfo()
	t.Expect(latest.GetBootTime().IsValid()).To(BeTrue(),
		"the device reports no boot time")
	bootTime := latest.GetBootTime().AsTime()
	matches := func(devInfo *eveinfo.ZInfoDevice) bool {
		return devInfo.GetBootTime().AsTime().Equal(bootTime) &&
			devInfo.GetAttestationInfo().GetState() ==
				eveinfo.AttestationState_ATTESTATION_STATE_COMPLETE
	}
	if matches(latest) {
		return
	}
	t.Eventually(updates, vaultOpenTimeout).Should(Receive(
		matchers.SatisfyPredicate(
			"Device reports attestation (and with it the vault key escrow) "+
				"complete on this boot",
			matches)),
		"last reported attestation: %v",
		device.GetDeviceInfo().GetAttestationInfo())
}
