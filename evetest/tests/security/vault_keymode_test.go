// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test that a vault whose persisted key-derivation mode was lost still opens.

package security

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	eveinfo "github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// Persisted pubsub topic holding the single bit that says which key
	// derivation the vault was created with. Removing it is the injected fault.
	vaultKeyModeDir = "/persist/status/vaultmgr/VaultConfig"

	vaultStatusFile = "/run/vaultmgr/VaultStatus/" + pillartypes.DefaultVaultName + ".json"

	// Written into the vault before the fault. Reading the same content back
	// afterwards is what separates "the original vault was opened" from "an
	// empty one was created in its place".
	vaultMarkerFile    = pillartypes.SealedDirName + "/evetest-keymode-marker"
	vaultMarkerContent = "keymode-recovery-marker"

	// types.VaultUnlockMethod values, restated because evetest pins a pillar
	// release older than the field.
	unlockTPMLocalSealed = 1

	vaultOpenTimeout = 5 * time.Minute

	// newlogd appends records to /persist/newlog/collect as they are logged, so
	// a message is readable on the device seconds after the fact.
	vaultLogTimeout = 2 * time.Minute

	// Upper bound on the settle reboots of settleVaultSeal.
	maxSettleReboots = 3

	shellCmdTimeout = 90 * time.Second

	// Only reached when the HYPERVISOR parameter selects EVE-k.
	clusterNodeReadyTimeout = 20 * time.Minute
)

// vaultStatus mirrors the fields of types.VaultStatus that this test reads.
// The publication is decoded here rather than into the pillar type because
// evetest pins a pillar release predating UnlockMethod.
type vaultStatus struct {
	Status             int
	ConversionComplete bool
	UnlockMethod       int
	MismatchingPCRs    []int
	Error              string
}

// TestVaultKeyModeRecovery verifies that a device recovers on its own when
// /persist comes back from a boot without the file recording which key
// derivation its vault was created with.
//
// /persist/status/vaultmgr/VaultConfig holds one bit: whether the vault key is
// the TPM key alone or that key merged with a build-time constant (the
// pre-7.10.0 form). An e2fsck repair of a torn /persist is free to clear that
// directory entry, and nothing on the device can reconstruct it. vaultmgr then
// infers the mode, and its only signal is whether the vault already exists --
// which for any existing vault answers "merged", the wrong derivation for every
// device installed since 7.10.0. The TPM unseal still succeeds and only the
// filesystem's own key check refuses, so the failure reads as a broken seal: the
// controller-key fallback re-seals and fails identically, and the device parks
// in maintenance mode with the vault locked. Persisting the guess on sight made
// that permanent.
//
// Fault injection
// ---------------
// `rm -rf /persist/status/vaultmgr/VaultConfig`, then a controller-requested
// reboot. Removing all of /persist/status reproduces a filesystem repair more
// faithfully, but it takes the device's onboarding state with it, so the fault is
// narrowed to the one file whose loss is not survivable.
//
// Evidence is read from the device's own /persist/newlog rather than from the
// controller: vaultmgr logs this during early boot, and those records reach the
// controller far too late to assert on within a test.
//
// Phases / assertions
// -------------------
//  1. setup-done: the device runs the filesystem this variant targets, its vault
//     is open and locally sealed (see settleVaultSeal), and its persisted mode is
//     TPM-key-only. That last check is load-bearing: against a vault created
//     with the merged key the inference below would be right by accident and the
//     test would prove nothing.
//  2. A marker file goes into the vault, to tell a recovered vault from a
//     recreated one.
//  3. rebooted-without-key-mode: the fault is confirmed to have landed before
//     the reboot, and again from the device's own logs afterwards. A fault that
//     silently failed to land would let every assertion below pass on an
//     ordinary boot, so the log counts are taken as a baseline first and
//     required to grow.
//  4. The logs must show the inferred mode failing and the other derivation
//     opening the vault; the unlock method must be the local TPM seal, since the
//     controller-key fallback and the wipe-and-recreate path would also end with
//     a device reporting an open vault; the marker must read back; the mode must
//     be persisted again; and the device must not be in maintenance mode.
//  5. rebooted-with-recovered-key-mode: a second reboot must read the persisted
//     mode with no inference at all, so the guess happens at most once per
//     device.
//
// The ZFS variant exercises a different vault handler with the same fault: it
// infers the mode from the dataset's key status rather than from a directory,
// and retries only the `zfs load-key`.
//
// Network model
// -------------
//   - netmodels.SingleEthWithDHCP -- not needed by the test itself, but the
//     network model is compared before device requirements are, so declaring the
//     same one as the rest of the suite is what keeps the SDN and EVE VMs from
//     being rebuilt.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
//   - FILESYSTEM (ext4|zfs, defaults to ext4).
//
// Suite placement: TestSecuritySuite, with one variant per filesystem, last
// because the filesystem is part of the device requirements and neither variant
// can share the device the rest of the suite reuses.
func TestVaultKeyModeRecovery(test *testing.T) {
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
			// The whole scenario is about a TPM-derived key; without a TPM
			// vaultmgr never consults the mode at all.
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

	// A device configuration has to be in place before the reboots below:
	// RequestReboot carries the reboot command on the device's current config,
	// and there is none until one is applied.
	device.ApplyConfig(vaultMgmtPortConfig(), true, true)

	// Which of the two vault handlers is under test is decided by what EVE
	// actually installed, so read it off the device rather than trusting the
	// requirement to have been honored.
	persistType, _, err := device.RunShellScript(
		"cat /run/eve.persist_type", shellCmdTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(strings.TrimSpace(persistType)).To(Equal(filesystem.String()),
		"the vault handler under test is selected by the /persist filesystem")

	waitForVaultOpen(t, device, filesystem, "before the fault")
	settleVaultSeal(t, device, filesystem)

	var keyMode pillartypes.VaultConfig
	t.Eventually(func() error {
		return evetest.ReadPublication(device, "vaultmgr", true, "global", &keyMode)
	}, vaultOpenTimeout, pollingInterval).Should(Succeed(),
		"vaultmgr must have persisted the vault key mode")
	t.Expect(keyMode.TpmKeyOnly).To(BeTrue(),
		"this test needs a vault created TPM-key-only; against one created with "+
			"the merged key the inference vaultmgr falls back to would be correct "+
			"and nothing would be exercised")
	evetest.Checkpoint("setup-done")

	runInPillar(t, device,
		"sh -c 'printf %s "+vaultMarkerContent+" > "+vaultMarkerFile+"'")
	runInPillar(t, device, "sync")

	// Baselines: the messages below also occur on a device's very first boot,
	// which legitimately has no vault config yet, so only growth after the fault
	// is evidence.
	const (
		msgNoConfig  = "Could not find vault config"
		msgInferring = "No persisted vault config; inferring tpmKeyOnly false"
		msgRetry     = "Vault did not open with inferred tpmKeyOnly=false"
		msgOpened    = "Vault opened with tpmKeyOnly=true"
		msgFromDisk  = "Vault config inited with tpmkeyonly true"
	)
	base := map[string]int{}
	for _, msg := range []string{msgNoConfig, msgInferring, msgRetry, msgOpened} {
		base[msg] = newlogCount(t, device, msg)
	}

	log.Infof("Removing the persisted vault key mode (%s)...", vaultKeyModeDir)
	_, stderr, err := device.RunShellScript(
		"rm -rf "+vaultKeyModeDir, shellCmdTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(),
		"failed to remove %s (stderr: %s)", vaultKeyModeDir, stderr)
	device.SyncDisks()
	exists, err := device.PathExists(vaultKeyModeDir)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(exists).To(BeFalse(),
		"%s is still there, so the reboot below would be an ordinary one and "+
			"every assertion after it would pass without the fault", vaultKeyModeDir)

	log.Infof("Rebooting the device with no persisted vault key mode...")
	device.RequestReboot(true)
	evetest.Checkpoint("rebooted-without-key-mode")

	waitForVaultOpen(t, device, filesystem, "after the persisted key mode was lost")

	// The fault landed: vaultmgr found no mode to read on this boot, and fell
	// back to inferring the merged form.
	expectNewlogGrew(t, device, msgNoConfig, base[msgNoConfig],
		"vaultmgr must report the persisted vault key mode as missing")
	expectNewlogGrew(t, device, msgInferring, base[msgInferring],
		"vaultmgr must infer the merged derivation for an existing vault")
	// The inferred mode did not open the vault, and the other derivation did.
	expectNewlogGrew(t, device, msgRetry, base[msgRetry],
		"the inferred mode must fail and be retried, not be trusted")
	expectNewlogGrew(t, device, msgOpened, base[msgOpened],
		"the vault must open with the derivation the inference got wrong")

	// The local seal is what opened it. The controller-key fallback and the
	// wipe-and-recreate path both also end with an open vault, so this is what
	// distinguishes recovery from either of them.
	st := readVaultStatus(t, device)
	t.Expect(st.UnlockMethod).To(Equal(unlockTPMLocalSealed),
		"the vault must be opened by the local TPM seal, not the controller key "+
			"or a recreate (unlockMethod=%d mismatchingPCRs=%v)",
		st.UnlockMethod, st.MismatchingPCRs)

	marker := runInPillar(t, device, "cat "+vaultMarkerFile)
	t.Expect(strings.TrimSpace(marker)).To(Equal(vaultMarkerContent),
		"the vault that was opened must be the one the marker was written to")

	keyMode = pillartypes.VaultConfig{}
	t.Eventually(func() error {
		return evetest.ReadPublication(device, "vaultmgr", true, "global", &keyMode)
	}, vaultOpenTimeout, pollingInterval).Should(Succeed(),
		"the mode that opened the vault must be persisted again")
	t.Expect(keyMode.TpmKeyOnly).To(BeTrue(),
		"the persisted mode must be the one that worked, not the inferred one")

	// The reboot wait already required a post-reboot info message, so this reads
	// the recovered boot's own report rather than a stale one.
	devInfo := device.GetDeviceInfo()
	t.Expect(devInfo.GetMaintenanceMode()).To(BeFalse(),
		"the device must not park in maintenance mode: reasons=%v",
		devInfo.GetMaintenanceModeReasons())

	stickyBase := map[string]int{
		msgNoConfig: newlogCount(t, device, msgNoConfig),
		msgRetry:    newlogCount(t, device, msgRetry),
		msgFromDisk: newlogCount(t, device, msgFromDisk),
	}
	log.Infof("Rebooting the device again, now with the key mode persisted...")
	device.RequestReboot(true)
	evetest.Checkpoint("rebooted-with-recovered-key-mode")

	waitForVaultOpen(t, device, filesystem, "after a second reboot")

	// Positive control for the two no-growth assertions below: this boot did log
	// about the vault config, and what it logged is that the mode came from the
	// file rather than from a guess.
	expectNewlogGrew(t, device, msgFromDisk, stickyBase[msgFromDisk],
		"vaultmgr must read the recovered mode from disk")
	t.Expect(newlogCount(t, device, msgNoConfig)).To(Equal(stickyBase[msgNoConfig]),
		"the recovered mode must survive the reboot")
	t.Expect(newlogCount(t, device, msgRetry)).To(Equal(stickyBase[msgRetry]),
		"a persisted mode must not be second-guessed")

	runInPillar(t, device, "rm -f "+vaultMarkerFile)
}

// settleVaultSeal reboots until the vault is opened by the local TPM seal.
//
// A device seals its vault key on its first boot, before onboarding writes the
// per-device /config files (device.cert.pem, tpm_credential, soft_serial).
// measure-config records those by existence into PCR14, so the next boot's PCR14
// no longer satisfies the sealing policy: the local unseal fails, the
// controller-provided key unlocks the vault, and that re-seals against the
// settled /config. Only from the boot after that does the local seal hold.
// Injecting the fault before this settles measures the PCR14 re-seal instead --
// the recovery would then arrive over the controller-key path and the local-seal
// assertion could not be made.
func settleVaultSeal(t *WithT, device *evetest.EdgeDevice,
	filesystem evetest.Filesystem) {
	for i := 0; i < maxSettleReboots; i++ {
		device.RequestReboot(true)
		waitForVaultOpen(t, device, filesystem, "after a settle reboot")
		if readVaultStatus(t, device).UnlockMethod == unlockTPMLocalSealed {
			return
		}
	}
	st := readVaultStatus(t, device)
	t.Expect(st.UnlockMethod).To(Equal(unlockTPMLocalSealed),
		"the vault seal did not settle to the local TPM key within %d reboots "+
			"(unlockMethod=%d mismatchingPCRs=%v); until it does, a recovery over "+
			"the controller key cannot be told apart from a PCR re-seal",
		maxSettleReboots, st.UnlockMethod, st.MismatchingPCRs)
}

// waitForVaultOpen blocks until vaultmgr reports the default vault as unlocked
// with no error, and on ZFS until the vault's ext4-on-zvol is actually mounted
// -- vaultmgr's status follows the dataset key, which is loaded before the mount
// happens.
func waitForVaultOpen(t *WithT, device *evetest.EdgeDevice,
	filesystem evetest.Filesystem, when string) {
	t.Eventually(func(g Gomega) {
		data, err := device.ReadFile(vaultStatusFile)
		g.Expect(err).ToNot(HaveOccurred())
		var st vaultStatus
		g.Expect(json.Unmarshal(data, &st)).To(Succeed())
		g.Expect(st.Status).To(
			Equal(int(eveinfo.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED)),
			"vault status is %d", st.Status)
		g.Expect(st.Error).To(BeEmpty())
	}, vaultOpenTimeout, pollingInterval).Should(Succeed(),
		"the vault must be unlocked "+when)

	if filesystem != evetest.FilesystemZFS {
		return
	}
	t.Eventually(func() error {
		_, _, err := device.RunShellScript(
			"eve exec pillar mountpoint -q "+pillartypes.SealedDirName,
			shellCmdTimeout, 0)
		return err
	}, vaultOpenTimeout, pollingInterval).Should(Succeed(),
		pillartypes.SealedDirName+" must be mounted "+when)
}

// readVaultStatus returns the current VaultStatus publication for the default
// vault.
func readVaultStatus(t *WithT, device *evetest.EdgeDevice) vaultStatus {
	data, err := device.ReadFile(vaultStatusFile)
	t.Expect(err).ToNot(HaveOccurred(), "failed to read %s", vaultStatusFile)
	var st vaultStatus
	t.Expect(json.Unmarshal(data, &st)).To(Succeed(),
		"failed to decode %s", vaultStatusFile)
	return st
}

// newlogCount returns how many records in the device's on-disk logs contain
// pattern.
//
// The whole of /persist/newlog is swept, not just collect/: collect/ holds only
// the last few minutes because newlogd rotates on size or a timer, so anything
// older -- including most of the current boot -- is already in the gzipped
// queues. One zcat per file keeps the argument list bounded and lets -f cover
// the plaintext chunks in collect/.
func newlogCount(t *WithT, device *evetest.EdgeDevice, pattern string) int {
	out := runInPillar(t, device,
		"sh -c 'find /persist/newlog -name \"dev.log.*\" -exec zcat -f {} \\; "+
			"| grep -a -F -c -- \""+pattern+"\" || true'")
	count, err := strconv.Atoi(strings.TrimSpace(out))
	t.Expect(err).ToNot(HaveOccurred(),
		"unexpected grep -c output %q for pattern %q", out, pattern)
	return count
}

// expectNewlogGrew waits until the device has logged pattern more times than
// base. Records are counted rather than matched by timestamp because newlogd
// keeps each one in both the keep and upload streams, so absolute counts are not
// meaningful but growth is.
func expectNewlogGrew(t *WithT, device *evetest.EdgeDevice, pattern string,
	base int, description string) {
	t.Eventually(func() int {
		return newlogCount(t, device, pattern)
	}, vaultLogTimeout, pollingInterval).Should(BeNumerically(">", base),
		"%s (no new log record containing %q; still %d)", description, pattern, base)
}

// runInPillar runs a command in the pillar container and returns its stdout.
// The vault and the logs are reachable from there in both layouts: on ZFS
// /persist/vault is an ext4-on-zvol mounted in pillar's mount namespace, not in
// the one the device's management SSH lands in.
func runInPillar(t *WithT, device *evetest.EdgeDevice, cmd string) string {
	stdout, stderr, err := device.RunShellScript(
		"eve exec pillar "+cmd, shellCmdTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(),
		"%q failed on the device (stderr: %s)", cmd, stderr)
	return stdout
}

// vaultMgmtPortConfig is the smallest configuration this test can run under: a
// single DHCP management port, no network instances and no applications, so the
// next subtest's config reset has nothing to wait for.
func vaultMgmtPortConfig() *evetest.EdgeDeviceConfig {
	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	return devConfig
}
