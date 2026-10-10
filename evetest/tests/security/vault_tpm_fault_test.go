// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Test that a TPM error while checking for the disk key never replaces it.

package security

import (
	"strings"
	"testing"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

const (
	// The fault point compiled into a FAULT_INJECTION=y image
	// (pkg/pillar/evetpm/faultinjection_keypresence.go): it fails that many
	// disk-key presence checks, counting the file down, or every one of them
	// while it reads "always".
	keyPresenceFaultFile = pillartypes.PersistStatusDir + "/tpm-key-presence-fault"

	tpmFaultMarkerFile    = pillartypes.SealedDirName + "/evetest-tpm-fault-marker"
	tpmFaultMarkerContent = "tpm-fault-marker"

	// One fewer than the presence check's attempts, so the check recovers.
	transientKeyPresenceFaults = "2"

	msgPresenceRetry  = "checking for the sealed disk key (attempt"
	msgPresenceFailed = "cannot tell whether a sealed disk key exists"
	msgFreshDiskKey   = "neither legacy nor sealed disk key present, generating a fresh key"
)

// TestVaultKeyKeptOnTPMError reboots a device whose TPM fails the check for the
// sealed disk key, first transiently and then on every attempt, and checks that
// the vault it opens afterwards is the original one. Taking that failure for an
// absent key seals a fresh key over the one the vault is encrypted with, and the
// vault is then lost on the next boot.
//
// Requires an image built with FAULT_INJECTION=y; the test skips when the fault
// point is not compiled in.
func TestVaultKeyKeptOnTPMError(test *testing.T) {
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
			Name:              devName,
			WithHypervisor:    hypervisor,
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

	device.ApplyConfig(vaultMgmtPortConfig(), true, true)
	waitForVaultOpen(t, device, filesystem, "before the fault")
	settleVaultSeal(t, device, filesystem)
	evetest.Checkpoint("setup-done")

	runInPillar(t, device,
		"sh -c 'printf %s "+tpmFaultMarkerContent+" > "+tpmFaultMarkerFile+"'")
	runInPillar(t, device, "sync")

	armFault := func(value string) map[string]int {
		_, stderr, err := device.RunShellScript(
			"echo "+value+" > "+keyPresenceFaultFile, shellCmdTimeout, 0)
		t.Expect(err).ToNot(HaveOccurred(),
			"failed to write %s (stderr: %s)", keyPresenceFaultFile, stderr)
		device.SyncDisks()
		base := map[string]int{}
		for _, msg := range []string{msgPresenceRetry, msgPresenceFailed, msgFreshDiskKey} {
			base[msg] = newlogCount(t, device, msg)
		}
		return base
	}
	expectOriginalVault := func(when string) {
		waitForVaultOpen(t, device, filesystem, when)
		st := readVaultStatus(t, device)
		t.Expect(st.UnlockMethod).To(Equal(unlockTPMLocalSealed),
			"the vault must be opened by the local TPM seal %s "+
				"(unlockMethod=%d mismatchingPCRs=%v)",
			when, st.UnlockMethod, st.MismatchingPCRs)
		marker := runInPillar(t, device, "cat "+tpmFaultMarkerFile)
		t.Expect(strings.TrimSpace(marker)).To(Equal(tpmFaultMarkerContent),
			"the vault opened %s must be the one the marker was written to", when)
	}

	log.Infof("Rebooting with %s presence-check faults armed...", transientKeyPresenceFaults)
	base := armFault(transientKeyPresenceFaults)
	device.RequestReboot(true)
	evetest.Checkpoint("rebooted-with-transient-fault")

	waitForVaultOpen(t, device, filesystem, "after the transient fault")
	left, err := device.ReadFile(keyPresenceFaultFile)
	t.Expect(err).ToNot(HaveOccurred())
	if strings.TrimSpace(string(left)) == transientKeyPresenceFaults {
		test.Skipf("the image under test was built without FAULT_INJECTION=y: "+
			"%s was never consumed", keyPresenceFaultFile)
	}
	t.Expect(strings.TrimSpace(string(left))).To(Equal("0"),
		"every armed fault must have been taken")
	expectNewlogGrew(t, device, msgPresenceRetry, base[msgPresenceRetry],
		"the injected TPM error must be retried")
	t.Expect(newlogCount(t, device, msgFreshDiskKey)).To(Equal(base[msgFreshDiskKey]),
		"a TPM error must not be taken for an absent disk key")
	expectOriginalVault("after the transient fault")

	log.Infof("Rebooting with every presence check failing...")
	base = armFault("always")
	device.RequestReboot(true)
	evetest.Checkpoint("rebooted-with-persistent-fault")

	expectNewlogGrew(t, device, msgPresenceFailed, base[msgPresenceFailed],
		"a TPM that keeps failing must be reported, not read as an absent key")
	t.Expect(newlogCount(t, device, msgFreshDiskKey)).To(Equal(base[msgFreshDiskKey]),
		"a TPM that keeps failing must not cause a fresh disk key")

	log.Infof("Clearing the fault and rebooting...")
	_, stderr, err := device.RunShellScript(
		"rm -f "+keyPresenceFaultFile, shellCmdTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(),
		"failed to remove %s (stderr: %s)", keyPresenceFaultFile, stderr)
	device.SyncDisks()
	device.RequestReboot(true)
	evetest.Checkpoint("rebooted-with-fault-cleared")
	expectOriginalVault("after the persistent fault was cleared")

	runInPillar(t, device, "rm -f "+tpmFaultMarkerFile)
}
