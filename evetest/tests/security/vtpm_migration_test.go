// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"fmt"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

const (
	vtpmLegacyVersionParam = "VTPM_LEGACY_EVE_VERSION"
	vtpmLegacyRepoParam    = "VTPM_LEGACY_EVE_REPO"
)

// TestAppVTPMLegacyToPCRMigration is an end-to-end upgrade test. The initial
// image must be a known build that creates NV-key-encrypted app state even
// though the device has a SHA256 PCR bank. One app keeps healthy legacy state;
// the other's two copies are corrupted before the upgrade. After upgrading,
// the first app must retain its NV identity under the PCR key, while the bad
// copies must be archived and the second app gets fresh state. Both must keep
// their post-upgrade identities after another reboot. SingleEthWithDHCP
// provides the controller and guest SSH links throughout the upgrade.
//
// Parameters:
//   - VTPM_LEGACY_EVE_VERSION: required pre-migration build (otherwise skip).
//   - VTPM_LEGACY_EVE_REPO: repository for that build (default lfedge/eve).
//   - EVE_VERSION: target build under test; empty uses the local HEAD build.
func TestAppVTPMLegacyToPCRMigration(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.EVEVersionParameter(),
		evetest.HypervisorParameter(),
		evetest.TestParameterDefinition{
			Key:          vtpmLegacyVersionParam,
			DefaultValue: "",
			Description: evetest.TestParameterDescription{
				Summary: "Pre-migration EVE build that creates legacy NV-encrypted vTPM state",
				Default: "unset; test skipped because it needs a legacy image fixture",
			},
		},
		evetest.TestParameterDefinition{
			Key:          vtpmLegacyRepoParam,
			DefaultValue: "lfedge/eve",
			Description: evetest.TestParameterDescription{
				Summary: "Container repository containing the pre-migration EVE image",
				Default: "lfedge/eve",
			},
		},
	)
	if evetest.GetHypervisorParameterValue() != evetest.HypervisorKVM {
		evetestT.Skip("vTPM migration requires KVM")
	}
	legacyVersion := evetest.GetTestParameter[string](vtpmLegacyVersionParam)
	if legacyVersion == "" {
		evetestT.Skip("set EVETEST_VTPM_LEGACY_EVE_VERSION to a verified legacy-key image")
	}
	targetVersion := evetest.GetEVEVersionParameterValue()
	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithEVEVersion:    legacyVersion,
			WithEVERepo:       evetest.GetTestParameter[string](vtpmLegacyRepoParam),
			WithHypervisor:    evetest.HypervisorKVM,
			WithTPM:           true,
			DeviceReusePolicy: evetest.CreateFromScratchWithInstaller,
		},
		evetest.RequireNetworkModel{NetworkModel: netmodels.SingleEthWithDHCP},
	)
	device := evetest.GetEdgeDevice(devName)
	config, niUUID := singleMgmtPortWithLocalNI(device, evetest.HypervisorKVM)
	id := addVTPMTestApp(config, niUUID, "vtpm-migration", 2222)
	badID := addVTPMTestApp(config, niUUID, "vtpm-both-keys-bad", 2223)
	device.ApplyConfig(config, true, true)
	device.WaitUntilAppIsRunning(id, appRunningTimeout)
	device.WaitUntilAppIsRunning(badID, appRunningTimeout)
	marker := newVTPMMarker(evetestT)
	writeGuestTPMMarker(t, device, id, marker)
	badMarker := newVTPMMarker(evetestT)
	writeGuestTPMMarker(t, device, badID, badMarker)
	expectDevicePath(t, device, fmt.Sprintf("%s/%s.encrypted", vtpmStateRoot, id), true)
	expectDevicePath(t, device, vtpmProtectedMarkerPath(id), false)
	expectDevicePath(t, device, fmt.Sprintf("%s/%s.encrypted", vtpmStateRoot, badID), true)
	expectDevicePath(t, device, vtpmProtectedMarkerPath(badID), false)
	evetest.Checkpoint("vtpm-legacy-state-created")

	// The second app exercises the case where neither key can read the state.
	// Corrupt both copies only after its TPM has shut down, so the fault is in
	// the saved bytes rather than a race with a running swtpm.
	device.RebootApplication(badID, true, appRunningTimeout)
	expectGuestTPMMarker(t, device, badID, badMarker)
	device.DeactivateApplication(badID, true, appRunningTimeout)
	expectSwtpmProcessCount(t, device, badID, 0)
	badState := vtpmStatePath(badID)
	expectDevicePath(t, device, badState+"/tpm2-00.permall.bak", true)
	corrupt := fmt.Sprintf(`set -eu
printf 'bad-legacy-primary' > %q/tpm2-00.permall
printf 'bad-legacy-backup' > %q/tpm2-00.permall.bak`, badState, badState)
	_, stderr, err := device.RunShellScript(corrupt, appSSHTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "corrupt legacy copies: %s", stderr)
	evetest.Checkpoint("vtpm-legacy-copies-corrupted")

	device.UpgradeEVE(targetVersion, evetest.HypervisorKVM,
		evetest.BaseOSDatastoreHTTP, true, false)
	device.WaitUntilAppIsRunning(id, appRunningTimeout)
	expectGuestTPMMarker(t, device, id, marker)
	expectOneSwtpmProcess(t, device, id)
	expectDevicePath(t, device, vtpmProtectedMarkerPath(id), true)
	t.Eventually(func(g Gomega) {
		out, stderr, err := device.RunShellScript("logread", 20*time.Second, 0)
		g.Expect(err).ToNot(HaveOccurred(), "read migration log: %s", stderr)
		g.Expect(strings.ToLower(out)).To(ContainSubstring(
			"migrated swtpm state for id "+id.String()),
			"the new build loaded the old state without exercising migration")
	}, 2*time.Minute, pollingInterval).Should(Succeed())
	evetest.Checkpoint("vtpm-state-migrated")

	device.ActivateApplication(badID, true, appRunningTimeout)
	waitForVTPMGuest(t, device, badID)
	expectDevicePath(t, device, vtpmProtectedMarkerPath(badID), true)
	oldNVCheck := fmt.Sprintf("if tpm2_nvread -C o -s %d %s >/dev/null 2>&1; then echo PRESENT; else echo ABSENT; fi",
		vtpmMarkerSize, vtpmNVIndex)
	oldNV, stderr, err := device.RunShellScriptInsideApp(badID, appAuth, oldNVCheck,
		appSSHTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "check old guest NV index: %s", stderr)
	t.Expect(strings.TrimSpace(oldNV)).To(Equal("ABSENT"),
		"both-key failure unexpectedly retained the old guest TPM identity")
	entries, err := device.ListDirEntries(vtpmStateRoot)
	t.Expect(err).ToNot(HaveOccurred())
	prefix := fmt.Sprintf("tpm-state-%s.corrupt-", badID)
	var archive string
	for _, entry := range entries {
		if strings.HasPrefix(entry, prefix) {
			t.Expect(archive).To(BeEmpty(), "multiple corrupt archives for one failed launch")
			archive = entry
		}
	}
	t.Expect(archive).ToNot(BeEmpty(), "both-key failure discarded the old state")
	oldPrimary, err := device.ReadFile(vtpmStateRoot + "/" + archive + "/tpm2-00.permall")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(string(oldPrimary)).To(Equal("bad-legacy-primary"))
	oldBackup, err := device.ReadFile(vtpmStateRoot + "/" + archive + "/tpm2-00.permall.bak")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(string(oldBackup)).To(Equal("bad-legacy-backup"))
	newMarker := newVTPMMarker(evetestT)
	writeGuestTPMMarker(t, device, badID, newMarker)
	evetest.Checkpoint("vtpm-both-keys-bad-preserved-and-reset")

	device.SoftReboot(true)
	device.WaitUntilAppIsRunning(id, appRunningTimeout)
	device.WaitUntilAppIsRunning(badID, appRunningTimeout)
	expectGuestTPMMarker(t, device, id, marker)
	expectGuestTPMMarker(t, device, badID, newMarker)
	expectOneSwtpmProcess(t, device, id)
	expectOneSwtpmProcess(t, device, badID)
	expectDevicePath(t, device, vtpmProtectedMarkerPath(id), true)
	evetest.Checkpoint("vtpm-migration-one-way-verified")
}
