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
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

func vtpmAppArmorDenials(output string) map[string]bool {
	denials := make(map[string]bool)
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, `apparmor="DENIED"`) &&
			strings.Contains(line, `profile="vtpm"`) {
			denials[strings.TrimSpace(line)] = true
		}
	}
	return denials
}

// TestAppVTPMProtectedKeyPath confirms that a SHA256-capable device uses the
// PCR-protected key and that launching an app introduces no vtpm AppArmor
// denials. The guest NV value proves that the key path also produces a usable
// vTPM. SingleEthWithDHCP supplies controller and guest SSH connectivity.
func TestAppVTPMProtectedKeyPath(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	device, config, niUUID := setupVTPMDevice(evetestT, true)
	before, stderr, err := device.RunShellScript("dmesg", 20*time.Second, 0)
	t.Expect(err).ToNot(HaveOccurred(), "read kernel audit log before launch: %s", stderr)
	baseline := vtpmAppArmorDenials(before)

	id := addVTPMTestApp(config, niUUID, "vtpm-protected-key", 2222)
	device.ApplyConfig(config, true, true)
	device.WaitUntilAppIsRunning(id, appRunningTimeout)
	marker := newVTPMMarker(evetestT)
	writeGuestTPMMarker(t, device, id, marker)
	expectGuestTPMMarker(t, device, id, marker)
	expectDevicePath(t, device, vtpmProtectedMarkerPath(id), true)
	expectDevicePath(t, device, fmt.Sprintf("%s/%s.encrypted", vtpmStateRoot, id), true)
	for path, mode := range map[string]string{
		vtpmStatePath(id):                          "700 101 101",
		fmt.Sprintf("/run/swtpm/%s.ctrl.sock", id): "600 101 101",
	} {
		out, statErrOut, statErr := device.RunShellScript(
			fmt.Sprintf("stat -c '%%a %%u %%g' %q", path), appSSHTimeout, 0)
		t.Expect(statErr).ToNot(HaveOccurred(), "stat vTPM path %s: %s", path, statErrOut)
		t.Expect(strings.TrimSpace(out)).To(Equal(mode), "unsafe vTPM path permissions: %s", path)
	}
	evetest.Checkpoint("vtpm-pcr-key-active")

	after, stderr, err := device.RunShellScript("dmesg", 20*time.Second, 0)
	t.Expect(err).ToNot(HaveOccurred(), "read kernel audit log after launch: %s", stderr)
	for denial := range vtpmAppArmorDenials(after) {
		t.Expect(baseline).To(HaveKey(denial), "new AppArmor denial during vTPM launch: %s", denial)
	}
}

// TestAppVTPMLegacyKeyWithoutSHA256 checks the NV-stored legacy key path on a
// KVM device whose host TPM has only the SHA1 PCR bank.
func TestAppVTPMLegacyKeyWithoutSHA256(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	device, config, niUUID := setupVTPMDeviceWithPCRBanks(evetestT, true,
		[]api.TPMPCRBank{api.TPMPCRBank_TPM_PCR_BANK_SHA1})
	// EVE's host shell does not carry tpm2-tools; the vtpm service image does.
	_, stderr, err := device.RunShellScript("eve exec vtpm /usr/bin/tpm2 pcrread sha1:0", appSSHTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "SHA1 PCR bank is unavailable: %s", stderr)
	// tpm2 pcrread exits successfully even when the selected bank has no
	// active PCRs, so inspect the TPM's allocation instead.
	banks, stderr, err := device.RunShellScript("eve exec vtpm /usr/bin/tpm2 getcap pcrs", appSSHTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "read active PCR banks: %s", stderr)
	t.Expect(banks).To(ContainSubstring("- sha1: [ 0,"), "SHA1 PCR bank is inactive")
	t.Expect(banks).To(ContainSubstring("- sha256: [ ]"), "SHA256 PCR bank is unexpectedly active")
	id := addVTPMTestApp(config, niUUID, "vtpm-legacy-key", 2222)
	device.ApplyConfig(config, true, true)
	device.WaitUntilAppIsRunning(id, appRunningTimeout)
	marker := newVTPMMarker(evetestT)
	writeGuestTPMMarker(t, device, id, marker)
	expectDevicePath(t, device, fmt.Sprintf("%s/%s.encrypted", vtpmStateRoot, id), true)
	expectDevicePath(t, device, vtpmProtectedMarkerPath(id), false)
	evetest.Checkpoint("vtpm-legacy-key-active")

	device.RebootApplication(id, true, appRunningTimeout)
	expectGuestTPMMarker(t, device, id, marker)
	evetest.Checkpoint("vtpm-legacy-key-reloaded")
}
