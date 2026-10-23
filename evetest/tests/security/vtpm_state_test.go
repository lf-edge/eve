// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// TestAppVTPMIdentitySurvivesReboots writes a value into guest TPM NV, then
// checks it after an app reboot and a device reboot. This detects a successful
// app boot with a silently reset vTPM. The SingleEthWithDHCP network provides
// controller and app SSH access; the test uses the KVM backend with a host TPM.
func TestAppVTPMIdentitySurvivesReboots(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	device, config, niUUID := setupVTPMDevice(evetestT, true)
	id := addVTPMTestApp(config, niUUID, "vtpm-identity", 2222)
	device.ApplyConfig(config, true, true)
	device.WaitUntilAppIsRunning(id, appRunningTimeout)
	waitForVTPMGuest(t, device, id)
	expectOneSwtpmProcess(t, device, id)
	evetest.Checkpoint("vtpm-identity-app-running")

	marker := newVTPMMarker(evetestT)
	writeGuestTPMMarker(t, device, id, marker)
	expectDevicePath(t, device, vtpmProtectedMarkerPath(id), true)
	evetest.Checkpoint("vtpm-identity-written")

	device.RebootApplication(id, true, appRunningTimeout)
	expectGuestTPMMarker(t, device, id, marker)
	expectOneSwtpmProcess(t, device, id)
	evetest.Checkpoint("vtpm-identity-after-app-reboot")

	device.SoftReboot(true)
	device.WaitUntilAppIsRunning(id, appRunningTimeout)
	expectGuestTPMMarker(t, device, id, marker)
	expectOneSwtpmProcess(t, device, id)
	expectDevicePath(t, device, vtpmProtectedMarkerPath(id), true)
	evetest.Checkpoint("vtpm-identity-after-device-reboot")
}

// TestAppVTPMCorruptStateRetention seeds an invalid unmarked SWTPM state
// before the app's first launch. vtpmd must preserve its bytes, start a fresh
// usable TPM, and keep only the ten newest corrupt snapshots for this UUID.
// This is a device-level fault injection test of the reset path; the app has
// never held a TPM identity, so resetting it is safe in this scenario.
func TestAppVTPMCorruptStateRetention(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	device, config, niUUID := setupVTPMDevice(evetestT, true)
	id := addVTPMTestApp(config, niUUID, "vtpm-corrupt-retention", 2222)
	stateDir := vtpmStatePath(id)
	defer func() {
		_, _, _ = device.RunShellScript(fmt.Sprintf("rm -rf %q.corrupt-*", stateDir),
			appSSHTimeout, 0)
	}()
	seed := fmt.Sprintf(`set -eu
test -d %q
mkdir %q
chmod 700 %q
for n in 1 2 3 4 5 6 7 8 9 10 11; do
  mkdir %q.corrupt-$n
  printf 'old-%%s' "$n" > %q.corrupt-$n/evetest-marker
done
printf 'evetest-corrupt-primary' > %q/tpm2-00.permall
printf 'evetest-corrupt-backup' > %q/tpm2-00.permall.bak
chown -R 101:101 %q
chown -R 101:101 %q.corrupt-*
chmod 600 %q/tpm2-00.permall %q/tpm2-00.permall.bak`,
		vtpmStateRoot, stateDir, stateDir, stateDir, stateDir, stateDir,
		stateDir, stateDir, stateDir, stateDir, stateDir)
	_, stderr, err := device.RunShellScript(seed, time.Minute, 0)
	t.Expect(err).ToNot(HaveOccurred(), "seed corrupt vTPM state: %s", stderr)
	evetest.Checkpoint("vtpm-corrupt-state-seeded")

	device.ApplyConfig(config, true, true)
	device.WaitUntilAppIsRunning(id, appRunningTimeout)
	waitForVTPMGuest(t, device, id)
	expectDevicePath(t, device, vtpmProtectedMarkerPath(id), true)
	entries, err := device.ListDirEntries(vtpmStateRoot)
	t.Expect(err).ToNot(HaveOccurred())
	prefix := fmt.Sprintf("tpm-state-%s.corrupt-", id)
	var saved []string
	for _, entry := range entries {
		if strings.HasPrefix(entry, prefix) {
			saved = append(saved, entry)
		}
	}
	t.Expect(saved).To(HaveLen(10), "corrupt-state retention exceeded its limit")
	for _, n := range []int{1, 2} {
		t.Expect(saved).ToNot(ContainElement(prefix+strconv.Itoa(n)),
			"oldest corrupt state %d was not pruned", n)
	}
	for n := 3; n <= 11; n++ {
		t.Expect(saved).To(ContainElement(prefix+strconv.Itoa(n)),
			"newer corrupt state %d was incorrectly removed", n)
	}
	var newest string
	for _, entry := range saved {
		if stamp, parseErr := strconv.ParseInt(strings.TrimPrefix(entry, prefix), 10, 64); parseErr == nil && stamp > 11 {
			newest = entry
		}
	}
	t.Expect(newest).ToNot(BeEmpty(), "new corrupt state was not preserved")
	primary, err := device.ReadFile(vtpmStateRoot + "/" + newest + "/tpm2-00.permall")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(string(primary)).To(Equal("evetest-corrupt-primary"))
	backup, err := device.ReadFile(vtpmStateRoot + "/" + newest + "/tpm2-00.permall.bak")
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(string(backup)).To(Equal("evetest-corrupt-backup"))

	marker := newVTPMMarker(evetestT)
	writeGuestTPMMarker(t, device, id, marker)
	expectGuestTPMMarker(t, device, id, marker)
	evetest.Checkpoint("vtpm-corrupt-state-retained-and-reset")
}

// TestAppVTPMBackupRecoversPrimaryCorruption verifies swtpm's backup can
// recover the same guest TPM identity when the primary encrypted state is bad.
// The app is deactivated while the state file is changed, then reactivated.
func TestAppVTPMBackupRecoversPrimaryCorruption(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	device, config, niUUID := setupVTPMDevice(evetestT, true)
	id := addVTPMTestApp(config, niUUID, "vtpm-backup", 2222)
	device.ApplyConfig(config, true, true)
	device.WaitUntilAppIsRunning(id, appRunningTimeout)
	marker := newVTPMMarker(evetestT)
	writeGuestTPMMarker(t, device, id, marker)
	device.RebootApplication(id, true, appRunningTimeout)
	expectGuestTPMMarker(t, device, id, marker)

	device.DeactivateApplication(id, true, appRunningTimeout)
	expectSwtpmProcessCount(t, device, id, 0)
	stateDir := vtpmStatePath(id)
	primary := stateDir + "/tpm2-00.permall"
	backup := primary + ".bak"
	expectDevicePath(t, device, backup, true)
	original, err := device.ReadFile(primary)
	t.Expect(err).ToNot(HaveOccurred())
	// Keep the original mode and owner: this must exercise decryption, not a
	// permission error. Save a copy so a failed assertion can restore the app.
	recovered := false
	defer func() {
		if !recovered {
			device.DeactivateApplication(id, true, appRunningTimeout)
			_, _, _ = device.RunShellScript(fmt.Sprintf("if [ -f %q ]; then cp -p %q %q; fi",
				primary+".evetest", primary+".evetest", primary),
				appSSHTimeout, 0)
		}
		_, _, _ = device.RunShellScript(fmt.Sprintf("rm -f %q", primary+".evetest"), appSSHTimeout, 0)
	}()
	inject := fmt.Sprintf("set -eu; cp -p %q %q; printf 'evetest-corrupt-primary' > %q", primary, primary+".evetest", primary)
	_, stderr, err := device.RunShellScript(inject, appSSHTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "inject primary corruption: %s", stderr)
	corrupt, err := device.ReadFile(primary)
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(string(corrupt)).To(Equal("evetest-corrupt-primary"))
	t.Expect(corrupt).ToNot(Equal(original))
	evetest.Checkpoint("vtpm-primary-corrupted")

	device.ActivateApplication(id, true, appRunningTimeout)
	expectGuestTPMMarker(t, device, id, marker)
	expectOneSwtpmProcess(t, device, id)
	recovered = true
	evetest.Checkpoint("vtpm-backup-recovered")
}

// TestAppVTPMProtectedFailurePreservesState corrupts both encrypted copies
// after the one-way PCR marker has been written. The guest may still boot, but
// it must have no vTPM; vtpmd must preserve the bytes and must not reset TPM
// identity or try the legacy key. Restoring the copies must restore the NV value.
func TestAppVTPMProtectedFailurePreservesState(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	device, config, niUUID := setupVTPMDevice(evetestT, true)
	id := addVTPMTestApp(config, niUUID, "vtpm-protected-failure", 2222)
	device.ApplyConfig(config, true, true)
	device.WaitUntilAppIsRunning(id, appRunningTimeout)
	marker := newVTPMMarker(evetestT)
	writeGuestTPMMarker(t, device, id, marker)
	device.RebootApplication(id, true, appRunningTimeout)
	expectGuestTPMMarker(t, device, id, marker)
	expectDevicePath(t, device, vtpmProtectedMarkerPath(id), true)

	device.DeactivateApplication(id, true, appRunningTimeout)
	expectSwtpmProcessCount(t, device, id, 0)
	stateDir := vtpmStatePath(id)
	primary := stateDir + "/tpm2-00.permall"
	backup := primary + ".bak"
	expectDevicePath(t, device, backup, true)
	const corruptText = "evetest-invalid-encrypted-state"
	restored := false
	defer func() {
		if restored {
			return
		}
		// Leave the device with its original TPM identity even if an assertion
		// fails. The test app has its own UUID and no other app uses this state.
		device.DeactivateApplication(id, true, appRunningTimeout)
		_, _, _ = device.RunShellScript(fmt.Sprintf(`for f in %q %q; do
  if [ -f "$f.evetest" ]; then cp -p "$f.evetest" "$f"; rm -f "$f.evetest"; fi
done`, primary, backup), appSSHTimeout, 0)
	}()
	inject := fmt.Sprintf(`set -eu
for f in %q %q; do
  cp -p "$f" "$f.evetest"
  printf '%s' > "$f"
done`, primary, backup, corruptText)
	_, stderr, err := device.RunShellScript(inject, appSSHTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "inject bad protected state: %s", stderr)
	evetest.Checkpoint("vtpm-protected-state-corrupted")

	device.ActivateApplication(id, true, appRunningTimeout)
	t.Eventually(func(g Gomega) {
		_, _, sshErr := device.RunShellScriptInsideApp(id, appAuth, "echo ready", appSSHTimeout, 0)
		g.Expect(sshErr).ToNot(HaveOccurred())
	}, vtpmGuestWaitTime, pollingInterval).Should(Succeed())
	_, _, err = device.RunShellScriptInsideApp(id, appAuth,
		"test ! -c /dev/tpmrm0 && test ! -c /dev/tpm0", appSSHTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "guest received a new vTPM after protected state failed")
	for _, file := range []string{primary, backup} {
		data, readErr := device.ReadFile(file)
		t.Expect(readErr).ToNot(HaveOccurred())
		t.Expect(strings.TrimSpace(string(data))).To(Equal(corruptText),
			"vtpmd changed protected state after failed decryption")
	}
	expectDevicePath(t, device, vtpmProtectedMarkerPath(id), true)
	evetest.Checkpoint("vtpm-protected-state-preserved")

	device.DeactivateApplication(id, true, appRunningTimeout)
	expectSwtpmProcessCount(t, device, id, 0)
	restore := fmt.Sprintf(`set -eu
for f in %q %q; do cp -p "$f.evetest" "$f"; rm -f "$f.evetest"; done`, primary, backup)
	_, stderr, err = device.RunShellScript(restore, appSSHTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "restore protected state: %s", stderr)
	restored = true
	device.ActivateApplication(id, true, appRunningTimeout)
	expectGuestTPMMarker(t, device, id, marker)
	evetest.Checkpoint("vtpm-protected-state-restored")
}

// TestAppVTPMIsolation gives two apps different TPM NV values, reboots one,
// then deletes it. The surviving app must keep its own value. This exercises
// concurrent vTPM launches and per-UUID teardown on one KVM device.
func TestAppVTPMIsolation(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	device, config, niUUID := setupVTPMDevice(evetestT, true)
	first := addVTPMTestApp(config, niUUID, "vtpm-isolation-a", 2222)
	second := addVTPMTestApp(config, niUUID, "vtpm-isolation-b", 2223)
	device.ApplyConfig(config, true, true)
	device.WaitUntilAppIsRunning(first, appRunningTimeout)
	device.WaitUntilAppIsRunning(second, appRunningTimeout)
	expectOneSwtpmProcess(t, device, first)
	expectOneSwtpmProcess(t, device, second)
	firstMarker, secondMarker := newVTPMMarker(evetestT), newVTPMMarker(evetestT)
	writeGuestTPMMarker(t, device, first, firstMarker)
	writeGuestTPMMarker(t, device, second, secondMarker)
	expectGuestTPMMarker(t, device, first, firstMarker)
	expectGuestTPMMarker(t, device, second, secondMarker)
	evetest.Checkpoint("vtpm-two-apps-running")

	device.RebootApplication(first, true, appRunningTimeout)
	expectGuestTPMMarker(t, device, first, firstMarker)
	expectGuestTPMMarker(t, device, second, secondMarker)
	config.DeleteApplication(first)
	device.ApplyConfig(config, true, true)
	expectGuestTPMMarker(t, device, second, secondMarker)
	expectDevicePath(t, device, vtpmStatePath(first), false)
	expectDevicePath(t, device, fmt.Sprintf("/run/swtpm/%s.ctrl.sock", first), false)
	expectDevicePath(t, device, fmt.Sprintf("/run/swtpm/%s.pid", first), false)
	expectDevicePath(t, device, vtpmStatePath(second), true)
	t.Eventually(func(g Gomega) {
		out, _, err := device.RunShellScript(fmt.Sprintf(swtpmCheckScriptFmt, first.String()),
			appSSHTimeout, 0)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(out).To(ContainSubstring("SWTPM_OWNER=none"), "purged app left a swtpm process")
	}, 2*time.Minute, pollingInterval).Should(Succeed())
	evetest.Checkpoint("vtpm-first-app-purged")
}
