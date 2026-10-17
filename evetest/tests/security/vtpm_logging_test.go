// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"fmt"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// TestAppVTPMLogForwardingAndRotation verifies that an active app gets a
// nonempty swtpm log and that sustained FIFO traffic rotates it without
// exceeding three compressed backups or the active log's size bound. The
// SingleEthWithDHCP model supplies app SSH for the real TPM command; host
// access supplies the extra log volume without thousands of guest commands.
func TestAppVTPMLogForwardingAndRotation(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	device, config, niUUID := setupVTPMDevice(evetestT, true)
	id := addVTPMTestApp(config, niUUID, "vtpm-log", 2222)
	device.ApplyConfig(config, true, true)
	device.WaitUntilAppIsRunning(id, appRunningTimeout)
	waitForVTPMGuest(t, device, id)
	_, stderr, err := device.RunShellScriptInsideApp(id, appAuth,
		"tpm2_getrandom --hex 8", appSSHTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "use guest TPM: %s", stderr)
	logPath := vtpmStatePath(id) + "/swtpm.log"
	fifoPath := fmt.Sprintf("/run/swtpm/%s-swtpm.log.fifo", id)
	expectDevicePath(t, device, logPath, true)
	expectDevicePath(t, device, fifoPath, true)
	t.Eventually(func(g Gomega) {
		out, _, statErr := device.RunShellScript(fmt.Sprintf("stat -c %%s %q", logPath),
			appSSHTimeout, 0)
		g.Expect(statErr).ToNot(HaveOccurred())
		g.Expect(out).To(MatchRegexp(`^[1-9][0-9]*\s*$`), "swtpm log stayed empty")
	}, time.Minute, pollingInterval).Should(Succeed())
	evetest.Checkpoint("vtpm-log-created")

	// Exercise the forwarder with more than four 10 MiB windows. Zero bytes
	// compress quickly, so this tests the rotation mechanism without filling
	// the test device with large backups or relying on log message wording.
	_, stderr, err = device.RunShellScript(
		fmt.Sprintf("dd if=/dev/zero of=%q bs=1048576 count=45", fifoPath),
		2*time.Minute, 0)
	t.Expect(err).ToNot(HaveOccurred(), "write vTPM log FIFO: %s", stderr)
	evetest.Checkpoint("vtpm-log-traffic-written")

	t.Eventually(func(g Gomega) {
		for i := 1; i <= vtpmLogBackupMax; i++ {
			present, pathErr := device.PathExists(fmt.Sprintf("%s.%d.gz", logPath, i))
			g.Expect(pathErr).ToNot(HaveOccurred())
			g.Expect(present).To(BeTrue(), "missing rotated swtpm log %d", i)
		}
	}, 2*time.Minute, pollingInterval).Should(Succeed())
	tooMany, err := device.PathExists(fmt.Sprintf("%s.%d.gz", logPath, vtpmLogBackupMax+1))
	t.Expect(err).ToNot(HaveOccurred())
	t.Expect(tooMany).To(BeFalse(), "swtpm log backups exceeded the configured cap")
	out, stderr, err := device.RunShellScript(fmt.Sprintf("stat -c %%s %q", logPath),
		appSSHTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "stat active swtpm log: %s", stderr)
	var size int64
	_, err = fmt.Sscan(out, &size)
	t.Expect(err).ToNot(HaveOccurred(), "parse active swtpm log size: %q", out)
	t.Expect(size).To(BeNumerically("<=", vtpmLogSizeLimit+65536),
		"active swtpm log grew past its rotation bound")
	evetest.Checkpoint("vtpm-log-rotation-bounded")
}
