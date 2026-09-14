// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// eveShellTimeout bounds a single command run on EVE.
const eveShellTimeout = 30 * time.Second

// runEVE runs a short command on EVE and returns its stdout with empty and
// logger lines dropped, WITHOUT asserting -- so callers can retry, since EVE's
// SSH and pillar are briefly unavailable after a reboot or across the
// conversion.
//
// Output is returned even when the command failed: for a script that reports
// why it is giving up before exiting non-zero, that output is the whole
// explanation, and discarding it leaves a caller with only an exit status.
func runEVE(device *evetest.EdgeDevice, script string) (string, error) {
	return runEVEWithTimeout(device, script, eveShellTimeout)
}

// runEVEWithTimeout is runEVE for a command that legitimately takes longer than
// a status read -- writing gigabytes, or reading the whole log archive.
func runEVEWithTimeout(device *evetest.EdgeDevice, script string,
	timeout time.Duration) (string, error) {
	stdout, _, err := device.RunShellScript(script, timeout, 0)
	var lines []string
	for _, l := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(l) == "" || strings.Contains(l, "level=") {
			continue
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n"), err
}

// readRunningVersion returns the EVE version the device is running, exactly as
// EVE spells it -- which is what the log records this test later reads back are
// keyed on.
func readRunningVersion(t Gomega, device *evetest.EdgeDevice) string {
	var version string
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, "cat /run/eve-release")
		g.Expect(err).NotTo(HaveOccurred())
		version = strings.TrimSpace(out)
		g.Expect(version).NotTo(BeEmpty(), "the device did not report a version")
	}, 3*time.Minute, 10*time.Second).Should(Succeed())
	return version
}
