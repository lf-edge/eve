// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"encoding/base64"
	"fmt"
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

// runEVEScript runs a multi-line shell script inside EVE's pillar container,
// passing it through base64 so nothing in it has to survive the ssh and
// `eve exec pillar sh -c` quoting layers -- the same trick the eden scripts use.
// args are appended, so the script reads them as $1, $2, ...
//
// Output is returned even on failure, for the same reason runEVE does it: a
// script that explains why it is giving up before exiting non-zero has said
// everything in that output.
func runEVEScript(device *evetest.EdgeDevice, script string,
	timeout time.Duration, args ...string) (string, error) {
	b64 := base64.StdEncoding.EncodeToString([]byte(script))
	cmd := fmt.Sprintf(
		`eve exec pillar sh -c 'echo %s | base64 -d > /tmp/evetest-frag.sh; `+
			`sh /tmp/evetest-frag.sh %s; rm -f /tmp/evetest-frag.sh'`,
		b64, strings.Join(args, " "))
	out, errOut, err := device.RunShellScript(cmd, timeout, 0)
	if err != nil {
		return out + errOut, err
	}
	return out, nil
}

// writeMarkerFile puts a known string in a file on EVE and reads it back, so a
// later test of whether it is still there is a statement about the file rather
// than about whether the write landed.
func writeMarkerFile(t Gomega, device *evetest.EdgeDevice, path, text string) {
	out, err := runEVE(device,
		`eve exec pillar sh -c 'printf %s `+text+` > `+path+`; sync'`)
	t.Expect(err).NotTo(HaveOccurred(), "writing %s failed:\n%s", path, out)
	assertMarkerFile(t, device, path, text)
}

// assertMarkerFile asserts the marker file still holds what was written to it.
func assertMarkerFile(t Gomega, device *evetest.EdgeDevice, path, text string) {
	out, err := runEVE(device, "eve exec pillar cat "+path)
	t.Expect(err).NotTo(HaveOccurred(), "reading %s failed", path)
	t.Expect(strings.TrimSpace(out)).To(Equal(text),
		"%s does not hold what was written to it", path)
}

// readOptionalFile returns the contents of a file on EVE, or "NONE" when there
// is no such file -- so a caller can assert on its absence as a value rather
// than on an error it would have to classify.
func readOptionalFile(t Gomega, device *evetest.EdgeDevice, path string) string {
	out, err := runEVE(device,
		`eve exec pillar sh -c 'cat `+path+` 2>/dev/null || echo NONE'`)
	t.Expect(err).NotTo(HaveOccurred(), "reading %s failed", path)
	return strings.TrimSpace(out)
}
