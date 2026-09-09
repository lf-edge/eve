// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// How vaultmgr reports the vault was unlocked, as the VaultStatus.UnlockMethod
// values appear on the wire.
const (
	unlockLocal      = "local"
	unlockController = "controller"
	unlockNoTPM      = "no-tpm"
)

// settleVaultLocal reboots until the vault unlocks from its own TPM seal rather
// than from the controller's key.
//
// A new rootfs moves the PCRs the seal is bound to, so the first boot after an
// upgrade necessarily falls back to the controller key and re-seals against the
// new measurements; only the boot after that can unlock locally. The conversion
// has to start from the settled state, because a local unlock on the last
// pre-conversion boot is exactly what the seal assertion afterwards looks for.
func settleVaultLocal(t Gomega, device *evetest.EdgeDevice) {
	log := evetest.Logger()
	const maxReboots = 4
	for attempt := 1; attempt <= maxReboots; attempt++ {
		var decided string
		t.Eventually(func() string {
			decided = readVaultUnlockMethod(device)
			return decided
		}, 12*time.Minute, 10*time.Second).ShouldNot(BeEmpty(),
			"the vault never reported an unlock method")

		switch decided {
		case unlockLocal:
			log.Infof("vault settled on a local TPM unlock")
			return
		case unlockNoTPM:
			t.Expect(decided).NotTo(Equal(unlockNoTPM),
				"the vault reports no TPM; this test needs one")
			return
		default:
			log.Infof("vault unlocked from the controller key (attempt %d/%d); rebooting to re-seal",
				attempt, maxReboots)
			device.RequestReboot(true)
		}
	}
	t.Expect(false).To(BeTrue(),
		"the vault did not settle on a local unlock within %d reboots", maxReboots)
}

// readVaultUnlockMethod returns how the vault was unlocked, or "" while
// vaultmgr has not published yet.
func readVaultUnlockMethod(device *evetest.EdgeDevice) string {
	out, _, err := device.RunShellScript(
		`eve exec pillar sh -c "cat /run/vaultmgr/VaultStatus/*.json 2>/dev/null"`,
		eveShellTimeout, 0)
	if err != nil {
		return ""
	}
	switch {
	case strings.Contains(out, `"UnlockMethod":1`):
		return unlockLocal
	case strings.Contains(out, `"UnlockMethod":2`):
		return unlockController
	case strings.Contains(out, `"UnlockMethod":3`):
		return unlockNoTPM
	}
	return ""
}

// newlogUnlockScan pulls every per-boot version marker and vault-unlock line out
// of the device's own log archive.
//
// It reads the whole of /persist/newlog, not just collect/: newlogd rotates a
// stream out of collect/ after about five minutes or 550 KB, so by the time the
// conversion has finished the boots this needs are in the gzipped queues. One
// zcat per file because busybox find has no `-exec ... +`, and -f so the same
// command handles the plaintext chunks in collect/.
const newlogUnlockScan = `eve exec pillar sh -c "find /persist/newlog -name \"dev.log.*\" -exec zcat -f {} \; 2>/dev/null | grep -aE \"EVE version: |unlocked: method=|local TPM unseal FAILED\""`

// newlogScanTimeout bounds that scan: it decompresses the whole archive, which
// is thousands of files on a device that has been up for a while.
const newlogScanTimeout = 3 * time.Minute

// vaultUnlock is one unlock event, attributed to the EVE version that was
// running when it happened.
type vaultUnlock struct {
	version string
	method  string
	// pcrs are the PCRs that failed to match, for a controller-key unlock or a
	// failed unseal; empty for a local one.
	pcrs []string
}

// assertSealSurvivedRepartition asserts the boot-disk repartition did not break
// the TPM seal, judged after the fact from the device's own logs.
//
// It has to be judged this way. The live window in which the post-conversion
// unlock is readable is a minute or two, and racing it makes the test flaky;
// /persist survives the repartition, so the record of every boot is still there
// afterwards. Two independent gates:
//
//  1. The last boot on the conversion-capable kvm image must have unsealed
//     locally. That is the boot after the repartition and before EVE-K, on which
//     only PCR5 changed -- and PCR5 is excluded from the seal precisely so that
//     a repartition does not invalidate it. Keyed on that exact version rather
//     than "any kvm boot", so a future baseline that also unlocks locally cannot
//     satisfy it by accident.
//  2. No controller-key or failed unseal anywhere lists PCR5 among its
//     mismatches. A PCR5-driven re-seal means the repartition did break the
//     seal, whatever gate 1 saw.
//
// The EVE-K boot unlocking from the controller key is expected and not a
// failure: a new rootfs moves PCRs 8, 9 and 13.
func assertSealSurvivedRepartition(t Gomega, device *evetest.EdgeDevice, kvmVersion string) {
	log := evetest.Logger()
	var raw string
	t.Eventually(func(g Gomega) {
		var err error
		raw, err = runEVEWithTimeout(device, newlogUnlockScan, newlogScanTimeout)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(raw).NotTo(BeEmpty(), "found no unlock records in /persist/newlog")
	}, 5*time.Minute, 15*time.Second).Should(Succeed())

	unlocks := parseVaultUnlocks(raw)
	for _, u := range unlocks {
		log.Infof("unlock: version=%s method=%s pcrs=%v", u.version, u.method, u.pcrs)
	}
	t.Expect(unlocks).NotTo(BeEmpty(),
		"no vault unlock was recorded in /persist/newlog, so the seal cannot be judged")

	var pcr5Reseals []vaultUnlock
	var onKVM []vaultUnlock
	for _, u := range unlocks {
		for _, p := range u.pcrs {
			if p == "5" {
				pcr5Reseals = append(pcr5Reseals, u)
				break
			}
		}
		if u.version == kvmVersion {
			onKVM = append(onKVM, u)
		}
	}

	t.Expect(pcr5Reseals).To(BeEmpty(),
		"PCR5 appears in a re-seal or failed unseal, so the repartition broke the TPM seal: %v",
		pcr5Reseals)
	t.Expect(onKVM).NotTo(BeEmpty(),
		"no vault unlock was recorded on %s, so the post-repartition boot cannot be judged",
		kvmVersion)
	t.Expect(onKVM[len(onKVM)-1].method).To(Equal(unlockLocal),
		"the last boot on %s did not unseal locally, so the repartition cost the seal: %v",
		kvmVersion, onKVM[len(onKVM)-1])
}

var (
	// logSecondsRE and logNanosRE order the records; newlog lines carry the
	// timestamp as a structured field rather than in message order.
	logSecondsRE = regexp.MustCompile(`"seconds":(\d+)`)
	logNanosRE   = regexp.MustCompile(`"nanos":(\d+)`)
	// eveVersionRE reads the per-boot version marker.
	eveVersionRE = regexp.MustCompile(`EVE version: ([0-9][A-Za-z0-9._+-]*)`)
	// mismatchPCRsRE reads the PCR list off a controller-key or failed unseal.
	mismatchPCRsRE = regexp.MustCompile(`mismatching ?PCRs=\[([0-9 ]*)\]`)
)

// parseVaultUnlocks turns the scanned log lines into unlock events, each
// attributed to the version marker that preceded it.
//
// The version marker has to come from pillar.out: baseosmgr also logs a
// "to EVE version X" line naming the version being installed, which is a
// different thing entirely and would attribute an unlock to the image the
// device was moving to rather than the one it was running.
func parseVaultUnlocks(raw string) []vaultUnlock {
	type event struct {
		seconds, nanos int64
		kind           string
		value          string
		pcrs           []string
	}
	var events []event
	for _, line := range strings.Split(raw, "\n") {
		var secs, nanos int64
		if m := logSecondsRE.FindStringSubmatch(line); m != nil {
			secs, _ = strconv.ParseInt(m[1], 10, 64)
		}
		if m := logNanosRE.FindStringSubmatch(line); m != nil {
			nanos, _ = strconv.ParseInt(m[1], 10, 64)
		}
		switch {
		case strings.Contains(line, "pillar.out") && strings.Contains(line, "EVE version:"):
			if m := eveVersionRE.FindStringSubmatch(line); m != nil {
				events = append(events, event{secs, nanos, "version", m[1], nil})
			}
		case strings.Contains(line, "unlocked: method=tpm-local-sealed"):
			events = append(events, event{secs, nanos, "unlock", unlockLocal, nil})
		case strings.Contains(line, "method=controller-key"):
			events = append(events, event{secs, nanos, "unlock", unlockController, mismatchedPCRs(line)})
		case strings.Contains(line, "unseal FAILED"):
			events = append(events, event{secs, nanos, "unlock", "failed", mismatchedPCRs(line)})
		}
	}
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].seconds != events[j].seconds {
			return events[i].seconds < events[j].seconds
		}
		return events[i].nanos < events[j].nanos
	})

	var unlocks []vaultUnlock
	current := ""
	for _, e := range events {
		if e.kind == "version" {
			current = e.value
			continue
		}
		unlocks = append(unlocks, vaultUnlock{version: current, method: e.value, pcrs: e.pcrs})
	}
	return unlocks
}

// mismatchedPCRs reads the PCR list off an unlock line, or nil when it has none.
func mismatchedPCRs(line string) []string {
	m := mismatchPCRsRE.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	return strings.Fields(m[1])
}
