// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"strings"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// zboot runs inside the pillar container: it is not on the PATH an ssh to the
// device lands on.
const zbootCmd = "eve exec pillar zboot "

// bootPartitions returns the partition the device is running and the other one.
func bootPartitions(t Gomega, device *evetest.EdgeDevice) (current, other string) {
	out, err := runEVE(device, zbootCmd+"curpart")
	t.Expect(err).NotTo(HaveOccurred(), "reading the current partition failed")
	current = strings.TrimSpace(out)
	t.Expect(current).To(BeElementOf("IMGA", "IMGB"),
		"unexpected current partition %q", current)
	other = "IMGB"
	if current == "IMGB" {
		other = "IMGA"
	}
	return current, other
}

// bootOtherPartition boots whatever is installed in the partition the device is
// not running, by staging it the way baseosmgr stages an update and rebooting.
//
// Staged directly rather than by re-pushing the update that installed it:
// baseosmgr will not retry a baseos it has marked failed without a retry counter
// the framework cannot bump, so the same push booted the other partition on one
// run and did nothing on the next. This changes only how the boot is initiated;
// what then runs on it is reached exactly as an update would reach it.
func bootOtherPartition(t Gomega, device *evetest.EdgeDevice) {
	current, other := bootPartitions(t, device)
	evetest.Logger().Infof("running on %s; staging %s and rebooting into it",
		current, other)
	out, err := runEVE(device, zbootCmd+"set_partstate "+other+" updating")
	t.Expect(err).NotTo(HaveOccurred(), "staging %s failed:\n%s", other, out)
	device.SoftReboot(false)
}

// commitCurrentPartition marks the partition the device is running as active and
// reboots, which is what baseosmgr does once an update passes its test period
// (MarkCurrentPartitionStateActive on TestComplete). The reboot is required
// rather than incidental: vaultmgr reads the partition state at startup.
func commitCurrentPartition(t Gomega, device *evetest.EdgeDevice) {
	current, other := bootPartitions(t, device)
	out, err := runEVE(device, zbootCmd+"set_partstate "+current+" active")
	t.Expect(err).NotTo(HaveOccurred(), "committing %s failed:\n%s", current, out)
	// Marking the other partition unused is the second half of EVE's own commit
	// (zboot.MarkCurrentPartitionStateActive). Without it both partitions read
	// active and the next boot can land on the wrong one -- which for a
	// conversion means a boot back into EVE-kvm, where none of the code under
	// test runs at all.
	out, err = runEVE(device, zbootCmd+"set_partstate "+other+" unused")
	t.Expect(err).NotTo(HaveOccurred(), "marking %s unused failed:\n%s", other, out)

	states, err := runEVE(device,
		`eve exec pillar sh -c 'echo cur=$(zboot curpart) `+
			current+`=$(zboot partstate `+current+`) `+
			other+`=$(zboot partstate `+other+`)'`)
	t.Expect(err).NotTo(HaveOccurred())
	t.Expect(states).To(ContainSubstring(current+"=active"),
		"%s did not take the commit: %s", current, strings.TrimSpace(states))
	t.Expect(states).To(ContainSubstring(other+"=unused"),
		"%s was not marked unused, so the next boot may not be %s: %s",
		other, current, strings.TrimSpace(states))
	evetest.Logger().Infof("committed %s; rebooting so vaultmgr reads the new state", current)
	device.SoftReboot(false)
}
