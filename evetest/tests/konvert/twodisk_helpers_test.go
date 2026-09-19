// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package konvert_test

import (
	"strings"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve/evetest"
)

// The two-disk shape of eden's twodisk-zfs leg (prep-kvm-to-k-topology.sh):
// eve.disk=32768 sizes both the boot disk and the extra disk, so the pair totals
// the same 64 GiB every other leg uses.
const (
	twodiskBootMiB          = 32768
	twodiskExtraDiskBytes   = 32 * evetest.GiB
	twodiskBootDiskName     = "vda"
	twodiskExtraDiskName    = "vdb"
	twodiskPersistPartLabel = "P3"
)

// twodiskParams sizes the boot disk for the two-disk topology, leaving an
// explicitly requested DISK_SIZE_MB alone.
func twodiskParams(p deviceParams) deviceParams {
	if evetest.GetDiskSizeMiBParameterValue() == 0 {
		p.diskMiB = twodiskBootMiB
	}
	return p
}

// movePersistToExtraDisk relocates /persist from the boot disk onto the blank
// extra disk, reproducing eden's twodisk-zfs topology: a partition labelled P3
// on the extra disk and none on the boot disk. EVE locates /persist by partition
// label across every disk, so it adopts the new one and formats it on the next
// boot -- ZFS here, because the device was set up WithFilesystem ZFS.
//
// The disk edits need the device powered off, and the caller must have declared
// RequireCapabilities{CAPABILITY_EDIT_DEVICE_DISK}.
func movePersistToExtraDisk(t Gomega, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig) {
	log := evetest.Logger()

	t.Expect(persistPoolVdev(t, device)).To(HavePrefix(twodiskBootDiskName),
		"/persist did not start on the boot disk, so moving it proves nothing")

	log.Infof("moving /persist onto the extra disk, with the device powered off")
	device.SyncDisks()
	device.PowerOff()
	device.CreatePersistPartition(0)
	device.DeletePartition(twodiskPersistPartLabel)
	// PowerOn does not wait for a reboot signal: nodeagent does not reliably
	// republish LastRebootTime after an external power cycle.
	device.PowerOn(false)
	waitDeviceResponds(t, device)
	// Answering SSH is not enough for the end-of-test reboot audit: nodeagent
	// does not promptly republish LastRebootTime after an external power cycle,
	// so the power cycle stays unobserved until the device reports again. A
	// confirmed config round trip is what makes it report.
	device.ApplyConfig(devConfig, true, true)

	vdev := persistPoolVdev(t, device)
	log.Infof("/persist pool is now on %s", vdev)
	t.Expect(vdev).To(HavePrefix(twodiskExtraDiskName),
		"/persist did not move to the extra disk")
	assertPersistType(t, device, "zfs")
}

// persistPoolVdev returns the single vdev backing the persist pool, e.g. "vdb1".
// `zpool list -vH` prints the pool on its first line and the vdevs under it on
// the following ones, tab-separated and without a header.
func persistPoolVdev(t Gomega, device *evetest.EdgeDevice) string {
	out, err := runEVE(device, "eve exec pillar zpool list -vH persist")
	t.Expect(err).NotTo(HaveOccurred(), "zpool list failed:\n%s", out)

	var vdevs []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] == "persist" {
			continue
		}
		vdevs = append(vdevs, fields[0])
	}
	t.Expect(vdevs).To(HaveLen(1),
		"expected one vdev under the persist pool, got %v:\n%s", vdevs, out)
	return vdevs[0]
}
