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

// The two-disk shape: a 32 GiB boot disk and a 32 GiB extra disk, so the pair
// totals the same 64 GiB as the single-disk tests.
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
// extra disk, leaving a partition labeled P3 on the extra disk and none on the
// boot disk. EVE locates /persist by partition label across every disk, so it
// adopts the new one and formats it on the next boot as filesystem, which must
// be what the device was set up with.
//
// The disk edits need the device powered off, and the caller must have declared
// RequireCapabilities{CAPABILITY_EDIT_DEVICE_DISK}.
func movePersistToExtraDisk(t Gomega, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig, filesystem evetest.Filesystem) {
	log := evetest.Logger()

	t.Expect(persistDiskPartition(t, device, filesystem)).To(HavePrefix(twodiskBootDiskName),
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
	stopProbe := probeStalledConfigFetch(device)
	device.ApplyConfig(devConfig, true, true)
	stopProbe()

	part := persistDiskPartition(t, device, filesystem)
	log.Infof("/persist is now on %s", part)
	t.Expect(part).To(HavePrefix(twodiskExtraDiskName),
		"/persist did not move to the extra disk")
	assertPersistType(t, device, persistTypeName(filesystem))
}

// wholeDiskPoolScript creates the persist pool on the whole extra disk the way
// the installer lays out a multi-disk ZFS install (pkg/installer/install
// prepare_mounts_and_zfs_pool, non-clustered), then exports it. The pool is
// created under a temporary altroot, which is not stored in the pool, so its
// datasets mount there instead of over the live /persist. $1 is the disk.
const wholeDiskPoolScript = `set -e
dev=$1
alt=$(mktemp -d)
zpool labelclear -f "$dev" 2>/dev/null || true
zpool create -f -R "$alt" -m none -o feature@encryption=enabled -O atime=off -O overlay=on persist "$dev"
resv=$(zfs get -o value -Hp available persist | awk '{ print int(($1/1024/1024)/5) }')
zfs create -o refreservation="${resv}m" persist/reserved
zfs set mountpoint=/persist persist
zfs set primarycache=metadata persist
zfs create -o mountpoint=/persist/containerd/io.containerd.snapshotter.v1.zfs persist/snapshots
zpool export persist
rmdir "$alt" 2>/dev/null || true
echo POOL_READY
`

// buildWholeDiskPersistPool moves /persist onto a ZFS pool spanning the whole
// extra disk, leaving no partition labeled P3 on any disk. storage-init then
// finds /persist by importing the pool by name rather than by partition label,
// and on that path a failed import leaves /persist unmounted instead of
// recreating it.
//
// The pool is created from inside the running EVE, so its feature flags are
// ones EVE's zfs imports, which is why the device must start on ext4: a ZFS
// /persist would already hold the pool name. The boot disk's P3 is deleted with
// the device powered off, and the caller must have declared
// RequireCapabilities{CAPABILITY_EDIT_DEVICE_DISK}.
func buildWholeDiskPersistPool(t Gomega, device *evetest.EdgeDevice,
	devConfig *evetest.EdgeDeviceConfig) {
	log := evetest.Logger()

	t.Expect(persistDiskPartition(t, device, evetest.FilesystemEXT4)).To(
		HavePrefix(twodiskBootDiskName),
		"/persist did not start on the boot disk, so moving it proves nothing")

	log.Infof("creating the persist pool on the whole of /dev/%s", twodiskExtraDiskName)
	out, err := runEVEScript(device, wholeDiskPoolScript, 2*time.Minute,
		"/dev/"+twodiskExtraDiskName)
	t.Expect(err).NotTo(HaveOccurred(), "building the pool failed:\n%s", out)
	t.Expect(out).To(ContainSubstring("POOL_READY"), "building the pool failed:\n%s", out)

	log.Infof("deleting the boot disk's P3, with the device powered off")
	device.SyncDisks()
	device.PowerOff()
	device.DeletePartition(twodiskPersistPartLabel)
	// See movePersistToExtraDisk for why the power cycle is not waited on as a
	// reboot and why a config round trip follows.
	device.PowerOn(false)
	waitDeviceResponds(t, device)
	stopProbe := probeStalledConfigFetch(device)
	device.ApplyConfig(devConfig, true, true)
	stopProbe()

	part := persistDiskPartition(t, device, evetest.FilesystemZFS)
	log.Infof("/persist is now on %s", part)
	t.Expect(part).To(HavePrefix(twodiskExtraDiskName),
		"/persist did not move to the extra disk")
	assertPersistType(t, device, "zfs")
	out, err = runEVE(device, "eve exec pillar blkid -t PARTLABEL=P3 -o device || true")
	t.Expect(err).NotTo(HaveOccurred())
	t.Expect(strings.TrimSpace(out)).To(BeEmpty(), "a partition labeled P3 remains")
}

// persistTypeName is how /run/eve.persist_type names filesystem.
func persistTypeName(filesystem evetest.Filesystem) string {
	if filesystem == evetest.FilesystemZFS {
		return "zfs"
	}
	return "ext4"
}

// persistDiskPartition returns the partition /persist lives on, e.g. "vdb1": the
// pool's vdev on ZFS, the mount source otherwise.
func persistDiskPartition(t Gomega, device *evetest.EdgeDevice,
	filesystem evetest.Filesystem) string {
	if filesystem == evetest.FilesystemZFS {
		return persistPoolVdev(t, device)
	}
	var part string
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, `eve exec pillar findmnt -no SOURCE /persist`)
		g.Expect(err).NotTo(HaveOccurred(), "findmnt failed:\n%s", out)
		part = strings.TrimPrefix(strings.TrimSpace(out), "/dev/")
		g.Expect(part).NotTo(BeEmpty(), "/persist is not mounted")
	}, 5*time.Minute, 10*time.Second).Should(Succeed())
	return part
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
