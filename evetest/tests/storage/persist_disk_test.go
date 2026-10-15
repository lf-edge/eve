// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/lf-edge/eve-api/go/evecommon"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"

	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
)

// TestPersistOnSeparateDisk asserts a device adopts a /persist that lives on a
// disk of its own, rather than on the boot disk where it is normally created.
//
// EVE locates /persist by GPT partition label across every block device, so
// which disk holds it is not fixed at install time. A device can therefore be
// given a dedicated storage disk in the field, and must come up using it. That
// also leaves the boot disk with no /persist to shrink, which is the shape in
// which EVE's in-field repartition has to grow into freed space instead --
// hence the free-tail assertion at the end.
//
// The move is done with the device powered off, because it is a change to the
// partition tables of two disks at once: a running EVE would be holding the
// /persist it is about to lose.
//
// Phases
// ------
//  1. Bring the device up normally and confirm /persist is on the boot disk.
//  2. Power off. Create a P3 partition spanning the extra disk, and delete P3
//     from the boot disk.
//  3. Power on. Assert /persist is now the extra disk's partition, is still
//     ext4, and that the boot disk has a free tail where P3 used to be.
//
// The extra disk's partition is deliberately created empty: EVE formats it on
// first sight, exactly as it would a new disk in the field, so what is being
// tested is EVE's own storage setup rather than a filesystem the harness built.
//
// Test params
// -----------
//   - HYPERVISOR (defaults to KVM).
func TestPersistOnSeparateDisk(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.HypervisorParameter(),
	)
	hypervisor := evetest.GetHypervisorParameterValue()

	const (
		devName = "edge-dev"
		// persistDiskSize is the dedicated /persist disk. Large enough that
		// EVE's own floors are not what a failure is about.
		persistDiskSize = 16 * evetest.GiB
	)

	evetest.Setup(
		evetest.RequireEdgeDevice{
			Name:              devName,
			WithHypervisor:    hypervisor,
			WithFilesystem:    evetest.FilesystemEXT4,
			ExtraDisks:        []uint64{persistDiskSize},
			DeviceReusePolicy: evetest.CreateFromScratchWithLiveImage,
		},
		evetest.RequireNetworkModel{
			NetworkModel: netmodels.SingleEthWithDHCP,
		},
		evetest.RequireCapabilities{
			Capabilities: []api.Capability{
				api.Capability_CAPABILITY_EDIT_DEVICE_DISK,
			},
		},
	)
	device := evetest.GetEdgeDevice(devName)
	log := evetest.Logger()
	evetest.Checkpoint("setup-done")

	devConfig := evetest.NewEdgeDeviceConfig(devName)
	dhcpNet := devConfig.AddNetwork(evetest.DHCPNetworkConfig{
		NetworkType: evecommon.NetworkType_V4Only,
	})
	devConfig.AddNetworkAdapter(evetest.NetworkAdapterConfig{
		LogicalLabel:  "ethernet0",
		PhysicalLabel: "eth0",
		InterfaceName: "eth0",
		NetworkUUID:   dhcpNet,
		Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
	})
	device.ApplyConfig(devConfig, true, true)

	// Phase 1. Asserted rather than assumed: if /persist were already
	// elsewhere, moving it would prove nothing.
	bootDisk := persistDiskName(t, device)
	log.Infof("/persist starts on %s", bootDisk)
	t.Expect(bootDisk).To(HavePrefix(bootDiskDevice),
		"/persist did not start out on the boot disk, so this test cannot show it moving")
	assertPersistType(t, device, "ext4")
	// Measured rather than assumed from the disk's size: what P3 occupies is
	// what deleting it has to give back, and that is the same statement on any
	// boot disk.
	freeBefore, p3Size := bootDiskGPT(t, device)
	log.Infof("the boot disk has %d free bytes, with P3 holding %d", freeBefore, p3Size)
	t.Expect(p3Size).To(BeNumerically(">", 0), "the boot disk has no P3 to move")
	evetest.Checkpoint("persist-on-boot-disk")

	// Phase 2.
	log.Infof("moving /persist onto the extra disk, with the device powered off")
	device.SyncDisks()
	device.PowerOff()
	device.CreatePersistPartition(0)
	device.DeletePartition("P3")
	// PowerOn does not wait for the reboot signal here: nodeagent does not
	// reliably republish LastRebootTime after an external power cycle, so
	// waiting for the device to answer is the signal that holds.
	device.PowerOn(false)
	waitDeviceResponds(t, device)
	evetest.Checkpoint("persist-moved")

	// Phase 3.
	movedDisk := persistDiskName(t, device)
	log.Infof("/persist is now on %s", movedDisk)
	t.Expect(movedDisk).To(HavePrefix(extraDiskDevice),
		"/persist did not move to the extra disk")
	assertPersistType(t, device, "ext4")

	freeAfter, p3After := bootDiskGPT(t, device)
	log.Infof("the boot disk now has %d free bytes, with P3 holding %d", freeAfter, p3After)
	t.Expect(p3After).To(BeZero(), "the boot disk still has a P3 partition")
	t.Expect(freeAfter-freeBefore).To(BeNumerically(">=", p3Size),
		"deleting P3 freed %d bytes on the boot disk, but P3 held %d",
		freeAfter-freeBefore, p3Size)

	// A device whose /persist moved has to still be manageable: /persist holds
	// the identity and the last configuration, so a device that came back with
	// a fresh one would answer SSH exactly like this one and still be unable to
	// be told anything.
	log.Infof("the device must still take configuration from its controller")
	device.ApplyConfig(devConfig, true, true)
	evetest.Checkpoint("persist-on-extra-disk")
}

// The virtio disks the broker attaches, in the order it attaches them: the boot
// disk first, then each extra disk.
const (
	bootDiskDevice  = "/dev/vda"
	extraDiskDevice = "/dev/vdb"
)

// persistDiskName returns the block device /persist is mounted from.
func persistDiskName(t Gomega, device *evetest.EdgeDevice) string {
	var name string
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device,
			`eve exec pillar sh -c "findmnt -no SOURCE /persist"`)
		g.Expect(err).NotTo(HaveOccurred())
		name = strings.TrimSpace(out)
		g.Expect(name).NotTo(BeEmpty(), "the device does not have /persist mounted")
	}, 5*time.Minute, 10*time.Second).Should(Succeed())
	return name
}

// assertPersistType asserts EVE formatted /persist as the expected filesystem.
//
// Checked after the move as well as before: EVE creates the filesystem on the
// partition the harness left empty, and a device that fell back to some other
// type would still have a working /persist while testing something else.
func assertPersistType(t Gomega, device *evetest.EdgeDevice, want string) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, "cat /run/eve.persist_type")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.TrimSpace(out)).To(Equal(want))
	}, 5*time.Minute, 10*time.Second).Should(Succeed())
}

// bootDiskGPT reports the boot disk's unallocated bytes and the size of its P3
// partition, both as the GPT itself describes them. P3 is reported as zero when
// the disk has none.
//
// Asked of the GPT rather than derived from the disk's size: those are
// different questions, and only what the GPT will let a partition occupy
// decides whether EVE can use the space. On this harness they genuinely differ
// -- a device disk grown past its template keeps a partition table describing
// the smaller disk, so the size of the image says nothing about what is usable.
func bootDiskGPT(t Gomega, device *evetest.EdgeDevice) (freeBytes, p3Bytes int64) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, "eve exec pillar sgdisk -p "+bootDiskDevice)
		g.Expect(err).NotTo(HaveOccurred())
		freeBytes = gptFreeBytes(g, out)
		p3Bytes = gptPartitionBytes(g, out, persistPartitionLabel)
	}, 3*time.Minute, 10*time.Second).Should(Succeed())
	return freeBytes, p3Bytes
}

// gptSectorSize is the logical sector size EVE's images are built with.
const gptSectorSize = 512

// persistPartitionLabel is the GPT name EVE gives its /persist partition.
const persistPartitionLabel = "P3"

var (
	// gptFreeSpaceRE reads the unallocated total sgdisk reports for a disk.
	gptFreeSpaceRE = regexp.MustCompile(`Total free space is (\d+) sectors`)
	// gptPartitionRowRE reads a partition row's first and last sector.
	gptPartitionRowRE = regexp.MustCompile(`^\s*\d+\s+(\d+)\s+(\d+)\s`)
)

// gptPartitionBytes returns the size of the named partition in an `sgdisk -p`
// dump, or zero if the disk has no such partition.
func gptPartitionBytes(g Gomega, sgdiskOutput, partitionLabel string) int64 {
	for _, line := range strings.Split(sgdiskOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[len(fields)-1] != partitionLabel {
			continue
		}
		row := gptPartitionRowRE.FindStringSubmatch(line)
		g.Expect(row).NotTo(BeNil(), "could not read the sectors of %q from: %s",
			partitionLabel, line)
		first, err := strconv.ParseInt(row[1], 10, 64)
		g.Expect(err).NotTo(HaveOccurred())
		last, err := strconv.ParseInt(row[2], 10, 64)
		g.Expect(err).NotTo(HaveOccurred())
		return (last - first + 1) * gptSectorSize
	}
	return 0
}

// gptFreeBytes returns the unallocated space in an `sgdisk -p` dump.
func gptFreeBytes(g Gomega, sgdiskOutput string) int64 {
	m := gptFreeSpaceRE.FindStringSubmatch(sgdiskOutput)
	g.Expect(m).NotTo(BeNil(),
		"could not read the free space from:\n%s", sgdiskOutput)
	sectors, err := strconv.ParseInt(m[1], 10, 64)
	g.Expect(err).NotTo(HaveOccurred())
	return sectors * gptSectorSize
}

// runEVE runs a short command on EVE and returns its stdout with empty and
// logger lines dropped, WITHOUT asserting -- so callers can retry, since EVE's
// SSH is briefly unavailable after a reboot.
//
// Output is returned even when the command failed: a script that reports why it
// is giving up before exiting non-zero has put the explanation there.
func runEVE(device *evetest.EdgeDevice, script string) (string, error) {
	stdout, _, err := device.RunShellScript(script, 30*time.Second, 0)
	var lines []string
	for _, l := range strings.Split(stdout, "\n") {
		if strings.TrimSpace(l) == "" || strings.Contains(l, "level=") {
			continue
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n"), err
}

// waitDeviceResponds blocks until EVE answers a trivial command, which is how a
// device that was power-cycled rather than rebooted is confirmed back.
func waitDeviceResponds(t Gomega, device *evetest.EdgeDevice) {
	t.Eventually(func(g Gomega) {
		out, err := runEVE(device, "echo device-is-up")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(out).To(ContainSubstring("device-is-up"))
	}, 15*time.Minute, 15*time.Second).Should(Succeed())
}
