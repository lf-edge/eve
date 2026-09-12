// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// fsWipeBytes is how much of a partition is zeroed at each end to make its
// filesystem unrecoverable. Five MiB at the front covers ext4's primary
// superblock and its group descriptor table, which is what stops fsck
// recovering from a backup superblock; the same at the back mirrors the scrub
// EVE's own installer performs.
const fsWipeBytes = int64(5) << 20

// growDisk enlarges a QCOW2 disk to newSizeBytes and leaves the added space
// unallocated past the last partition.
//
// No partition is created or resized, but the partition table is not left
// alone: the backup GPT has to follow the end of the disk, or the added space
// is not usable. See relocateBackupGPT.
//
// The device must be powered off: qemu-img refuses to resize an image a
// running VM holds open, but only when that VM took a lock, so the caller
// checks rather than relying on it.
func growDisk(ctx context.Context, log *logrus.Entry,
	diskPath string, newSizeBytes uint64) error {
	current, err := diskVirtualSizeBytes(ctx, diskPath)
	if err != nil {
		return err
	}
	if int64(newSizeBytes) < current {
		return fmt.Errorf(
			"cannot grow disk %q to %d bytes: it is already %d bytes, and shrinking is not supported",
			diskPath, newSizeBytes, current)
	}
	if int64(newSizeBytes) == current {
		log.Infof("Disk %q is already %d bytes; nothing to grow", diskPath, current)
		return nil
	}
	out, err := exec.CommandContext(ctx, "qemu-img", "resize",
		"-f", "qcow2", diskPath, fmt.Sprintf("%d", newSizeBytes)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img resize of %q to %d bytes failed: %v: %s",
			diskPath, newSizeBytes, err, out)
	}
	if err := relocateBackupGPT(ctx, log, diskPath); err != nil {
		return err
	}
	log.Infof("Grew disk %q from %d to %d bytes (added space left unallocated)",
		diskPath, current, newSizeBytes)
	return nil
}

// relocateBackupGPT moves the backup GPT to the new end of a disk that has just
// been grown, and extends the last-usable-LBA to match.
//
// Growing the image alone is not enough and leaves the disk worse than it
// started: the backup header stays where the old end was, the partition table
// still says the disk ends there, and the added space is not usable. EVE sees
// an inconsistent table -- a device given one has been observed rebooting under
// its own watchdog rather than failing outright, which is a slow way to find
// out.
//
// See editGPT for why this goes through a raw copy.
func relocateBackupGPT(ctx context.Context, log *logrus.Entry, diskPath string) error {
	err := editGPT(ctx, diskPath, func(raw string) error {
		if err := runSgdisk(ctx, "relocate the backup GPT", "-e", raw); err != nil {
			return err
		}
		return runSgdisk(ctx, "verify the partition table", "-v", raw)
	})
	if err != nil {
		return fmt.Errorf("could not relocate the backup GPT of %q: %w", diskPath, err)
	}
	log.Infof("Relocated the backup GPT of %q to the new end of the disk", diskPath)
	return nil
}

// editGPT runs edit against a raw copy of a QCOW2 disk, and writes the result
// back.
//
// sgdisk cannot operate on a QCOW2, so the image is round-tripped through a raw
// copy, as eden does for the same job. That flattens a backing-file overlay
// into a standalone image, which costs space but nothing else: the device boots
// from this path either way. The disk is written back only if edit succeeded,
// so a failed edit leaves the original alone rather than half-rewritten.
func editGPT(ctx context.Context, diskPath string, edit func(raw string) error) error {
	raw := diskPath + ".gptedit.raw"
	defer func() { _ = os.Remove(raw) }()

	out, err := exec.CommandContext(ctx, "qemu-img", "convert",
		"-f", "qcow2", "-O", "raw", diskPath, raw).CombinedOutput()
	if err != nil {
		return fmt.Errorf("export to raw failed: %v: %s", err, out)
	}
	if err := edit(raw); err != nil {
		return err
	}
	out, err = exec.CommandContext(ctx, "qemu-img", "convert",
		"-f", "raw", "-O", "qcow2", raw, diskPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("import from raw failed: %v: %s", err, out)
	}
	return nil
}

// runSgdisk runs one sgdisk command, naming what it was for if it fails.
func runSgdisk(ctx context.Context, what string, args ...string) error {
	out, err := exec.CommandContext(ctx, "sgdisk", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("could not %s: %v: %s", what, err, out)
	}
	return nil
}

// persistPartitionTypeGUID is the GPT type EVE gives its /persist partition,
// and persistPartitionLabel the name it looks it up by. Both have to match what
// EVE writes, or storage-init will not take the partition for its own
// (pkg/storage-init/storage-init.sh, pkg/installer/install).
const (
	persistPartitionTypeGUID = "5f24425a-2dfa-11e8-a270-7b663faccc2c"
	persistPartitionLabel    = "P3"
)

// createPersistPartition writes a fresh GPT on a blank disk with a single
// partition spanning it, typed and named as EVE's /persist partition.
//
// The partition is deliberately left unformatted. storage-init looks P3 up by
// partition label across every block device, finds no filesystem on it, and
// formats it itself on the next boot -- with the encryption feature EVE's vault
// needs. Formatting it here would mean reproducing that by hand, and risking a
// filesystem that differs from EVE's in ways the test never thinks to check.
//
// The device must be powered off.
func createPersistPartition(ctx context.Context, log *logrus.Entry, diskPath string) error {
	err := editGPT(ctx, diskPath, func(raw string) error {
		return runSgdisk(ctx, "create the persist partition",
			"--largest-new=1",
			"--typecode=1:"+persistPartitionTypeGUID,
			"--change-name=1:"+persistPartitionLabel,
			raw)
	})
	if err != nil {
		return fmt.Errorf("could not create a persist partition on %q: %w", diskPath, err)
	}
	log.Infof("Created an empty %s partition spanning %q, for EVE to format",
		persistPartitionLabel, diskPath)
	return nil
}

// deletePartition removes the named partition from a disk's GPT, leaving the
// space it occupied unallocated.
//
// The device must be powered off.
func deletePartition(ctx context.Context, log *logrus.Entry,
	diskPath, partitionLabel string) error {
	err := editGPT(ctx, diskPath, func(raw string) error {
		number, err := gptPartitionNumber(ctx, raw, partitionLabel)
		if err != nil {
			return err
		}
		if err := runSgdisk(ctx, "delete partition "+partitionLabel,
			"-d", strconv.Itoa(number), raw); err != nil {
			return err
		}
		// Asked of the table again rather than inferred from sgdisk's exit
		// status: the whole point of the operation is that it is gone.
		if _, err := gptPartitionNumber(ctx, raw, partitionLabel); err == nil {
			return fmt.Errorf("partition %q is still present after deleting it",
				partitionLabel)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("could not delete partition %q from %q: %w",
			partitionLabel, diskPath, err)
	}
	log.Infof("Deleted partition %q from %q", partitionLabel, diskPath)
	return nil
}

// gptPartitionNumber returns the number of the partition with the given name,
// and an error if the disk has none.
func gptPartitionNumber(ctx context.Context, diskPath, partitionLabel string) (int, error) {
	out, err := exec.CommandContext(ctx, "sgdisk", "-p", diskPath).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("could not read the partition table: %v: %s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[len(fields)-1] != partitionLabel {
			continue
		}
		number, convErr := strconv.Atoi(fields[0])
		if convErr != nil {
			continue
		}
		return number, nil
	}
	return 0, fmt.Errorf("no GPT partition named %q", partitionLabel)
}

// destroyPartitionFilesystem makes the filesystem on the named GPT partition
// unrecoverable, so that EVE reformats it on the next boot. The partition
// table is deliberately left intact: that is the state a real filesystem loss
// leaves behind, and the partition still has to be found afterwards.
//
// The device must be powered off.
func destroyPartitionFilesystem(ctx context.Context, log *logrus.Entry,
	diskPath, partitionLabel string) error {
	head, err := readDiskHead(ctx, diskPath)
	if err != nil {
		return err
	}
	part, err := findGPTPartition(head, partitionLabel)
	if err != nil {
		return fmt.Errorf("cannot destroy the filesystem on partition %q of %q: %w",
			partitionLabel, diskPath, err)
	}

	// A partition too small to hold two separate wipe regions is zeroed whole,
	// which is strictly more destructive and therefore still correct.
	ranges := [][2]int64{}
	if part.Length <= 2*fsWipeBytes {
		ranges = append(ranges, [2]int64{part.Offset, part.Length})
	} else {
		ranges = append(ranges,
			[2]int64{part.Offset, fsWipeBytes},
			[2]int64{part.Offset + part.Length - fsWipeBytes, fsWipeBytes})
	}
	for _, r := range ranges {
		script := fmt.Sprintf("write -z %d %d", r[0], r[1])
		out, err := exec.CommandContext(ctx, "qemu-io",
			"-f", "qcow2", "-c", script, diskPath).CombinedOutput()
		if err != nil {
			return fmt.Errorf("qemu-io zeroing %d bytes at offset %d of %q failed: %v: %s",
				r[1], r[0], diskPath, err, out)
		}
	}
	log.Infof("Destroyed the filesystem on partition %q (offset %d, length %d) of %q",
		partitionLabel, part.Offset, part.Length, diskPath)
	return nil
}

// diskVirtualSizeBytes reports the virtual size of a QCOW2 disk.
func diskVirtualSizeBytes(ctx context.Context, diskPath string) (int64, error) {
	out, err := exec.CommandContext(ctx, "qemu-img", "info",
		"-f", "qcow2", "--output=json", diskPath).Output()
	if err != nil {
		return 0, fmt.Errorf("qemu-img info of %q failed: %w", diskPath, err)
	}
	var info struct {
		VirtualSize int64 `json:"virtual-size"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return 0, fmt.Errorf("failed to parse qemu-img info output for %q: %w", diskPath, err)
	}
	if info.VirtualSize <= 0 {
		return 0, fmt.Errorf("qemu-img info reported no virtual size for %q", diskPath)
	}
	return info.VirtualSize, nil
}
