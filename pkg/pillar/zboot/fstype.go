// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zboot

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// Filesystem detection for the inactive root partition.
//
// baseosmgr reads /etc/eve-release out of the partition it has just written
// in order to check the installed version against the one the controller
// asked for (see checkInstalledVersion). That means mounting a partition
// whose filesystem this code did not create and cannot assume.
//
// EVE's rootfs format is a build-time choice: squashfs by default, ext4 when
// the image is built with ROOTFS_FORMAT=ext4, and erofs where the erofs
// config fragment is applied. Mounting with the wrong type fails with EINVAL,
// which surfaces as an empty version string rather than as a mount error -
// baseosmgr then reports "image name not match. config <ver>, image ver "
// and rolls the partition back to unused. The update looks like it was
// rejected on content when in fact it was never readable.
//
// Detection is by superblock magic rather than by trying each type in turn,
// so a wrong guess never reaches the kernel and never logs a spurious
// "VFS: Can't find ext4 filesystem" for what is really a squashfs.

const (
	// squashfs stores its magic in the first four bytes.
	squashfsMagicOffset = 0
	// erofs puts its superblock at 1024 and the magic at its start.
	erofsMagicOffset = 1024
	// ext2/3/4 put the superblock at 1024 and s_magic 56 bytes into it.
	extMagicOffset = 1024 + 56
)

var (
	// "hsqs": squashfs 4.x as mksquashfs writes it on a little-endian host.
	squashfsMagicLE = []byte{0x68, 0x73, 0x71, 0x73}
	// "sqsh": the big-endian variant, still found in older images.
	squashfsMagicBE = []byte{0x73, 0x71, 0x73, 0x68}
	// 0xe0f5e1e2, little-endian on disk.
	erofsMagic = []byte{0xe2, 0xe1, 0xf5, 0xe0}
	// 0xef53, little-endian on disk. Shared by ext2, ext3 and ext4; the
	// ext4 driver mounts all three, so one type string covers them.
	extMagic = []byte{0x53, 0xef}
)

// allFSTypes is the fallback order when the magic is unrecognised, most
// likely format first. Keeping squashfs first preserves the behaviour this
// code had when it was hardcoded.
var allFSTypes = []string{"squashfs", "ext4", "erofs"}

// detectFSType returns the mount filesystem type for the image in r, or ""
// when no superblock magic is recognised. It reads at most 1080 bytes and
// treats a short read as "not this filesystem" rather than an error, so a
// truncated or empty partition simply yields "".
func detectFSType(r io.ReaderAt) string {
	matches := func(offset int64, want []byte) bool {
		got := make([]byte, len(want))
		if _, err := r.ReadAt(got, offset); err != nil {
			return false
		}
		return bytes.Equal(got, want)
	}

	switch {
	case matches(squashfsMagicOffset, squashfsMagicLE),
		matches(squashfsMagicOffset, squashfsMagicBE):
		return "squashfs"
	case matches(erofsMagicOffset, erofsMagic):
		return "erofs"
	case matches(extMagicOffset, extMagic):
		return "ext4"
	}
	return ""
}

// fsTypesForDevice returns the filesystem types to try for devname, in order.
// The detected type comes first; the remaining known types follow it as a
// fallback, so an unreadable device or an unrecognised magic degrades to the
// same try-everything behaviour rather than failing outright.
func fsTypesForDevice(devname string) ([]string, error) {
	file, err := os.Open(devname)
	if err != nil {
		return allFSTypes, fmt.Errorf("open %s: %w", devname, err)
	}
	defer file.Close()

	detected := detectFSType(file)
	if detected == "" {
		return allFSTypes, nil
	}
	ordered := []string{detected}
	for _, fstype := range allFSTypes {
		if fstype != detected {
			ordered = append(ordered, fstype)
		}
	}
	return ordered, nil
}
