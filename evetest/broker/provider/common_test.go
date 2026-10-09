// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"strings"
	"testing"
)

// TestDiskImageMediaDefaultsToDisk guards the zero value: every DiskImage built
// before Media existed must keep meaning a writable disk.
func TestDiskImageMediaDefaultsToDisk(t *testing.T) {
	var disk DiskImage
	if disk.Media != DiskImageMediaDisk {
		t.Fatalf("zero DiskImage.Media = %v, want %v", disk.Media, DiskImageMediaDisk)
	}
}

// TestCheckDiskMedia covers the guard every provider runs before attaching
// disks: plain disks pass, and a CD-ROM -- declared for installer ISOs but not
// implemented by any provider yet -- is refused rather than attached as a disk.
func TestCheckDiskMedia(t *testing.T) {
	disks := []DiskImage{
		{Format: DiskImageFormatQcow2, Path: "/img/installer.qcow2"},
		{Format: DiskImageFormatQcow2, Path: "/img/installed.qcow2", Media: DiskImageMediaDisk},
	}
	if err := checkDiskMedia(disks); err != nil {
		t.Fatalf("checkDiskMedia(disks) = %v, want nil", err)
	}
	if err := checkDiskMedia(nil); err != nil {
		t.Fatalf("checkDiskMedia(nil) = %v, want nil", err)
	}

	withCdrom := append(disks, DiskImage{
		Format: DiskImageFormatRaw, Path: "/img/installer.iso", Media: DiskImageMediaCdrom})
	err := checkDiskMedia(withCdrom)
	if err == nil {
		t.Fatal("checkDiskMedia accepted a CD-ROM, which no provider implements yet")
	}
	for _, want := range []string{"/img/installer.iso", "cdrom"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}
