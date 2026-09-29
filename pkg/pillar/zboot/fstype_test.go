// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zboot

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// image builds a fake partition image with want written at offset.
func image(size int, offset int, magic []byte) *bytes.Reader {
	buf := make([]byte, size)
	copy(buf[offset:], magic)
	return bytes.NewReader(buf)
}

func TestDetectFSType(t *testing.T) {
	tests := []struct {
		name   string
		reader *bytes.Reader
		want   string
	}{
		{"squashfs little-endian", image(2048, squashfsMagicOffset, squashfsMagicLE), "squashfs"},
		{"squashfs big-endian", image(2048, squashfsMagicOffset, squashfsMagicBE), "squashfs"},
		{"erofs", image(2048, erofsMagicOffset, erofsMagic), "erofs"},
		{"ext4", image(2048, extMagicOffset, extMagic), "ext4"},
		{"all zeroes", image(2048, 0, nil), ""},
		{"too short for any superblock", image(16, 0, nil), ""},
		{"empty", bytes.NewReader(nil), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectFSType(tt.reader); got != tt.want {
				t.Errorf("detectFSType() = %q, want %q", got, tt.want)
			}
		})
	}
}

// An ext4 superblock sits at 1024 and a squashfs magic at 0, so an image
// carrying both must not be reported as ext4 - squashfs is checked first and
// is the one the kernel would accept for a real EVE rootfs.
func TestDetectFSTypeSquashfsWins(t *testing.T) {
	buf := make([]byte, 2048)
	copy(buf[squashfsMagicOffset:], squashfsMagicLE)
	copy(buf[extMagicOffset:], extMagic)
	if got := detectFSType(bytes.NewReader(buf)); got != "squashfs" {
		t.Errorf("detectFSType() = %q, want squashfs", got)
	}
}

func TestFSTypesForDevice(t *testing.T) {
	dir := t.TempDir()

	// A detected type must come first, with the others kept as fallback.
	path := filepath.Join(dir, "ext4.img")
	buf := make([]byte, 2048)
	copy(buf[extMagicOffset:], extMagic)
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := fsTypesForDevice(path)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(got) != len(allFSTypes) || got[0] != "ext4" {
		t.Errorf("fsTypesForDevice() = %v, want ext4 first and all %d types", got, len(allFSTypes))
	}

	// An unreadable device must degrade to trying everything, and say why.
	got, err = fsTypesForDevice(filepath.Join(dir, "does-not-exist"))
	if err == nil {
		t.Error("expected an error for a missing device")
	}
	if len(got) != len(allFSTypes) || got[0] != "squashfs" {
		t.Errorf("fsTypesForDevice() = %v, want the full fallback list", got)
	}
}
