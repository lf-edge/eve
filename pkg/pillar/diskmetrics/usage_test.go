// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"io"
	"os"
	"testing"

	"github.com/containerd/containerd/mount"
)

func TestIsWholeFilesystem(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		mi   mount.Info
		want bool
	}{
		{
			name: "ext4 filesystem mounted at dir",
			dir:  "/persist/vault",
			mi:   mount.Info{Mountpoint: "/persist/vault", Root: "/", FSType: "ext4"},
			want: true,
		},
		{
			name: "zfs dataset mounted at dir",
			dir:  "/persist/reserved",
			mi:   mount.Info{Mountpoint: "/persist/reserved", Root: "/", FSType: "zfs"},
			want: true,
		},
		{
			name: "dir is a plain subdirectory of a mountpoint",
			dir:  "/persist/vault/volumes",
			mi:   mount.Info{Mountpoint: "/persist", Root: "/", FSType: "zfs"},
			want: false,
		},
		{
			name: "bind mount of a subtree",
			dir:  "/persist/kubelog",
			mi:   mount.Info{Mountpoint: "/persist/kubelog", Root: "/log", FSType: "ext4"},
			want: false,
		},
		{
			name: "mountpoint is a prefix of dir",
			dir:  "/persist/vault2",
			mi:   mount.Info{Mountpoint: "/persist/vault", Root: "/", FSType: "ext4"},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isWholeFilesystem(tc.mi, tc.dir); got != tc.want {
				t.Fatalf("isWholeFilesystem(%+v, %s) = %v, want %v",
					tc.mi, tc.dir, got, tc.want)
			}
		})
	}
}

func TestStatAllocatedBytes(t *testing.T) {
	// Generate a tmpfile path
	tmpdir, err := os.MkdirTemp("", "teststatallocatedbytes")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	// Create a file for io
	// Allocate the last half of the file
	file, err := os.Create(tmpdir + "/testfile.dat")
	if err != nil {
		t.Fatalf("os.Create failed creating testfile.dat : %v", err)
	}
	defer file.Close()
	_, err = file.Seek(1024*512, io.SeekStart)
	if err != nil {
		t.Fatalf("file.Seek failed: %v", err)
	}
	halfMB := make([]byte, 1024*512)
	_, err = file.Write(halfMB)
	if err != nil {
		t.Fatalf("file.Write failed: %v", err)
	}
	err = file.Close()
	if err != nil {
		t.Fatalf("file.Close failed: %v", err)
	}
	allocatedBytes, err := StatAllocatedBytes(tmpdir + "/testfile.dat")
	if err != nil {
		t.Fatalf("StatAllocatedBytes failed: %v", err)
	}
	// check if the allocated bytes are 50% of 1MB
	if allocatedBytes != 1024*512 {
		t.Fatalf("Test file should be half allocated")
	}

	//
	// Now fully allocate it (allocate the first half of the file)
	//
	file, err = os.OpenFile(tmpdir+"/testfile.dat", os.O_RDWR, 0644)
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		t.Fatalf("file.Seek failed: %v", err)
	}
	halfMB = make([]byte, 1024*512)
	_, err = file.Write(halfMB)
	if err != nil {
		t.Fatalf("file.Write failed: %v", err)
	}
	err = file.Close()
	if err != nil {
		t.Fatalf("file.Close failed: %v", err)
	}
	allocatedBytes, err = StatAllocatedBytes(tmpdir + "/testfile.dat")
	if err != nil {
		t.Fatalf("StatAllocatedBytes failed: %v", err)
	}
	// check if the allocated bytes are 100% of 1MB
	if allocatedBytes != 1024*1024 {
		t.Fatalf("Test File should be fully allocated")
	}
}
