// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/containerd/containerd/mount"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

func TestWalkHeartbeat(t *testing.T) {
	beats := 0
	hb := newWalkHeartbeat(func() { beats++ })

	hb.beat()
	hb.beat()
	if beats != 1 {
		t.Fatalf("beats = %d, want 1: beat() within walkTickInterval must be dropped", beats)
	}

	hb.next = time.Now().Add(-time.Second)
	hb.beat()
	if beats != 2 {
		t.Fatalf("beats = %d, want 2: beat() after walkTickInterval must report", beats)
	}

	// A walk with no callback carries a nil heartbeat.
	newWalkHeartbeat(nil).beat()
}

func TestSizeFromDirReportsProgress(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), t.Name(), 0) //nolint:staticcheck
	tmpdir := t.TempDir()

	const (
		dirs          = 3
		filesPerDir   = 25
		bytesPerFile  = 100
		expectedTotal = dirs * filesPerDir * bytesPerFile
	)
	for d := 0; d < dirs; d++ {
		subdir := fmt.Sprintf("%s/sub%d", tmpdir, d)
		if err := os.Mkdir(subdir, 0755); err != nil {
			t.Fatalf("os.Mkdir failed: %v", err)
		}
		for f := 0; f < filesPerDir; f++ {
			name := fmt.Sprintf("%s/file%d", subdir, f)
			if err := os.WriteFile(name, make([]byte, bytesPerFile), 0644); err != nil {
				t.Fatalf("os.WriteFile failed: %v", err)
			}
		}
	}

	beats := 0
	size, err := SizeFromDir(log, tmpdir, func() { beats++ })
	if err != nil {
		t.Fatalf("SizeFromDir failed: %v", err)
	}
	if size != expectedTotal {
		t.Fatalf("SizeFromDir = %d, want %d", size, expectedTotal)
	}
	if beats == 0 {
		t.Fatalf("SizeFromDir never reported progress")
	}

	size, err = SizeFromDir(log, tmpdir, nil)
	if err != nil {
		t.Fatalf("SizeFromDir with no callback failed: %v", err)
	}
	if size != expectedTotal {
		t.Fatalf("SizeFromDir with no callback = %d, want %d", size, expectedTotal)
	}
}

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

func TestDom0DiskReservedSizeNewlogTerm(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), t.Name(), 0) //nolint:staticcheck

	// The newlog term is one of several summands, and which of the others
	// applies depends on the disk size. Difference against a zero quota to
	// isolate it.
	newlogTerm := func(deviceDiskSize uint64, quotaMBytes uint32) uint64 {
		reserved := func(quota uint32) uint64 {
			gc := types.DefaultConfigItemValueMap()
			gc.SetGlobalValueInt(types.LogRemainToSendMBytes, quota)
			return Dom0DiskReservedSize(log, gc, deviceDiskSize, 0)
		}
		return reserved(quotaMBytes) - reserved(0)
	}

	tests := []struct {
		name           string
		deviceDiskSize uint64
		quotaMBytes    uint32
		want           uint64
	}{
		{
			// newlogd clamps its own quota to a tenth of /persist, so the
			// default 2048 MBytes is unreachable on a 4 GByte /persist.
			name:           "quota above newlogd's tenth-of-persist clamp",
			deviceDiskSize: 4037619712,
			quotaMBytes:    2048,
			want:           403761971,
		},
		{
			name:           "quota below the clamp is converted from MBytes",
			deviceDiskSize: 32000000000,
			quotaMBytes:    2048,
			want:           2048000000,
		},
		{
			name:           "minimum quota",
			deviceDiskSize: 32000000000,
			quotaMBytes:    10,
			want:           10000000,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := newlogTerm(tc.deviceDiskSize, tc.quotaMBytes)
			if got != tc.want {
				t.Errorf("newlog reserve on %d bytes of /persist with a %d MByte quota = %d, want %d",
					tc.deviceDiskSize, tc.quotaMBytes, got, tc.want)
			}
		})
	}
}
