// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/containerd/containerd/mount"
	"github.com/lf-edge/eve/pkg/pillar/base"
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

func TestParseLsblkPartitions(t *testing.T) {
	const linuxFSGUID = "0fc63daf-8483-4772-8e79-3d69d8477de4"
	const efiGUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"

	tests := []struct {
		name    string
		input   string
		want    []DiskPartition
		wantErr bool
	}{
		{
			name: "EVE GPT layout",
			input: `{
              "blockdevices": [
                {"name":"sda","partlabel":null,"parttype":null,"partuuid":null},
                {"name":"sda1","partlabel":"EFI System","parttype":"` + efiGUID + `","partuuid":"11111111-1111-1111-1111-111111111111"},
                {"name":"sda2","partlabel":"CONFIG","parttype":"` + linuxFSGUID + `","partuuid":"22222222-2222-2222-2222-222222222222"},
                {"name":"sda3","partlabel":"IMGA","parttype":"` + linuxFSGUID + `","partuuid":"33333333-3333-3333-3333-333333333333"},
                {"name":"sda4","partlabel":"IMGB","parttype":"` + linuxFSGUID + `","partuuid":"44444444-4444-4444-4444-444444444444"},
                {"name":"sda9","partlabel":"P3","parttype":"` + linuxFSGUID + `","partuuid":"99999999-9999-9999-9999-999999999999"}
              ]
            }`,
			want: []DiskPartition{
				{Name: "sda"},
				{Name: "sda1", PartitionLabel: "EFI System", PartitionType: efiGUID, PartitionUUID: "11111111-1111-1111-1111-111111111111"},
				{Name: "sda2", PartitionLabel: "CONFIG", PartitionType: linuxFSGUID, PartitionUUID: "22222222-2222-2222-2222-222222222222"},
				{Name: "sda3", PartitionLabel: "IMGA", PartitionType: linuxFSGUID, PartitionUUID: "33333333-3333-3333-3333-333333333333"},
				{Name: "sda4", PartitionLabel: "IMGB", PartitionType: linuxFSGUID, PartitionUUID: "44444444-4444-4444-4444-444444444444"},
				{Name: "sda9", PartitionLabel: "P3", PartitionType: linuxFSGUID, PartitionUUID: "99999999-9999-9999-9999-999999999999"},
			},
		},
		{
			name: "MBR partitions leave PARTLABEL and PARTUUID empty",
			input: `{
              "blockdevices": [
                {"name":"sdb","partlabel":null,"parttype":null,"partuuid":null},
                {"name":"sdb1","partlabel":null,"parttype":"0x83","partuuid":null},
                {"name":"sdb2","partlabel":null,"parttype":"0x82","partuuid":null}
              ]
            }`,
			want: []DiskPartition{
				{Name: "sdb"},
				{Name: "sdb1", PartitionType: "0x83"},
				{Name: "sdb2", PartitionType: "0x82"},
			},
		},
		{
			name:  "empty blockdevices list",
			input: `{"blockdevices":[]}`,
			want:  []DiskPartition{},
		},
		{
			name:    "malformed JSON",
			input:   `{"blockdevices":`,
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   ``,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLsblkPartitions([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil; result=%+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseLsblkPartitions mismatch\n got: %+v\nwant: %+v", got, tc.want)
			}
		})
	}
}
