// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"io"
	"os"
	"reflect"
	"testing"
)

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
