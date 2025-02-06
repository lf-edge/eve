// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"io"
	"os"
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
