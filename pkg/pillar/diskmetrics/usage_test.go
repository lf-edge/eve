// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"io"
	"os"
	"path/filepath"
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

func TestFindLargeFilesExcludedDirBoundary(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "testfindlargefiles")
	if err != nil {
		t.Fatalf("os.MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	excludedDir := filepath.Join(tmpDir, "pkgs")
	if err := os.MkdirAll(excludedDir, 0o755); err != nil {
		t.Fatalf("os.MkdirAll(%s) failed: %v", excludedDir, err)
	}

	excludedLargeFile := filepath.Join(excludedDir, "in-excluded-dir.bin")
	includedLargeFile := filepath.Join(tmpDir, "pkgs.img")
	smallFile := filepath.Join(tmpDir, "small.bin")

	if err := os.WriteFile(excludedLargeFile, make([]byte, 2048), 0o644); err != nil {
		t.Fatalf("os.WriteFile(%s) failed: %v", excludedLargeFile, err)
	}
	if err := os.WriteFile(includedLargeFile, make([]byte, 2048), 0o644); err != nil {
		t.Fatalf("os.WriteFile(%s) failed: %v", includedLargeFile, err)
	}
	if err := os.WriteFile(smallFile, make([]byte, 128), 0o644); err != nil {
		t.Fatalf("os.WriteFile(%s) failed: %v", smallFile, err)
	}

	list, err := FindLargeFiles(tmpDir, 1024, []string{excludedDir})
	if err != nil {
		t.Fatalf("FindLargeFiles failed: %v", err)
	}

	found := make(map[string]struct{}, len(list))
	for _, entry := range list {
		found[entry.Path] = struct{}{}
	}
	if _, ok := found[excludedLargeFile]; ok {
		t.Fatalf("excluded file %s must not be returned", excludedLargeFile)
	}
	if _, ok := found[includedLargeFile]; !ok {
		t.Fatalf("file %s should be returned", includedLargeFile)
	}
	if _, ok := found[smallFile]; ok {
		t.Fatalf("small file %s must not be returned", smallFile)
	}
}
