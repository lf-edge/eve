// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"os"
	"testing"
	"unicode/utf16"
)

// buildTestGPT lays out a minimal but structurally valid GPT: a protective MBR
// at LBA 0, a header at LBA 1, and a 128-entry array at LBA 2.
func buildTestGPT(t *testing.T, parts []struct {
	Name     string
	FirstLBA uint64
	LastLBA  uint64
}) []byte {
	t.Helper()
	const entrySize = 128
	const numEntries = 128
	head := make([]byte, 1<<20)

	hdr := head[512:]
	copy(hdr[0:8], []byte("EFI PART"))
	binary.LittleEndian.PutUint64(hdr[72:80], 2) // partition entry LBA
	binary.LittleEndian.PutUint32(hdr[80:84], numEntries)
	binary.LittleEndian.PutUint32(hdr[84:88], entrySize)

	for i, p := range parts {
		off := 2*512 + i*entrySize
		e := head[off : off+entrySize]
		e[0] = 0xAA // non-zero type GUID so the entry looks used
		binary.LittleEndian.PutUint64(e[32:40], p.FirstLBA)
		binary.LittleEndian.PutUint64(e[40:48], p.LastLBA)
		for j, r := range utf16.Encode([]rune(p.Name)) {
			binary.LittleEndian.PutUint16(e[56+j*2:58+j*2], r)
		}
	}
	return head
}

func TestFindGPTPartition(t *testing.T) {
	head := buildTestGPT(t, []struct {
		Name     string
		FirstLBA uint64
		LastLBA  uint64
	}{
		{Name: "EFI", FirstLBA: 2048, LastLBA: 6143},
		{Name: "CONFIG", FirstLBA: 6144, LastLBA: 16383},
		{Name: "IMGA", FirstLBA: 16384, LastLBA: 65535},
	})

	got, err := findGPTPartition(head, "CONFIG")
	if err != nil {
		t.Fatalf("findGPTPartition: %v", err)
	}
	if got.Offset != 6144*512 {
		t.Errorf("Offset = %d, want %d", got.Offset, 6144*512)
	}
	if got.Length != (16383-6144+1)*512 {
		t.Errorf("Length = %d, want %d", got.Length, (16383-6144+1)*512)
	}
}

func TestFindGPTPartitionNotFound(t *testing.T) {
	head := buildTestGPT(t, []struct {
		Name     string
		FirstLBA uint64
		LastLBA  uint64
	}{
		{Name: "EFI", FirstLBA: 2048, LastLBA: 6143},
	})
	if _, err := findGPTPartition(head, "CONFIG"); err == nil {
		t.Fatal("expected an error when no CONFIG partition exists")
	}
}

func TestFindGPTPartitionBadSignature(t *testing.T) {
	head := buildTestGPT(t, nil)
	copy(head[512:520], []byte("NOTAGPT!"))
	if _, err := findGPTPartition(head, "CONFIG"); err == nil {
		t.Fatal("expected an error for a bad GPT signature")
	}
}

func TestFindGPTPartitionShortInput(t *testing.T) {
	if _, err := findGPTPartition(make([]byte, 100), "CONFIG"); err == nil {
		t.Fatal("expected an error for a truncated disk head")
	}
}

// TestFindGPTPartitionRealImage runs the parser against bytes captured from a
// real EVE live image, so a change in the on-disk layout is caught here rather
// than at boot time.
func TestFindGPTPartitionRealImage(t *testing.T) {
	head, err := os.ReadFile("testdata/gpt-head-live.bin")
	if err != nil {
		t.Skipf("fixture not available: %v", err)
	}
	got, err := findGPTPartition(head, gptConfigPartName)
	if err != nil {
		t.Fatalf("findGPTPartition: %v", err)
	}
	const configPartSize = 5 * 1024 * 1024
	if got.Length != configPartSize {
		t.Errorf("Length = %d, want %d (make-raw CONF_PART_SIZE)", got.Length, configPartSize)
	}
	if got.Offset%(1<<20) != 0 {
		t.Errorf("Offset = %d, expected 1 MiB alignment", got.Offset)
	}
}

// TestFindGPTPartitionOverflowingHeader covers a corrupt header whose entry
// array location overflows int64: the offset wraps negative, which an
// upper-bound-only check would let through into a panicking slice.
func TestFindGPTPartitionOverflowingHeader(t *testing.T) {
	head := buildTestGPT(t, nil)
	hdr := head[512:]
	binary.LittleEndian.PutUint64(hdr[72:80], 1<<54) // entry array LBA
	binary.LittleEndian.PutUint32(hdr[80:84], 128)   // number of entries
	binary.LittleEndian.PutUint32(hdr[84:88], 128)   // entry size
	if _, err := findGPTPartition(head, gptConfigPartName); err == nil {
		t.Fatal("expected an error for a header whose entry array overflows int64")
	}
}
