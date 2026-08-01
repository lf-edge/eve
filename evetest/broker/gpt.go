// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"unicode/utf16"
)

const (
	// gptSectorSize is the logical sector size EVE images are built with:
	// pkg/mkimage-raw-efi/make-raw computes every partition offset as
	// sectors * 512.
	gptSectorSize = 512
	// gptHeaderLBA holds the primary GPT header; LBA 0 is the protective MBR.
	gptHeaderLBA = 1
	// gptSignature is the magic at the start of a GPT header.
	gptSignature = "EFI PART"
	// gptHeadBytes is how much of the disk to read. The protective MBR, header
	// and a standard 128 x 128 B entry array need only 16 KiB; 1 MiB is read
	// instead because it is the first partition's alignment boundary, so it
	// covers the whole GPT region however large the entry array is.
	gptHeadBytes = 1 << 20
	// gptMinEntrySize is the size mandated by the UEFI spec; anything smaller
	// means we are not looking at a GPT.
	gptMinEntrySize = 128
	// gptConfigPartName is the GPT partition name EVE gives its config
	// partition, in both the live (make-raw do_conf) and installer
	// (do_conf_win) layouts. EVE itself finds it with `findfs PARTLABEL=CONFIG`.
	gptConfigPartName = "CONFIG"
)

// gptPartition is a located partition, as byte offset and length from the
// start of the disk.
type gptPartition struct {
	Offset int64
	Length int64
}

// findGPTPartition locates a partition by its GPT name in the first
// gptHeadBytes of a disk. Matching on the name rather than the type GUID lets
// one code path serve both EVE layouts, which use different type GUIDs for the
// same CONFIG partition.
func findGPTPartition(head []byte, name string) (gptPartition, error) {
	const headerMinLen = 92
	hdrOff := gptHeaderLBA * gptSectorSize
	if len(head) < hdrOff+headerMinLen {
		return gptPartition{}, fmt.Errorf(
			"disk head is %d bytes, too short to contain a GPT header", len(head))
	}
	hdr := head[hdrOff:]
	if string(hdr[0:8]) != gptSignature {
		return gptPartition{}, fmt.Errorf("no %q signature at LBA %d",
			gptSignature, gptHeaderLBA)
	}
	entryLBA := int64(binary.LittleEndian.Uint64(hdr[72:80]))
	numEntries := int64(binary.LittleEndian.Uint32(hdr[80:84]))
	entrySize := int64(binary.LittleEndian.Uint32(hdr[84:88]))
	if entrySize < gptMinEntrySize {
		return gptPartition{}, fmt.Errorf(
			"GPT entry size %d is below the %d-byte minimum", entrySize, gptMinEntrySize)
	}

	base := entryLBA * gptSectorSize
	for i := int64(0); i < numEntries; i++ {
		off := base + i*entrySize
		// entryLBA, entrySize and numEntries all come from the disk, so a
		// corrupt or truncated image can make these products overflow into
		// negative values. A negative offset passes an upper-bound-only check
		// and then panics on the slice below, so check both ends.
		if off < 0 || off+entrySize < off || off+entrySize > int64(len(head)) {
			break
		}
		entry := head[off : off+entrySize]
		firstLBA := int64(binary.LittleEndian.Uint64(entry[32:40]))
		lastLBA := int64(binary.LittleEndian.Uint64(entry[40:48]))
		if firstLBA == 0 && lastLBA == 0 {
			continue
		}
		if decodeGPTName(entry[56:128]) != name {
			continue
		}
		if lastLBA < firstLBA {
			return gptPartition{}, fmt.Errorf(
				"GPT partition %q has last LBA %d before first LBA %d",
				name, lastLBA, firstLBA)
		}
		return gptPartition{
			Offset: firstLBA * gptSectorSize,
			Length: (lastLBA - firstLBA + 1) * gptSectorSize,
		}, nil
	}
	return gptPartition{}, fmt.Errorf("no GPT partition named %q", name)
}

// decodeGPTName decodes the 72-byte UTF-16LE, NUL-padded partition name field.
func decodeGPTName(raw []byte) string {
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		c := binary.LittleEndian.Uint16(raw[i : i+2])
		if c == 0 {
			break
		}
		units = append(units, c)
	}
	return string(utf16.Decode(units))
}

// readDiskHead reads the leading gptHeadBytes of a QCOW2 disk into memory.
// qemu-img is used rather than opening the file directly because the disk is
// QCOW2 (and its clusters are compressed), so the bytes are not at their
// nominal offsets on disk.
func readDiskHead(ctx context.Context, diskPath string) ([]byte, error) {
	tmpDir, err := os.MkdirTemp("", "evetest-gpt-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	headPath := filepath.Join(tmpDir, "head.bin")
	out, err := exec.CommandContext(ctx, "qemu-img", "dd",
		"-f", "qcow2", "-O", "raw",
		fmt.Sprintf("bs=%d", gptHeadBytes), "count=1",
		"if="+diskPath, "of="+headPath).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("qemu-img dd of %q failed: %v: %s", diskPath, err, out)
	}
	return os.ReadFile(headPath)
}
