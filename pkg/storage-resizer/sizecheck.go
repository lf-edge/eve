// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

// Pre-flight size checks for the EVE-kvm -> EVE-k repartition (design-doc Item 2).
//
// These run before any destructive operation to decide whether the boot disk
// already has the EVE-k geometry, whether there is room to create it outright,
// and whether the ext4 /persist filesystem can be shrunk to make room. They are
// deliberately dependency-free: the GPT and the ext4 superblock are parsed
// directly so the same code runs identically in baseosmgr (via the binary's
// `check` subcommand) and in the standalone resizer, on a disk image or a real
// block device, mounted or not.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf16"
)

const (
	// GiB is a binary gibibyte.
	GiB = int64(1) << 30

	// EVE-k target partition sizes (verified against pkg/mkimage-raw-efi/make-raw:
	// part 1 "EFI System" 2 GB, IMGA/IMGB 10 GB, persist labelled "P3" at index 9).
	espTargetBytes = 2 * GiB
	imgTargetBytes = 10 * GiB

	// spaceNeededBytes is the additional room the three new partitions need
	// (2 + 10 + 10 GB).
	spaceNeededBytes = espTargetBytes + 2*imgTargetBytes

	// MiB is a binary mebibyte.
	MiB = int64(1) << 20

	// Shrink floor margin. resize2fs cannot shrink an ext4 filesystem below its
	// minimum size (used data plus non-relocatable metadata). The resize-bench
	// floor sweep (tests/resize-bench) measured that floor above the used bytes
	// as roughly a fixed reserve plus a small fraction of the partition size, so
	// these bound it: a shrink is allowed only if the target leaves the result at
	// least this far above the used data, else resize2fs would refuse mid-shrink.
	//
	// Fitted (with a 1.25x safety factor) to the full resize-bench fill sweep
	// (fill 30/50/70/85/95% x small/mix/aged x default/eve/nojournal, 8-64 GB).
	// The worst-case floor-above-used tracks ~1742 MiB + 1.311% of size; the
	// constants below are that fit scaled by 1.25, giving ~1.25x headroom over the
	// measured upper envelope across the whole size range. See
	// tests/resize-bench/README.md and ~/notes/ext4-floor-sweep0.md.
	shrinkMarginFixedBytes = 2177 * MiB // fixed reserve
	shrinkMarginPerLakh    = 1639       // + 1.639% of partition size (1639 / 100000)

	// Real EVE GPT partition labels.
	labelESP     = "EFI System"
	labelIMGA    = "IMGA"
	labelIMGB    = "IMGB"
	labelPersist = "P3"

	// gptBackupSectors is the space the secondary GPT (header + entry array)
	// reserves at the very end of the disk; it must not be counted as free.
	gptBackupSectors = 33
)

// Partition is one GPT entry, sizes resolved to bytes.
type Partition struct {
	Index     int    `json:"index"`
	Name      string `json:"name"`
	FirstLBA  uint64 `json:"firstLBA"`
	LastLBA   uint64 `json:"lastLBA"`
	SizeBytes int64  `json:"sizeBytes"`
}

// deviceSize returns the size in bytes of a regular file or a block device by
// seeking to the end (works for both, unlike Stat on a block device).
func deviceSize(f *os.File) (int64, error) {
	return f.Seek(0, io.SeekEnd)
}

// readGPT parses the primary GPT of the disk at path using the given logical
// sector size (EVE uses 512). It returns the non-empty partitions and the total
// device size in bytes.
func readGPT(path string, sectorSize int64) (parts []Partition, diskSize int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = f.Close() }()

	diskSize, err = deviceSize(f)
	if err != nil {
		return nil, 0, err
	}

	// GPT header lives in LBA 1.
	hdr := make([]byte, sectorSize)
	if _, err := f.ReadAt(hdr, sectorSize); err != nil {
		return nil, 0, fmt.Errorf("read GPT header: %w", err)
	}
	if string(hdr[0:8]) != "EFI PART" {
		return nil, 0, errors.New("not a GPT disk (missing EFI PART signature)")
	}
	entryLBA := binary.LittleEndian.Uint64(hdr[72:80])
	numEntries := binary.LittleEndian.Uint32(hdr[80:84])
	entrySize := binary.LittleEndian.Uint32(hdr[84:88])
	if entrySize < 128 || numEntries == 0 || numEntries > 1024 {
		return nil, 0, fmt.Errorf("implausible GPT entry array: num=%d size=%d", numEntries, entrySize)
	}

	buf := make([]byte, int(numEntries)*int(entrySize))
	if _, err := f.ReadAt(buf, int64(entryLBA)*sectorSize); err != nil {
		return nil, 0, fmt.Errorf("read GPT entries: %w", err)
	}
	for i := 0; i < int(numEntries); i++ {
		e := buf[i*int(entrySize) : (i+1)*int(entrySize)]
		first := binary.LittleEndian.Uint64(e[32:40])
		last := binary.LittleEndian.Uint64(e[40:48])
		if first == 0 && last == 0 {
			continue // unused slot
		}
		parts = append(parts, Partition{
			Index:     i + 1,
			Name:      decodeUTF16Name(e[56:128]),
			FirstLBA:  first,
			LastLBA:   last,
			SizeBytes: int64(last-first+1) * sectorSize,
		})
	}
	return parts, diskSize, nil
}

// decodeUTF16Name decodes a GPT partition name (UTF-16LE, NUL-padded).
func decodeUTF16Name(b []byte) string {
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i : i+2])
		if c == 0 {
			break
		}
		u16 = append(u16, c)
	}
	return string(utf16.Decode(u16))
}

// partByName returns the first partition with the given GPT name.
func partByName(parts []Partition, name string) (Partition, bool) {
	for _, p := range parts {
		if p.Name == name {
			return p, true
		}
	}
	return Partition{}, false
}

// LargeResult reports whether each large partition is already at its target size.
type LargeResult struct {
	InPlace bool  `json:"inPlace"`
	ESP     int64 `json:"espBytes"`
	IMGA    int64 `json:"imgaBytes"`
	IMGB    int64 `json:"imgbBytes"`
}

// LargePartitionsInPlace reports whether ESP ("EFI System") is >= 2 GB and
// IMGA/IMGB are each >= 10 GB — i.e. the disk already has the EVE-k geometry.
func LargePartitionsInPlace(parts []Partition) LargeResult {
	esp, okE := partByName(parts, labelESP)
	imga, okA := partByName(parts, labelIMGA)
	imgb, okB := partByName(parts, labelIMGB)
	r := LargeResult{ESP: esp.SizeBytes, IMGA: imga.SizeBytes, IMGB: imgb.SizeBytes}
	r.InPlace = okE && okA && okB &&
		esp.SizeBytes >= espTargetBytes &&
		imga.SizeBytes >= imgTargetBytes &&
		imgb.SizeBytes >= imgTargetBytes
	return r
}

// SpaceResult reports the free tail on the boot disk.
type SpaceResult struct {
	OK            bool  `json:"ok"`
	FreeTailBytes int64 `json:"freeTailBytes"`
	NeededBytes   int64 `json:"neededBytes"`
}

// SpaceForLargePartitions reports whether the boot disk has at least 22 GB of
// unallocated space after the last partition (minus the backup-GPT reservation)
// — enough to create ESP2/IMGA2/IMGB2 without shrinking anything.
func SpaceForLargePartitions(parts []Partition, diskSize, sectorSize int64) SpaceResult {
	var maxEnd int64 // first byte past the last partition
	for _, p := range parts {
		end := int64(p.LastLBA+1) * sectorSize
		if end > maxEnd {
			maxEnd = end
		}
	}
	free := diskSize - maxEnd - gptBackupSectors*sectorSize
	if free < 0 {
		free = 0
	}
	return SpaceResult{OK: free >= spaceNeededBytes, FreeTailBytes: free, NeededBytes: spaceNeededBytes}
}

// ShrinkResult reports whether the ext4 /persist can be shrunk to free the
// requested space while leaving the resulting filesystem no fuller than policy
// allows.
type ShrinkResult struct {
	OK             bool  `json:"ok"`
	TotalBytes     int64 `json:"totalBytes"`
	UsedBytes      int64 `json:"usedBytes"`
	FreeBytes      int64 `json:"freeBytes"`
	NeededBytes    int64 `json:"neededBytes"`    // space to free for the new partitions
	TargetBytes    int64 `json:"targetBytes"`    // resulting fs size = total - need
	MaxFullPercent int   `json:"maxFullPercent"` // policy: result must be <= this % full
	ResultPercent  int   `json:"resultPercent"`  // used/target as a percent (0 if target<=0)
	BlockSize      int64 `json:"blockSize"`
	MarginBytes    int64 `json:"marginBytes"`        // shrink floor margin above used
	FloorEstBytes  int64 `json:"floorEstimateBytes"` // used + margin; target must be >= this
}

// ext4Superblock holds the few fields the shrink check needs.
type ext4Superblock struct {
	blockSize  int64
	blockCount int64
	freeBlocks int64
}

// readExt4Superblock parses the ext4 superblock located 1024 bytes into the
// partition that starts at partOffset bytes within path.
func readExt4Superblock(path string, partOffset int64) (ext4Superblock, error) {
	f, err := os.Open(path)
	if err != nil {
		return ext4Superblock{}, err
	}
	defer func() { _ = f.Close() }()

	b := make([]byte, 1024)
	if _, err := f.ReadAt(b, partOffset+1024); err != nil {
		return ext4Superblock{}, fmt.Errorf("read ext4 superblock: %w", err)
	}
	if binary.LittleEndian.Uint16(b[0x38:0x3a]) != 0xEF53 {
		return ext4Superblock{}, errors.New("not an ext4 filesystem (bad magic)")
	}
	logBlockSize := binary.LittleEndian.Uint32(b[0x18:0x1c])
	blockCount := uint64(binary.LittleEndian.Uint32(b[0x04:0x08])) |
		uint64(binary.LittleEndian.Uint32(b[0x150:0x154]))<<32
	freeBlocks := uint64(binary.LittleEndian.Uint32(b[0x0c:0x10])) |
		uint64(binary.LittleEndian.Uint32(b[0x158:0x15c]))<<32
	return ext4Superblock{
		blockSize:  int64(1024) << logBlockSize,
		blockCount: int64(blockCount),
		freeBlocks: int64(freeBlocks),
	}, nil
}

// SpaceToShrinkExt reports whether the ext4 filesystem at partOffset can give
// back needBytes (by shrinking to total-need) while leaving the result at most
// maxFullPercent full.
//
// Two conditions must hold. First, the target must clear the resize2fs *floor*:
// resize2fs refuses to shrink below the used data plus non-relocatable metadata,
// so the target has to leave a margin (a fixed reserve plus a fraction of size,
// measured by resize-bench) above the used bytes — otherwise the shrink fails
// mid-flight. Second, a flat free-space check is not enough for operating
// headroom: shrinking a filesystem that is 75% of a 100 GB partition down by
// 22 GB lands it at ~96% full, with no room to run; so the result must also be
// at most maxFullPercent full. The margin tends to bind on small partitions, the
// fullness cap on large ones.
func SpaceToShrinkExt(path string, partOffset, needBytes int64, maxFullPercent int) (ShrinkResult, error) {
	sb, err := readExt4Superblock(path, partOffset)
	if err != nil {
		return ShrinkResult{}, err
	}
	total := sb.blockCount * sb.blockSize
	free := sb.freeBlocks * sb.blockSize
	used := total - free
	target := total - needBytes
	margin := shrinkMarginFixedBytes + total*shrinkMarginPerLakh/100000
	r := ShrinkResult{
		TotalBytes: total, UsedBytes: used, FreeBytes: free,
		NeededBytes: needBytes, TargetBytes: target,
		MaxFullPercent: maxFullPercent, BlockSize: sb.blockSize,
		MarginBytes: margin, FloorEstBytes: used + margin,
	}
	if target <= 0 {
		return r, nil // cannot free that much; OK stays false
	}
	r.ResultPercent = int(used * 100 / target)
	// OK iff the target clears the resize2fs floor AND the result is at most
	// maxFullPercent full.
	r.OK = target >= r.FloorEstBytes && used*100 <= int64(maxFullPercent)*target
	return r, nil
}
