// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

const testSector = 512

type partSpec struct {
	name string
	size int64
}

// fixtureGUID maps a fixture partition label to the fixed EVE partition GUID
// buildGPTImage stamps on it. "ESP-B" is a fixture-only label for the reserved
// second ESP (matched by GUID, not label).
var fixtureGUID = map[string]string{
	labelESP:     espAUUID,
	labelIMGA:    imgaUUID,
	labelIMGB:    imgbUUID,
	labelPersist: persistUUID,
	"ESP-B":      espBUUID,
}

// encodeGUIDBytes converts a canonical GUID string to the 16-byte mixed-endian
// on-disk form. Empty string yields all zeros.
func encodeGUIDBytes(guid string) []byte {
	b := make([]byte, 16)
	raw, err := hex.DecodeString(strings.ReplaceAll(guid, "-", ""))
	if err != nil || len(raw) != 16 {
		return b
	}
	b[0], b[1], b[2], b[3] = raw[3], raw[2], raw[1], raw[0]
	b[4], b[5] = raw[5], raw[4]
	b[6], b[7] = raw[7], raw[6]
	copy(b[8:16], raw[8:16])
	return b
}

// gptHeaderBytes builds one GPT header sector. myLBA/altLBA and entriesLBA are
// what distinguish the primary copy from the backup copy at end-of-disk.
func gptHeaderBytes(myLBA, altLBA, entriesLBA, diskSectors uint64, entriesCRC uint32) []byte {
	hdr := make([]byte, testSector)
	copy(hdr[0:8], "EFI PART")
	binary.LittleEndian.PutUint32(hdr[8:12], 0x00010000) // revision 1.0
	binary.LittleEndian.PutUint32(hdr[12:16], 92)        // header size
	binary.LittleEndian.PutUint64(hdr[24:32], myLBA)
	binary.LittleEndian.PutUint64(hdr[32:40], altLBA)
	binary.LittleEndian.PutUint64(hdr[40:48], 34)             // first usable LBA
	binary.LittleEndian.PutUint64(hdr[48:56], diskSectors-34) // last usable LBA
	binary.LittleEndian.PutUint64(hdr[72:80], entriesLBA)
	binary.LittleEndian.PutUint32(hdr[80:84], 128)
	binary.LittleEndian.PutUint32(hdr[84:88], 128)
	binary.LittleEndian.PutUint32(hdr[88:92], entriesCRC)
	// The header CRC covers the first 92 bytes with its own field zeroed, which
	// it still is at this point.
	binary.LittleEndian.PutUint32(hdr[16:20], crc32.ChecksumIEEE(hdr[0:92]))
	return hdr
}

// buildGPTImage writes a sparse disk image at path carrying a valid primary and
// backup GPT, laying the parts out contiguously from LBA 2048. go-diskfs
// validates the signature, revision, header size and both CRCs, so the fixture
// has to be a structurally sound GPT and not just the fields the checks read.
// diskBytes sets the total device size (sparse). Fails the test on error.
func buildGPTImage(t *testing.T, path string, diskBytes int64, parts []partSpec) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create image: %v", err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Truncate(diskBytes); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	cursor := uint64(2048)
	entries := make([]byte, 128*128)
	for i, p := range parts {
		sectors := uint64((p.size + testSector - 1) / testSector)
		first := cursor
		last := first + sectors - 1
		e := entries[i*128 : (i+1)*128]
		// minimal non-zero type GUID so the slot is "used"
		e[0] = 0x01
		// unique partition GUID derived from the fixture label (the "ESP-B"
		// fixture label maps to the reserved second ESP's GUID)
		copy(e[16:32], encodeGUIDBytes(fixtureGUID[p.name]))
		binary.LittleEndian.PutUint64(e[32:40], first)
		binary.LittleEndian.PutUint64(e[40:48], last)
		u16 := utf16.Encode([]rune(p.name))
		for j, c := range u16 {
			binary.LittleEndian.PutUint16(e[56+j*2:58+j*2], c)
		}
		cursor = last + 1
	}

	entriesCRC := crc32.ChecksumIEEE(entries)
	diskSectors := uint64(diskBytes / testSector)
	backupEntriesLBA := diskSectors - 33
	sectors := []struct {
		what string
		b    []byte
		lba  uint64
	}{
		{"primary entries", entries, 2},
		{"backup entries", entries, backupEntriesLBA},
		{"primary header", gptHeaderBytes(1, diskSectors-1, 2, diskSectors, entriesCRC), 1},
		{"backup header", gptHeaderBytes(diskSectors-1, 1, backupEntriesLBA, diskSectors, entriesCRC), diskSectors - 1},
	}
	for _, w := range sectors {
		if _, err := f.WriteAt(w.b, int64(w.lba)*testSector); err != nil {
			t.Fatalf("write %s: %v", w.what, err)
		}
	}
}

func TestReadGPT(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.img")
	parts := []partSpec{
		{labelESP, 2 * GiB},
		{labelIMGA, 10 * GiB},
		{labelIMGB, 10 * GiB},
		{"CONFIG", 5 << 20},
		{labelPersist, 1 * GiB},
	}
	buildGPTImage(t, path, 30*GiB, parts)

	got, diskSize, err := readGPT(path, testSector)
	if err != nil {
		t.Fatalf("readGPT: %v", err)
	}
	if diskSize != 30*GiB {
		t.Errorf("diskSize = %d, want %d", diskSize, 30*GiB)
	}
	if len(got) != len(parts) {
		t.Fatalf("got %d partitions, want %d", len(got), len(parts))
	}
	for i, p := range parts {
		if got[i].Name != p.name {
			t.Errorf("part %d name = %q, want %q", i, got[i].Name, p.name)
		}
		// size rounds up to a whole sector; allow that
		if got[i].SizeBytes < p.size || got[i].SizeBytes >= p.size+testSector {
			t.Errorf("part %d size = %d, want ~%d", i, got[i].SizeBytes, p.size)
		}
	}
}

// TestReadGPTRejectsBackupRecovery corrupts the primary partition-entry array
// and leaves the backup GPT intact. gpt.Read then recovers the table from the
// backup, and the pre-flight has to refuse the disk rather than plan against a
// layout the kernel and the bootloader are not using.
func TestReadGPTRejectsBackupRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.img")
	buildGPTImage(t, path, 30*GiB, []partSpec{
		{labelESP, 2 * GiB},
		{labelIMGA, 10 * GiB},
		{labelIMGB, 10 * GiB},
		{labelPersist, 1 * GiB},
	})

	// The intact fixture must read cleanly first, so a failure after the
	// corruption is the corruption and not a malformed fixture.
	if _, _, err := readGPT(path, testSector); err != nil {
		t.Fatalf("readGPT on the intact fixture: %v", err)
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("reopen image: %v", err)
	}
	// Invert one byte of the first entry in the primary array so its CRC no
	// longer matches the primary header. Inverting cannot be a no-op.
	const corruptOff = 2*testSector + 40
	one := make([]byte, 1)
	if _, err := f.ReadAt(one, corruptOff); err != nil {
		t.Fatalf("read primary entry byte: %v", err)
	}
	one[0] ^= 0xff
	if _, err := f.WriteAt(one, corruptOff); err != nil {
		t.Fatalf("corrupt primary entries: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close image: %v", err)
	}

	_, _, err = readGPT(path, testSector)
	if err == nil {
		t.Fatal("readGPT accepted a table recovered from the backup GPT")
	}
	if !strings.Contains(err.Error(), "backup GPT") {
		t.Errorf("error = %v, want it to name the backup GPT", err)
	}
}

func TestLargePartitionsInPlace(t *testing.T) {
	cases := []struct {
		name  string
		parts []partSpec
		want  bool
	}{
		{
			name:  "full eve-k geometry incl ESP-B",
			parts: []partSpec{{labelESP, 2 * GiB}, {labelIMGA, 10 * GiB}, {labelIMGB, 10 * GiB}, {"ESP-B", 2 * GiB}, {labelPersist, 1 * GiB}},
			want:  true,
		},
		{
			name:  "large but ESP-B missing (e.g. EVE 17.0)",
			parts: []partSpec{{labelESP, 2 * GiB}, {labelIMGA, 10 * GiB}, {labelIMGB, 10 * GiB}, {labelPersist, 1 * GiB}},
			want:  false,
		},
		{
			name:  "pre-conversion small partitions",
			parts: []partSpec{{labelESP, 10 << 20}, {labelIMGA, 300 << 20}, {labelIMGB, 300 << 20}, {labelPersist, 1 * GiB}},
			want:  false,
		},
		{
			name:  "esp big but imgb too small",
			parts: []partSpec{{labelESP, 2 * GiB}, {labelIMGA, 10 * GiB}, {labelIMGB, 8 * GiB}, {labelPersist, 1 * GiB}},
			want:  false,
		},
		{
			name:  "missing imgb",
			parts: []partSpec{{labelESP, 2 * GiB}, {labelIMGA, 10 * GiB}, {labelPersist, 1 * GiB}},
			want:  false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "disk.img")
			buildGPTImage(t, path, 40*GiB, c.parts)
			parts, _, err := readGPT(path, testSector)
			if err != nil {
				t.Fatalf("readGPT: %v", err)
			}
			if got := LargePartitionsInPlace(parts).InPlace; got != c.want {
				t.Errorf("LargePartitionsInPlace = %v, want %v", got, c.want)
			}
		})
	}
}

func TestNeededBytes(t *testing.T) {
	cases := []struct {
		name  string
		parts []partSpec
		want  int64
	}{
		{
			name:  "pre-ESP-B kvm (all small, no ESP-B)",
			parts: []partSpec{{labelESP, 10 << 20}, {labelIMGA, 300 << 20}, {labelIMGB, 300 << 20}, {labelPersist, 1 * GiB}},
			want:  24 * GiB,
		},
		{
			name:  "EVE 17.0 (large ESP/IMG, no ESP-B) -> just ESP-B",
			parts: []partSpec{{labelESP, 2 * GiB}, {labelIMGA, 10 * GiB}, {labelIMGB, 10 * GiB}, {labelPersist, 1 * GiB}},
			want:  2 * GiB,
		},
		{
			name:  "fully provisioned (four large + ESP-B) -> nothing",
			parts: []partSpec{{labelESP, 2 * GiB}, {labelIMGA, 10 * GiB}, {labelIMGB, 10 * GiB}, {"ESP-B", 2 * GiB}, {labelPersist, 1 * GiB}},
			want:  0,
		},
		{
			name:  "one img undersized only",
			parts: []partSpec{{labelESP, 2 * GiB}, {labelIMGA, 10 * GiB}, {labelIMGB, 8 * GiB}, {"ESP-B", 2 * GiB}, {labelPersist, 1 * GiB}},
			want:  10 * GiB,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "disk.img")
			buildGPTImage(t, path, 60*GiB, c.parts)
			parts, _, err := readGPT(path, testSector)
			if err != nil {
				t.Fatalf("readGPT: %v", err)
			}
			if got := neededBytes(parts); got != c.want {
				t.Errorf("neededBytes = %d, want %d", got, c.want)
			}
		})
	}
}

func TestSpaceForLargePartitions(t *testing.T) {
	// small front partitions (~620 MB) then a big free tail
	front := []partSpec{{labelESP, 10 << 20}, {labelIMGA, 300 << 20}, {labelIMGB, 300 << 20}, {"CONFIG", 5 << 20}}
	cases := []struct {
		name     string
		diskSize int64
		want     bool
	}{
		{"30G disk, ~29G free tail", 30 * GiB, true},
		{"22.5G disk, ~21.9G free tail", 22*GiB + 512*(1<<20), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "disk.img")
			buildGPTImage(t, path, c.diskSize, front)
			parts, diskSize, err := readGPT(path, testSector)
			if err != nil {
				t.Fatalf("readGPT: %v", err)
			}
			if got := SpaceForLargePartitions(parts, diskSize, testSector, 22*GiB).OK; got != c.want {
				t.Errorf("SpaceForLargePartitions = %v, want %v", got, c.want)
			}
		})
	}
}

// writeFakeSuperblock writes a minimal ext4 superblock (just the fields the
// parser reads) at partOffset+1024 of a fresh file sized to hold it.
func writeFakeSuperblock(t *testing.T, path string, partOffset, logBlockSize uint32, blockCount, freeBlocks uint64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Truncate(int64(partOffset) + 4096); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	b := make([]byte, 1024)
	binary.LittleEndian.PutUint32(b[0x04:0x08], uint32(blockCount))
	binary.LittleEndian.PutUint32(b[0x150:0x154], uint32(blockCount>>32))
	binary.LittleEndian.PutUint32(b[0x0c:0x10], uint32(freeBlocks))
	binary.LittleEndian.PutUint32(b[0x158:0x15c], uint32(freeBlocks>>32))
	binary.LittleEndian.PutUint32(b[0x18:0x1c], logBlockSize)
	binary.LittleEndian.PutUint16(b[0x38:0x3a], 0xEF53)
	if _, err := f.WriteAt(b, int64(partOffset)+1024); err != nil {
		t.Fatalf("write superblock: %v", err)
	}
}

func TestSpaceToShrinkExt(t *testing.T) {
	const blockSize = 4096
	const total = 100 * GiB
	blockCount := uint64(total / blockSize)
	// 30 GB free
	freeBlocks := uint64(30 * GiB / blockSize)

	// 100 GiB total, 30 GiB free => 70 GiB used. Freeing 22 GiB leaves a 78 GiB
	// target at ~89.7% full.
	cases := []struct {
		name       string
		partOffset int64
		need       int64
		maxFull    int
		want       bool
	}{
		{"22G need, 78G target ~89% full, max 90 -> ok", 0, 22 * GiB, 90, true},
		{"same at a partition offset", 17 << 20, 22 * GiB, 90, true},
		{"22G need, ~89% full, max 85 -> too full", 0, 22 * GiB, 85, false},
		{"30G need, 70G target 100% full -> too full", 0, 30 * GiB, 90, false},
		{"80G need, target below used -> reject", 0, 80 * GiB, 90, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "p3.img")
			writeFakeSuperblock(t, path, uint32(c.partOffset), 2 /*4096*/, blockCount, freeBlocks)
			sr, err := SpaceToShrinkExt(path, c.partOffset, c.need, c.maxFull)
			if err != nil {
				t.Fatalf("SpaceToShrinkExt: %v", err)
			}
			if sr.OK != c.want {
				t.Errorf("OK = %v, want %v (result %d%% full of %d)", sr.OK, c.want, sr.ResultPercent, sr.TargetBytes)
			}
			if sr.BlockSize != blockSize {
				t.Errorf("BlockSize = %d, want %d", sr.BlockSize, blockSize)
			}
		})
	}
}

// TestSpaceToShrinkExtMargin exercises the shrink-floor margin as the binding
// constraint on a small partition, where it rejects a shrink the fullness cap
// alone would have allowed. 32 GiB total, freeing 22 GiB -> 10 GiB target; the
// margin there is ~2.65 GiB (2177 MiB + 1.639% of 32 GiB), so the floor estimate
// is used + ~2.65 GiB. At 8 GiB used the result is only 80% full (under the 90%
// cap) yet the 10 GiB target is below the ~10.65 GiB floor, so the shrink must be
// rejected; at 7 GiB used it clears both.
func TestSpaceToShrinkExtMargin(t *testing.T) {
	const blockSize = 4096
	const total = 32 * GiB
	blockCount := uint64(total / blockSize)
	cases := []struct {
		name    string
		usedGiB int64
		need    int64
		maxFull int
		want    bool
	}{
		{"8G used, margin binds though only 80% full -> reject", 8, 22 * GiB, 90, false},
		{"7G used, clears floor and fullness -> ok", 7, 22 * GiB, 90, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "p3.img")
			freeBlocks := uint64((total - c.usedGiB*GiB) / blockSize)
			writeFakeSuperblock(t, path, 0, 2 /*4096*/, blockCount, freeBlocks)
			sr, err := SpaceToShrinkExt(path, 0, c.need, c.maxFull)
			if err != nil {
				t.Fatalf("SpaceToShrinkExt: %v", err)
			}
			if sr.OK != c.want {
				t.Errorf("OK = %v, want %v (used %dG, target %dB, floorEst %dB, %d%% full)",
					sr.OK, c.want, c.usedGiB, sr.TargetBytes, sr.FloorEstBytes, sr.ResultPercent)
			}
		})
	}
}

// TestReadExt4SuperblockReal validates the parser against a real mkfs.ext4 image
// (no root/loop needed — mkfs.ext4 works on a regular file).
func TestReadExt4SuperblockReal(t *testing.T) {
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("mkfs.ext4 not available")
	}
	path := filepath.Join(t.TempDir(), "ext4.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = f.Truncate(64 << 20)
	_ = f.Close()
	if out, err := exec.Command("mkfs.ext4", "-F", "-q", path).CombinedOutput(); err != nil {
		t.Fatalf("mkfs.ext4: %v\n%s", err, out)
	}
	sb, err := readExt4Superblock(path, 0)
	if err != nil {
		t.Fatalf("readExt4Superblock: %v", err)
	}
	if sb.blockSize != 1024 && sb.blockSize != 4096 {
		t.Errorf("blockSize = %d, want 1024 or 4096", sb.blockSize)
	}
	total := sb.blockCount * sb.blockSize
	if total < 60<<20 || total > 64<<20 {
		t.Errorf("total = %d, want ~64 MiB", total)
	}
	if sb.freeBlocks <= 0 || sb.freeBlocks >= sb.blockCount {
		t.Errorf("freeBlocks = %d, want 0 < free < %d", sb.freeBlocks, sb.blockCount)
	}
}

func TestParseSize(t *testing.T) {
	cases := map[string]int64{
		"512": 512, "22G": 22 * GiB, "300M": 300 << 20, "36M": 36 << 20, "1T": 1 << 40,
	}
	for in, want := range cases {
		got, err := parseSize(in)
		if err != nil {
			t.Fatalf("parseSize(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("parseSize(%q) = %d, want %d", in, got, want)
		}
	}
}
