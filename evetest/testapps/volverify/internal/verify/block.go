// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package verify implements the two-layer self-verifying fill/delete pattern used
// to detect application-volume corruption caused by a watchdog-interrupted
// EVE-kvm→EVE-k offline filesystem shrink (design: kvm-to-k-appvol-shrink-soak).
//
// Layer 1 (this file) gives every on-disk block content that is a pure function
// of the file's *logical* identity — (fileID, logical block index within the
// file), never the physical disk placement. Physical placement changes by design
// when resize2fs relocates the P3 tail, so the verifier reads a file back through
// the filesystem and checks that each logical block still yields the bytes its
// identity implies. A block that reads back as another file's or another index's
// content (an extent tree torn during relocation) is caught by the identity in
// its header.
package verify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
)

const (
	// blockMagic marks a well-formed block header ("VVB1" little-endian).
	blockMagic = 0x31425656
	// headerLen is the fixed prefix each block reserves for its header.
	headerLen = 32
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// deriveKey returns the 16-byte AES key for a file's block content. It is a pure
// function of fileID, so a block's expected bytes depend only on file identity
// and logical index — never on stored state, so no content manifest is needed.
func deriveKey(fileID uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], fileID)
	sum := sha256.Sum256(append([]byte("volverify-key-v1"), b[:]...))
	return sum[:16]
}

// blockBody fills dst with the deterministic, incompressible, non-zero body for
// (fileID, blockIndex): an AES-CTR keystream over zeros. blockIndex occupies the
// high half of the IV so per-block counter ranges never overlap.
func blockBody(fileID, blockIndex uint64, dst []byte) {
	blk, err := aes.NewCipher(deriveKey(fileID))
	if err != nil {
		panic(err) // deriveKey always yields a valid 16-byte key
	}
	var iv [aes.BlockSize]byte
	binary.BigEndian.PutUint64(iv[0:8], blockIndex)
	ctr := cipher.NewCTR(blk, iv[:])
	for i := range dst {
		dst[i] = 0
	}
	ctr.XORKeyStream(dst, dst)
}

// BuildBlock returns a blockSize-byte block for the logical (fileID, blockIndex).
func BuildBlock(fileID, blockIndex uint64, blockSize int) []byte {
	buf := make([]byte, blockSize)
	body := buf[headerLen:]
	blockBody(fileID, blockIndex, body)
	binary.LittleEndian.PutUint32(buf[0:4], blockMagic)
	binary.LittleEndian.PutUint64(buf[4:12], fileID)
	binary.LittleEndian.PutUint64(buf[12:20], blockIndex)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(len(body)))
	binary.LittleEndian.PutUint32(buf[24:28], crc32.Checksum(body, castagnoli))
	binary.LittleEndian.PutUint32(buf[28:32], crc32.Checksum(buf[0:28], castagnoli))
	return buf
}

// BlockStatus classifies one on-disk block against its expected logical identity.
type BlockStatus int

const (
	// BlockOK means the block content matches the expected keystream.
	BlockOK BlockStatus = iota
	// BlockZeroed means the block is all zero — fsck cleared it or a torn/short write.
	BlockZeroed
	// BlockGarbage means there is no valid header (bad magic/header-CRC/length).
	BlockGarbage
	// BlockMisplaced means a valid header carrying another file's or index's identity.
	BlockMisplaced
	// BlockTorn means the header is intact but the body CRC disagrees with the body.
	BlockTorn
	// BlockAltered means the block is self-consistent but its body != expected keystream.
	BlockAltered
)

func (s BlockStatus) String() string {
	switch s {
	case BlockOK:
		return "ok"
	case BlockZeroed:
		return "zeroed"
	case BlockGarbage:
		return "garbage"
	case BlockMisplaced:
		return "misplaced"
	case BlockTorn:
		return "torn"
	case BlockAltered:
		return "altered"
	}
	return "unknown"
}

// BlockResult is a classified block plus, for a misplaced block, the logical
// identity its header actually carried (so cross-file smearing can be traced).
type BlockResult struct {
	Status     BlockStatus
	FoundFile  uint64
	FoundIndex uint64
}

// parseHeader extracts a block's declared logical identity. ok is false when the
// block has no usable header (bad magic, header-CRC mismatch, or wrong body length).
func parseHeader(buf []byte, blockSize int) (fileID, blockIndex uint64, ok bool) {
	if len(buf) < headerLen {
		return 0, 0, false
	}
	if binary.LittleEndian.Uint32(buf[0:4]) != blockMagic {
		return 0, 0, false
	}
	if binary.LittleEndian.Uint32(buf[28:32]) != crc32.Checksum(buf[0:28], castagnoli) {
		return 0, 0, false
	}
	if int(binary.LittleEndian.Uint32(buf[20:24])) != blockSize-headerLen {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint64(buf[4:12]), binary.LittleEndian.Uint64(buf[12:20]), true
}

// VerifyBlock classifies buf against the block expected at logical (expFile, expIndex).
func VerifyBlock(buf []byte, expFile, expIndex uint64, blockSize int) BlockResult {
	if isZero(buf) {
		return BlockResult{Status: BlockZeroed}
	}
	fid, bidx, ok := parseHeader(buf, blockSize)
	if !ok {
		return BlockResult{Status: BlockGarbage}
	}
	if fid != expFile || bidx != expIndex {
		return BlockResult{Status: BlockMisplaced, FoundFile: fid, FoundIndex: bidx}
	}
	body := buf[headerLen:]
	if binary.LittleEndian.Uint32(buf[24:28]) != crc32.Checksum(body, castagnoli) {
		return BlockResult{Status: BlockTorn}
	}
	exp := make([]byte, len(body))
	blockBody(expFile, expIndex, exp)
	if !bytesEqual(exp, body) {
		return BlockResult{Status: BlockAltered}
	}
	return BlockResult{Status: BlockOK}
}

// headerFileID reports the file identity a block claims, for the lost+found scan
// (design §4.3): an orphaned file is identified by reading its first block header.
func headerFileID(buf []byte, blockSize int) (uint64, bool) {
	fid, _, ok := parseHeader(buf, blockSize)
	return fid, ok
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
