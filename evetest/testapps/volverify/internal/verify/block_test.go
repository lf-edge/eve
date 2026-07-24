// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verify

import "testing"

const testBlockSize = 256

func TestBlockRoundTrip(t *testing.T) {
	b := BuildBlock(7, 3, testBlockSize)
	if res := VerifyBlock(b, 7, 3, testBlockSize); res.Status != BlockOK {
		t.Fatalf("roundtrip: got %v, want ok", res.Status)
	}
	// The body must be non-zero and reproducible.
	b2 := BuildBlock(7, 3, testBlockSize)
	if !bytesEqual(b, b2) {
		t.Fatal("block content not reproducible for same identity")
	}
	if isZero(b[headerLen:]) {
		t.Fatal("block body is all-zero")
	}
}

func TestBlockZeroed(t *testing.T) {
	b := make([]byte, testBlockSize)
	if res := VerifyBlock(b, 1, 0, testBlockSize); res.Status != BlockZeroed {
		t.Fatalf("got %v, want zeroed", res.Status)
	}
}

func TestBlockGarbage(t *testing.T) {
	b := BuildBlock(1, 0, testBlockSize)
	b[1] ^= 0xff // corrupt the magic
	if res := VerifyBlock(b, 1, 0, testBlockSize); res.Status != BlockGarbage {
		t.Fatalf("got %v, want garbage", res.Status)
	}
}

func TestBlockMisplaced(t *testing.T) {
	// A block written for file 9 read where file 1 is expected.
	b := BuildBlock(9, 0, testBlockSize)
	res := VerifyBlock(b, 1, 0, testBlockSize)
	if res.Status != BlockMisplaced || res.FoundFile != 9 {
		t.Fatalf("got %v foundFile=%d, want misplaced foundFile=9", res.Status, res.FoundFile)
	}
	// Same file, wrong index is also misplaced.
	b2 := BuildBlock(1, 5, testBlockSize)
	if res := VerifyBlock(b2, 1, 0, testBlockSize); res.Status != BlockMisplaced || res.FoundIndex != 5 {
		t.Fatalf("got %v foundIndex=%d, want misplaced foundIndex=5", res.Status, res.FoundIndex)
	}
}

func TestBlockTorn(t *testing.T) {
	b := BuildBlock(1, 0, testBlockSize)
	// Flip a body byte without updating the body CRC: the header still parses.
	b[headerLen+10] ^= 0xff
	if res := VerifyBlock(b, 1, 0, testBlockSize); res.Status != BlockTorn {
		t.Fatalf("got %v, want torn", res.Status)
	}
}

func TestBlockHeaderFileID(t *testing.T) {
	b := BuildBlock(42, 0, testBlockSize)
	if id, ok := headerFileID(b, testBlockSize); !ok || id != 42 {
		t.Fatalf("got id=%d ok=%v, want 42 true", id, ok)
	}
}
