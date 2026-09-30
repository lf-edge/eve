// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
)

// CreateRandomImageFile creates a file of sizeBytes random bytes, served by
// evetest's built-in image server (see AddImageServerFile), and returns its
// filename (for ImageRelativePath) together with the hex-encoded SHA256 of
// its content (for ImageSHA256).
//
// Random (non-blank) content makes ImageSHA256 verification meaningful: a
// blank file's checksum can't distinguish "downloaded correctly" from
// "downloaded as all zeros/corrupted-but-still-blank" -- a corrupted
// download of random content is vanishingly unlikely to still match the
// checksum computed here.
func CreateRandomImageFile(name string, sizeBytes uint64) (relativePath, sha256Hex string) {
	th := getTestHarness()
	content := make([]byte, sizeBytes)
	if _, err := rand.Read(content); err != nil {
		th.t.Fatalf("failed to generate random content for %s: %v", name, err)
	}
	sum := sha256.Sum256(content)
	relativePath = AddImageServerFile(name, content)
	return relativePath, hex.EncodeToString(sum[:])
}

// AddImageServerFile writes content to a file served by evetest's built-in
// image server, returning its filename for use as HTTPStorage.ImageRelativePath.
func AddImageServerFile(name string, content []byte) string {
	th := getTestHarness()
	path := filepath.Join(th.imgServerDir, name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		th.t.Fatalf("failed to write image server file %s: %v", name, err)
	}
	return name
}
