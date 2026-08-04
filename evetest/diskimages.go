// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	eveconfig "github.com/lf-edge/eve-api/go/config"
)

// CreateBlankImageFile creates an empty disk image of the given format and
// size, served by evetest's built-in image server (both over HTTP and
// SFTP), and returns its filename (for ImageRelativePath) together with the
// hex-encoded SHA256 of the resulting file's content (for ImageSHA256).
//
// Requires qemu-img to be available inside the evetest container (already a
// build dependency of the broker).
func CreateBlankImageFile(
	name string, format eveconfig.Format, sizeBytes uint64) (relativePath, sha256Hex string) {
	th := getTestHarness()
	formatStr, ok := qemuImgFormat(format)
	if !ok {
		th.t.Fatalf(
			"unsupported disk image format for CreateBlankImageFile: %v", format)
	}
	path := filepath.Join(th.imgServerDir, name)
	cmd := exec.Command("qemu-img", "create", "-f", formatStr,
		path, strconv.FormatUint(sizeBytes, 10))
	if out, err := cmd.CombinedOutput(); err != nil {
		th.t.Fatalf("qemu-img create -f %s %s %d failed: %v: %s",
			formatStr, path, sizeBytes, err, out)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		th.t.Fatalf("failed to read back created disk image %s: %v", path, err)
	}
	sum := sha256.Sum256(content)
	return name, hex.EncodeToString(sum[:])
}

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
// image server (both over HTTP and SFTP), returning its filename for use as
// HTTPStorage.ImageRelativePath / SFTPStorage.ImageRelativePath.
func AddImageServerFile(name string, content []byte) string {
	th := getTestHarness()
	path := filepath.Join(th.imgServerDir, name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		th.t.Fatalf("failed to write image server file %s: %v", name, err)
	}
	return name
}

// qemuImgFormat maps an eveconfig.Format to the "-f" format name accepted by
// qemu-img.
func qemuImgFormat(format eveconfig.Format) (string, bool) {
	switch format {
	case eveconfig.Format_RAW:
		return "raw", true
	case eveconfig.Format_QCOW:
		return "qcow", true
	case eveconfig.Format_QCOW2:
		return "qcow2", true
	case eveconfig.Format_VHD:
		return "vpc", true // qemu-img calls the VHD format "vpc"
	case eveconfig.Format_VMDK:
		return "vmdk", true
	case eveconfig.Format_VHDX:
		return "vhdx", true
	default:
		return "", false
	}
}
