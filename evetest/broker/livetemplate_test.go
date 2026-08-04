// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/sirupsen/logrus"
)

// writeLiveTar builds an upload tar with the given members.
func writeLiveTar(t *testing.T, path string, members map[string][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tar: %v", err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	for name, data := range members {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(data)),
		}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
}

// qcow2FromRaw wraps raw bytes into a real qcow2 image via qemu-img, the same
// tool unpackLiveTemplate's readDiskHead shells out to. Tests that exercise
// the full path (including the GPT read) need disk.qcow2 to actually be
// qcow2-formatted, not just GPT-shaped raw bytes.
func qcow2FromRaw(t *testing.T, raw []byte) []byte {
	t.Helper()
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw.bin")
	if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
		t.Fatalf("write raw fixture: %v", err)
	}
	qcowPath := filepath.Join(dir, "disk.qcow2")
	out, err := exec.Command("qemu-img", "convert",
		"-f", "raw", "-O", "qcow2", rawPath, qcowPath).CombinedOutput()
	if err != nil {
		t.Fatalf("qemu-img convert: %v: %s", err, out)
	}
	data, err := os.ReadFile(qcowPath)
	if err != nil {
		t.Fatalf("read converted qcow2: %v", err)
	}
	return data
}

func liveTarMembers(t *testing.T) map[string][]byte {
	t.Helper()
	head, err := os.ReadFile("testdata/gpt-head-live.bin")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return map[string][]byte{
		templateDiskFile:                              qcow2FromRaw(t, head),
		templateConfigImgFile:                         make([]byte, 5<<20),
		filepath.Join(templateFirmwareDir, "OVMF.fd"): []byte("fw"),
	}
}

// liveTarDiskSHA256 computes the hash unpackLiveTemplate is expected to verify
// disk.qcow2 against, from the same bytes a test tar was built from.
func liveTarDiskSHA256(members map[string][]byte) string {
	sum := sha256.Sum256(members[templateDiskFile])
	return hex.EncodeToString(sum[:])
}

func TestUnpackLiveTemplateRejectsMissingMember(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "u.tar")
	members := liveTarMembers(t)
	wantSHA256 := liveTarDiskSHA256(members)
	delete(members, templateConfigImgFile)
	writeLiveTar(t, tarPath, members)

	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	_, err := unpackLiveTemplate(tarPath, wantSHA256)(context.Background(), log, t.TempDir())
	if err == nil {
		t.Fatal("expected an error when config.img is absent from the upload")
	}
}

func TestUnpackLiveTemplateRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "u.tar")
	writeLiveTar(t, tarPath, map[string][]byte{"../escape": []byte("x")})

	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	dst := t.TempDir()
	_, err := unpackLiveTemplate(tarPath, strings.Repeat("0", 64))(context.Background(), log, dst)
	if err == nil {
		t.Fatal("expected an error for a tar member escaping the destination")
	}
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(dst), "escape")); statErr == nil {
		t.Fatal("a tar member was written outside the destination directory")
	}
}

func TestUnpackLiveTemplateRejectsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "u.tar")
	writeLiveTar(t, tarPath, map[string][]byte{"/etc/passwd": []byte("x")})

	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	dst := t.TempDir()
	_, err := unpackLiveTemplate(tarPath, strings.Repeat("0", 64))(context.Background(), log, dst)
	if err == nil {
		t.Fatal("expected an error for a tar member with an absolute path")
	}
	if _, statErr := os.Stat(filepath.Join(dst, "etc", "passwd")); statErr == nil {
		t.Fatal("a tar member with an absolute path was written")
	}
}

// TestUnpackLiveTemplateVerifiesDiskHash covers the success path: a correctly
// hashed upload must install cleanly and report the CONFIG partition location.
func TestUnpackLiveTemplateVerifiesDiskHash(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "u.tar")
	members := liveTarMembers(t)
	writeLiveTar(t, tarPath, members)
	wantSHA256 := liveTarDiskSHA256(members)

	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	part, err := unpackLiveTemplate(tarPath, wantSHA256)(context.Background(), log, t.TempDir())
	if err != nil {
		t.Fatalf("unpackLiveTemplate: %v", err)
	}
	if part.Length == 0 {
		t.Error("expected a non-zero CONFIG partition length")
	}
}

// TestUnpackLiveTemplateRejectsHashMismatch covers the trust boundary this
// fix closes: the declared sha256 is the cache key and the storage path, but
// until this check it was never verified against the bytes actually received.
func TestUnpackLiveTemplateRejectsHashMismatch(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "u.tar")
	members := liveTarMembers(t)
	writeLiveTar(t, tarPath, members)

	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	wrongSHA256 := strings.Repeat("0", 64)
	if wrongSHA256 == liveTarDiskSHA256(members) {
		t.Fatal("test bug: wrongSHA256 collides with the real hash")
	}
	_, err := unpackLiveTemplate(tarPath, wrongSHA256)(context.Background(), log, t.TempDir())
	if err == nil {
		t.Fatal("expected an error for a disk hash mismatch")
	}
}

// writeLocalLiveSource lays out a client-side live build (live.qcow2,
// installer/config.img, installer/firmware/*) and returns the source message
// describing it plus the disk's real sha256.
func writeLocalLiveSource(t *testing.T, dir string) (*api.LocalLiveImageSource, string) {
	t.Helper()
	members := liveTarMembers(t)
	disk := members[templateDiskFile]
	diskPath := filepath.Join(dir, "live.qcow2")
	if err := os.WriteFile(diskPath, disk, 0o600); err != nil {
		t.Fatalf("write live.qcow2: %v", err)
	}
	cfgPath := filepath.Join(dir, "config.img")
	if err := os.WriteFile(cfgPath, members[templateConfigImgFile], 0o600); err != nil {
		t.Fatalf("write config.img: %v", err)
	}
	fwDir := filepath.Join(dir, "firmware")
	if err := os.MkdirAll(fwDir, 0o755); err != nil {
		t.Fatalf("mkdir firmware: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fwDir, "OVMF.fd"), []byte("fw"), 0o600); err != nil {
		t.Fatalf("write OVMF.fd: %v", err)
	}
	return &api.LocalLiveImageSource{
		DiskPath:      diskPath,
		DiskBytes:     uint64(len(disk)),
		ConfigImgPath: cfgPath,
		FirmwareDir:   fwDir,
	}, liveTarDiskSHA256(members)
}

// TestLocalLiveSourceUsable covers the decision that replaces an upload with a
// direct read. Every rejection must be a plain false, not an error: the caller
// falls back to the upload, which is always correct if slower.
func TestLocalLiveSourceUsable(t *testing.T) {
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	src, _ := writeLocalLiveSource(t, t.TempDir())

	if !localLiveSourceUsable(log, src) {
		t.Fatal("expected a complete local source to be usable")
	}
	if localLiveSourceUsable(log, nil) {
		t.Error("expected a nil source to be unusable")
	}

	tests := []struct {
		name   string
		mutate func(*api.LocalLiveImageSource)
	}{
		{"relative disk path", func(s *api.LocalLiveImageSource) {
			s.DiskPath = "dist/live.qcow2"
		}},
		{"empty firmware dir", func(s *api.LocalLiveImageSource) {
			s.FirmwareDir = ""
		}},
		{"disk not present on this host", func(s *api.LocalLiveImageSource) {
			s.DiskPath = filepath.Join(t.TempDir(), "absent.qcow2")
		}},
		{"disk size disagrees", func(s *api.LocalLiveImageSource) {
			s.DiskBytes++
		}},
		{"config image absent", func(s *api.LocalLiveImageSource) {
			s.ConfigImgPath = filepath.Join(t.TempDir(), "absent.img")
		}},
		{"firmware dir is a file", func(s *api.LocalLiveImageSource) {
			s.FirmwareDir = s.ConfigImgPath
		}},
		{"disk is a directory", func(s *api.LocalLiveImageSource) {
			s.DiskPath = s.FirmwareDir
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			broken, _ := writeLocalLiveSource(t, t.TempDir())
			tt.mutate(broken)
			if localLiveSourceUsable(log, broken) {
				t.Errorf("expected %s to make the source unusable", tt.name)
			}
		})
	}
}

// TestInstallLocalLiveTemplate covers the success path: the template is
// populated from the client's own files, with no upload staged anywhere.
func TestInstallLocalLiveTemplate(t *testing.T) {
	src, wantSHA256 := writeLocalLiveSource(t, t.TempDir())
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)

	dst := t.TempDir()
	part, err := installLocalLiveTemplate(src, wantSHA256)(context.Background(), log, dst)
	if err != nil {
		t.Fatalf("installLocalLiveTemplate: %v", err)
	}
	if part.Length == 0 {
		t.Error("expected a non-zero CONFIG partition length")
	}
	for _, f := range []string{
		templateDiskFile,
		templateConfigImgFile,
		filepath.Join(templateFirmwareDir, "OVMF.fd"),
	} {
		if _, err := os.Stat(filepath.Join(dst, f)); err != nil {
			t.Errorf("template is missing %q: %v", f, err)
		}
	}
}

// TestInstallLocalLiveTemplateRejectsHashMismatch is why reading the client's
// file directly is safe: content that does not match the declared hash -- the
// template's cache key -- must never be installed under it, or every later run
// asking for that key silently gets the wrong EVE build.
func TestInstallLocalLiveTemplateRejectsHashMismatch(t *testing.T) {
	src, realSHA256 := writeLocalLiveSource(t, t.TempDir())
	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)

	wrongSHA256 := strings.Repeat("0", 64)
	if wrongSHA256 == realSHA256 {
		t.Fatal("test bug: wrongSHA256 collides with the real hash")
	}
	_, err := installLocalLiveTemplate(src, wrongSHA256)(
		context.Background(), log, t.TempDir())
	if err == nil {
		t.Fatal("expected an error for a local disk hash mismatch")
	}
}

// TestRemoveStaleLiveUploadsSweepsOwner covers a broker restarting on its own
// image directory: any staged tar or leftover ".part" file belongs to a
// session that did not survive the restart, so an owner must remove both.
func TestRemoveStaleLiveUploadsSweepsOwner(t *testing.T) {
	c := newTestCache(t)
	uploadsDir := liveUploadsDir(c.imageDir)
	if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	stagedTar := filepath.Join(uploadsDir, "abc.tar")
	if err := os.WriteFile(stagedTar, []byte("tar"), 0o600); err != nil {
		t.Fatalf("write staged tar: %v", err)
	}
	partFile := filepath.Join(uploadsDir, "abc.tar.deadbeef.part")
	if err := os.WriteFile(partFile, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write part file: %v", err)
	}

	if err := c.removeStaleLiveUploads(); err != nil {
		t.Fatalf("removeStaleLiveUploads: %v", err)
	}
	if _, err := os.Stat(stagedTar); !os.IsNotExist(err) {
		t.Error("owner did not remove the staged tar")
	}
	if _, err := os.Stat(partFile); !os.IsNotExist(err) {
		t.Error("owner did not remove the leftover .part file")
	}
}

// TestNonOwnerDoesNotRemoveStaleLiveUploads covers a second broker starting on
// a shared image directory: the staged tar or ".part" file it would sweep may
// belong to the owner's upload currently in progress, not to a killed one, so
// a non-owner must leave both alone. This is the half that actually matters --
// a method that deletes nothing at all would also pass a test that only checks
// the owner case.
func TestNonOwnerDoesNotRemoveStaleLiveUploads(t *testing.T) {
	imageDir := t.TempDir()
	log := logrus.New()
	log.SetOutput(io.Discard)

	owner := newTemplateCache(imageDir, log)
	if err := owner.tryLock(); err != nil {
		t.Fatalf("first tryLock must succeed: %v", err)
	}
	t.Cleanup(owner.unlock)

	second := newTemplateCache(imageDir, log)
	if err := second.tryLock(); err != nil {
		t.Fatalf("second tryLock must not error: %v", err)
	}
	if second.owner {
		t.Fatal("second cache claimed ownership while the first holds the lock")
	}

	uploadsDir := liveUploadsDir(imageDir)
	if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	stagedTar := filepath.Join(uploadsDir, "abc.tar")
	if err := os.WriteFile(stagedTar, []byte("tar"), 0o600); err != nil {
		t.Fatalf("write staged tar: %v", err)
	}
	partFile := filepath.Join(uploadsDir, "abc.tar.deadbeef.part")
	if err := os.WriteFile(partFile, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write part file: %v", err)
	}

	if err := second.removeStaleLiveUploads(); err != nil {
		t.Fatalf("removeStaleLiveUploads: %v", err)
	}
	if _, err := os.Stat(stagedTar); err != nil {
		t.Errorf("a non-owner removed another broker's staged tar: %v", err)
	}
	if _, err := os.Stat(partFile); err != nil {
		t.Errorf("a non-owner removed another broker's .part file: %v", err)
	}

	// The owner must still sweep both.
	if err := owner.removeStaleLiveUploads(); err != nil {
		t.Fatalf("owner removeStaleLiveUploads: %v", err)
	}
	if _, err := os.Stat(stagedTar); !os.IsNotExist(err) {
		t.Error("the owner failed to sweep the staged tar")
	}
	if _, err := os.Stat(partFile); !os.IsNotExist(err) {
		t.Error("the owner failed to sweep the .part file")
	}
}

// TestUnpackLiveTemplateRejectsRelocatedAbsolutePath guards the subtlety that
// filepath.Join(dst, "/etc/passwd") does not fail -- it quietly yields
// dst/etc/passwd. Rebuilding the destination from a verified relative path is
// what keeps an escape out, but on its own it would turn an absolute member into
// a silent relocation instead of a rejection.
func TestUnpackLiveTemplateRejectsRelocatedAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "u.tar")
	writeLiveTar(t, tarPath, map[string][]byte{"/etc/passwd": []byte("x")})

	log := logrus.NewEntry(logrus.New())
	log.Logger.SetOutput(io.Discard)
	dst := t.TempDir()
	_, err := unpackLiveTemplate(tarPath, strings.Repeat("0", 64))(
		context.Background(), log, dst)
	if err == nil {
		t.Fatal("expected an error for an absolute tar member")
	}
	if _, statErr := os.Stat(filepath.Join(dst, "etc", "passwd")); statErr == nil {
		t.Error("an absolute member was relocated under the destination " +
			"instead of being rejected")
	}
}
