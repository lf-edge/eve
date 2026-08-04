// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/utils"
	"github.com/sirupsen/logrus"
)

// liveUploadsSubdir holds uploaded-but-not-yet-installed live images. A sibling
// of templates/ so the template sweep never sees a partial upload.
const liveUploadsSubdir = ".live-uploads"

// liveUploadsDir is where staged live image uploads (and their in-progress
// ".part" files) live, under the broker's image dir.
func liveUploadsDir(imageDir string) string {
	return filepath.Join(imageDir, liveUploadsSubdir)
}

// liveUploadPath is where an uploaded live image tar is staged before install.
func liveUploadPath(imageDir, sha string) string {
	return filepath.Join(liveUploadsDir(imageDir), sha+".tar")
}

// removeStaleLiveUploads deletes every staged live-image upload -- both
// completed tars and in-progress ".part" files -- left behind by a killed
// broker, or by a client that aborted before a successful BuildImage retry
// ever consumed and removed the tar. Called once at startup, alongside
// removeStaleTmpDirs. A non-owner broker must skip this: the uploads it would
// sweep may belong to another broker's upload currently in progress, not to a
// killed one.
func (c *templateCache) removeStaleLiveUploads() error {
	if !c.owner {
		return nil
	}
	dir := liveUploadsDir(c.imageDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read live upload dir %q: %w", dir, err)
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if err := os.RemoveAll(path); err != nil {
			c.log.Warnf("Failed to remove stale live image upload %q: %v", path, err)
			continue
		}
		c.log.Infof("Removed stale live image upload %q", path)
	}
	return nil
}

// localLiveSourceUsable reports whether the broker can install a template by
// reading the client's own live image files, skipping the upload entirely. True
// only when the broker and the client share a filesystem, which is not
// something the client can be asked: it is decided here, by looking.
//
// Every reason to say no is benign -- the caller then reports
// missing_eve_live_image and the client uploads exactly as it always has -- so
// this is deliberately strict and silent. The size check is what keeps a
// mismatch cheap: without it, a same-path-different-content file on a remote
// broker would be read in full only to fail the hash.
func localLiveSourceUsable(log *logrus.Entry, src *api.LocalLiveImageSource) bool {
	if src == nil {
		return false
	}
	// A relative path would resolve against the broker's working directory,
	// which has nothing to do with the client's.
	for _, p := range []string{
		src.GetDiskPath(), src.GetConfigImgPath(), src.GetFirmwareDir()} {
		if p == "" || !filepath.IsAbs(p) {
			return false
		}
	}
	disk, err := os.Stat(src.GetDiskPath())
	if err != nil || !disk.Mode().IsRegular() {
		log.Debugf("Live image %q is not readable here, taking the upload: %v",
			src.GetDiskPath(), err)
		return false
	}
	if uint64(disk.Size()) != src.GetDiskBytes() {
		log.Debugf("Live image %q is %d bytes here, client declared %d, "+
			"taking the upload",
			src.GetDiskPath(), disk.Size(), src.GetDiskBytes())
		return false
	}
	cfg, err := os.Stat(src.GetConfigImgPath())
	if err != nil || !cfg.Mode().IsRegular() {
		log.Debugf("Config image %q is not readable here, taking the upload: %v",
			src.GetConfigImgPath(), err)
		return false
	}
	fw, err := os.Stat(src.GetFirmwareDir())
	if err != nil || !fw.IsDir() {
		log.Debugf("Firmware dir %q is not readable here, taking the upload: %v",
			src.GetFirmwareDir(), err)
		return false
	}
	return true
}

// installLocalLiveTemplate returns a templateBuilder that installs a template
// straight from the client's own files, for a broker that shares the client's
// filesystem (all-in-one mode, or a broker run by hand on the developer's
// machine). The alternative is a client streaming a 2 GB tar to a process that
// could already open the file, then the broker writing those bytes twice --
// once as the staged tar, once as the template.
//
// The disk is still hashed against wantSHA256, for the same reason the upload
// path hashes it: the hash is the template's cache key, so installing content
// that does not match it would serve the wrong EVE build to every later run
// that asks for that key. Hashing is nearly free here because the bytes are
// being read for the copy anyway -- what it rules out is a stale client-side
// hash (an in-place `LIVE_UPDATE=1 make live` rebuild that happens to land on
// the same file size), not a corrupted transfer.
func installLocalLiveTemplate(
	src *api.LocalLiveImageSource, wantSHA256 string) templateBuilder {

	return func(ctx context.Context, log *logrus.Entry, dstDir string) (gptPartition, error) {
		var none gptPartition

		diskPath := filepath.Join(dstDir, templateDiskFile)
		gotSHA256, err := copyAndHash(src.GetDiskPath(), diskPath)
		if err != nil {
			return none, err
		}
		if gotSHA256 != wantSHA256 {
			return none, fmt.Errorf(
				"local live image %q hash mismatch: got %s, want %s",
				src.GetDiskPath(), gotSHA256, wantSHA256)
		}
		if err := utils.CopyFile(src.GetConfigImgPath(),
			filepath.Join(dstDir, templateConfigImgFile)); err != nil {
			return none, fmt.Errorf("failed to copy the config image %q: %w",
				src.GetConfigImgPath(), err)
		}
		if err := utils.CopyFolder(src.GetFirmwareDir(),
			filepath.Join(dstDir, templateFirmwareDir)); err != nil {
			return none, fmt.Errorf("failed to copy the firmware dir %q: %w",
				src.GetFirmwareDir(), err)
		}

		head, err := readDiskHead(ctx, diskPath)
		if err != nil {
			return none, fmt.Errorf("failed to read GPT of %q: %w", diskPath, err)
		}
		part, err := findGPTPartition(head, gptConfigPartName)
		if err != nil {
			return none, fmt.Errorf("failed to locate the CONFIG partition in %q: %w",
				diskPath, err)
		}
		log.Infof("Installed EVE live image template by reading %q in place "+
			"(no upload): CONFIG partition at offset %d, length %d",
			src.GetDiskPath(), part.Offset, part.Length)
		return part, nil
	}
}

// copyAndHash copies srcPath to dstPath and returns the hex sha256 of the bytes
// copied, hashing as it writes so the file is read only once.
func copyAndHash(srcPath, dstPath string) (string, error) {
	in, err := os.Open(srcPath)
	if err != nil {
		return "", fmt.Errorf("failed to open %q: %w", srcPath, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", fmt.Errorf("failed to create %q: %w", dstPath, err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, hasher), in); err != nil {
		out.Close()
		return "", fmt.Errorf("failed to copy %q to %q: %w", srcPath, dstPath, err)
	}
	if err := out.Close(); err != nil {
		return "", fmt.Errorf("failed to write %q: %w", dstPath, err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// liveTemplateMembers maps every member an uploaded live image may contain to
// the path it is written to, relative to the template directory. The values are
// this package's own constants, so an entry's name only ever selects a
// destination and never builds one: an archive is attacker-shaped input, and a
// name that cannot reach a file operation cannot direct one out of the template
// directory however the ".." components in it are spelled.
//
// The firmware members are the files the device providers actually consume
// (qemu and libvirt both open OVMF_CODE.fd and OVMF_VARS.fd, and
// resolveLocalLiveImage requires all three); anything else a build happens to
// leave in its firmware directory is unused, so it is skipped rather than
// installed.
var liveTemplateMembers = map[string]string{
	templateDiskFile:                      templateDiskFile,
	templateConfigImgFile:                 templateConfigImgFile,
	templateFirmwareDir + "/OVMF.fd":      templateFirmwareDir + "/OVMF.fd",
	templateFirmwareDir + "/OVMF_CODE.fd": templateFirmwareDir + "/OVMF_CODE.fd",
	templateFirmwareDir + "/OVMF_VARS.fd": templateFirmwareDir + "/OVMF_VARS.fd",
}

// unpackLiveTemplate returns a templateBuilder that installs a template from an
// uploaded tar instead of building one with the EVE container. Everything the
// container path produces is already in the tar, because `make live` emits
// live.qcow2, config.img and the OVMF firmware as separate files.
//
// wantSHA256 is the hash the client declared for disk.qcow2 -- the same value
// that was used to compute the template's cache key and the upload's path on
// disk. It is verified against the bytes actually received, not merely
// asserted by the client: the cache key, the tar's storage path and the
// content itself must all agree, or a mismatched or corrupted upload would
// otherwise be installed as if it were the image the client claimed.
func unpackLiveTemplate(tarPath, wantSHA256 string) templateBuilder {
	return func(ctx context.Context, log *logrus.Entry, dstDir string) (gptPartition, error) {
		var none gptPartition

		f, err := os.Open(tarPath)
		if err != nil {
			return none, fmt.Errorf("failed to open the uploaded live image %q: %w",
				tarPath, err)
		}
		defer f.Close()

		dstDir, err = filepath.Abs(dstDir)
		if err != nil {
			return none, fmt.Errorf("failed to resolve the destination directory %q: %w",
				dstDir, err)
		}
		dstDir = filepath.Clean(dstDir)

		seen := map[string]bool{}
		diskHasher := sha256.New()
		tr := tar.NewReader(f)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return none, fmt.Errorf("failed to read the uploaded live image: %w", err)
			}
			clean := filepath.Clean(hdr.Name)
			dest, expected := liveTemplateMembers[clean]
			if !expected {
				// Nothing outside the table is installed, so an escape is already
				// impossible; it is still called out rather than skipped quietly,
				// because a legitimate upload has no reason to contain one.
				if filepath.IsAbs(hdr.Name) || clean == ".." ||
					strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
					return none, fmt.Errorf("upload contains an unsafe path %q", hdr.Name)
				}
				log.Debugf("Ignoring unexpected member %q in the uploaded live image",
					hdr.Name)
				continue
			}
			// Every table entry names a file, so a directory carrying one of those
			// names is malformed rather than something to create.
			if hdr.Typeflag == tar.TypeDir {
				return none, fmt.Errorf("upload member %q is a directory, expected a file",
					hdr.Name)
			}
			target := filepath.Join(dstDir, dest)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return none, err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return none, err
			}
			// The 2 GB disk image is hashed as it is written, not re-read
			// afterwards: a second pass over the whole file would double the
			// I/O this check costs.
			var dst io.Writer = out
			if dest == templateDiskFile {
				dst = io.MultiWriter(out, diskHasher)
			}
			if _, err := io.Copy(dst, tr); err != nil {
				out.Close()
				return none, fmt.Errorf("failed to write %q: %w", target, err)
			}
			if err := out.Close(); err != nil {
				return none, err
			}
			seen[dest] = true
		}

		for _, required := range []string{templateDiskFile, templateConfigImgFile} {
			if !seen[required] {
				return none, fmt.Errorf("upload is missing %q", required)
			}
		}

		if gotSHA256 := hex.EncodeToString(diskHasher.Sum(nil)); gotSHA256 != wantSHA256 {
			return none, fmt.Errorf(
				"uploaded live image disk hash mismatch: got %s, want %s",
				gotSHA256, wantSHA256)
		}

		diskPath := filepath.Join(dstDir, templateDiskFile)
		head, err := readDiskHead(ctx, diskPath)
		if err != nil {
			return none, fmt.Errorf("failed to read GPT of %q: %w", diskPath, err)
		}
		part, err := findGPTPartition(head, gptConfigPartName)
		if err != nil {
			return none, fmt.Errorf("failed to locate the CONFIG partition in %q: %w",
				diskPath, err)
		}
		log.Infof("Installed EVE live image template from the uploaded tar: "+
			"CONFIG partition at offset %d, length %d", part.Offset, part.Length)
		return part, nil
	}
}
