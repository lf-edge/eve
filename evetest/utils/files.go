// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// ResolveFile returns the absolute path of the given file after verifying that
// it exists and is accessible. It returns an error if the path is empty,
// cannot be resolved, or does not exist.
func ResolveFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path %q: %w", path, err)
	}
	if _, err := os.Stat(abs); err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("path does not exist: %q", abs)
		}
		return "", fmt.Errorf("failed to stat path %q: %w", abs, err)
	}
	return abs, nil
}

// CopyFile copy file from src to dst with same permission
func CopyFile(src string, dst string) (err error) {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(dst); os.IsNotExist(err) {
		if err = os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		//follow symlinks
		src, err = os.Readlink(src)
		if err != nil {
			return err
		}
		src = filepath.Join(filepath.Dir(src), filepath.Base(src))
	}
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}

// FileHashAndSize computes the SHA-256 hex digest and byte size of the file at path.
func FileHashAndSize(path string) (sha256hex string, size int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// CopyFolder from source to destination
func CopyFolder(source, destination string) error {
	srcInfo, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("source is not a directory")
	}
	// Ensure destination root exists
	if err := os.MkdirAll(destination, srcInfo.Mode()); err != nil {
		return err
	}
	return filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}
		dstPath := filepath.Join(destination, relPath)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}
		return CopyFile(path, dstPath)
	})
}
