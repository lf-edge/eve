// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// MaxDecompressedContentSize is the maximum size of a file that can be written to disk after decompression.
// This is to prevent a DoS attack by unpacking a compressed file that is too big to be decompressed.
const MaxDecompressedContentSize = 1024 * 1024 * 1024 // 1 GB

// ExtractFromTar extracts files from a tar reader into the destination directory
func ExtractFromTar(u io.Reader, destination string) error {
	cleanDestination := path.Clean(destination)
	// path inside tar must remain relative and contained within destination
	safePath := func(oldPath string) (string, error) {
		if oldPath == "" {
			return "", fmt.Errorf("empty archive path")
		}
		cleanOldPath := path.Clean(oldPath)
		if cleanOldPath == "." || strings.HasPrefix(cleanOldPath, "..") || strings.Contains(cleanOldPath, "/..") || path.IsAbs(cleanOldPath) {
			return "", fmt.Errorf("invalid archive path: %s", oldPath)
		}
		fullPath := path.Clean(path.Join(cleanDestination, cleanOldPath))
		if fullPath != cleanDestination && !strings.HasPrefix(fullPath, cleanDestination+"/") {
			return "", fmt.Errorf("archive path escapes destination: %s", oldPath)
		}
		return fullPath, nil
	}
	tarReader := tar.NewReader(u)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("ExtractFromTar: Next() failed: %w", err)
		}
		entryPath, err := safePath(header.Name)
		if err != nil {
			return fmt.Errorf("ExtractFromTar: invalid entry name %q: %w", header.Name, err)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(entryPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("ExtractFromTar: Mkdir() failed: %w", err)
			}
		case tar.TypeReg:
			if _, err := os.Lstat(entryPath); err == nil {
				err = os.Remove(entryPath)
				if err != nil {
					return fmt.Errorf("ExtractFromTar: cannot remove old file: %w", err)
				}
			}
			outFile, err := os.OpenFile(entryPath, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("ExtractFromTar: OpenFile() failed: %w", err)
			}
			// Limit the size of the extracted file to prevent decompression bomb
			limitReader := io.LimitReader(tarReader, MaxDecompressedContentSize+1)
			bytesCopied, err := io.Copy(outFile, limitReader)
			if err != nil {
				return fmt.Errorf("ExtractFromTar: Copy() failed: %w", err)
			}
			if bytesCopied > MaxDecompressedContentSize {
				return fmt.Errorf("ExtractFromTar: Max decompressed content size reached")
			}
			if err := outFile.Close(); err != nil {
				return fmt.Errorf("ExtractFromTar: outFile.Close() failed: %w", err)
			}
		case tar.TypeLink, tar.TypeSymlink:
			if _, err := os.Lstat(entryPath); err == nil {
				err = os.Remove(entryPath)
				if err != nil {
					return fmt.Errorf("ExtractFromTar: cannot remove old symlink: %w", err)
				}
			}
			linkPath, err := safePath(header.Linkname)
			if err != nil {
				return fmt.Errorf("ExtractFromTar: invalid link name %q: %w", header.Linkname, err)
			}
			if err := os.Symlink(linkPath, entryPath); err != nil {
				return fmt.Errorf("ExtractFromTar: Symlink(%s, %s) failed: %w",
					entryPath, linkPath, err)
			}
		default:
			return fmt.Errorf(
				"ExtractFromTar: unknown type: '%s' in %s",
				string([]byte{header.Typeflag}),
				header.Name)
		}
	}
	return nil
}
