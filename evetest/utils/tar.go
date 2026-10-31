// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MaxDecompressedContentSize is the maximum size of a file that can be written to disk after decompression.
// This is to prevent a DoS attack by unpacking a compressed file that is too big to be decompressed.
const MaxDecompressedContentSize = 1024 * 1024 * 1024 // 1 GB

// ExtractFromTar extracts files from a tar reader into the destination directory
func ExtractFromTar(u io.Reader, destination string) error {
	cleanDestination := filepath.Clean(destination)
	if err := os.MkdirAll(cleanDestination, 0o755); err != nil {
		return fmt.Errorf("ExtractFromTar: MkdirAll(destination) failed: %w", err)
	}
	realDestination, err := filepath.EvalSymlinks(cleanDestination)
	if err != nil {
		return fmt.Errorf("ExtractFromTar: EvalSymlinks(destination) failed: %w", err)
	}

	isWithinDestination := func(candidate string) bool {
		rel, err := filepath.Rel(realDestination, candidate)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
	}

	resolveArchivePath := func(archivePath string) (string, error) {
		if filepath.IsAbs(archivePath) {
			return "", fmt.Errorf("absolute path is not allowed: %s", archivePath)
		}
		candidate := filepath.Join(realDestination, archivePath)
		parent := filepath.Dir(candidate)
		resolvedParent, err := filepath.EvalSymlinks(parent)
		if err != nil {
			return "", fmt.Errorf("cannot resolve parent path %s: %w", parent, err)
		}
		finalPath := filepath.Join(resolvedParent, filepath.Base(candidate))
		if !isWithinDestination(finalPath) {
			return "", fmt.Errorf("path escapes destination: %s", archivePath)
		}
		return finalPath, nil
	}

	resolveLinkTarget := func(linkName, linkTarget string) (string, error) {
		linkPath, err := resolveArchivePath(linkName)
		if err != nil {
			return "", err
		}
		linkParent := filepath.Dir(linkPath)
		var targetCandidate string
		if filepath.IsAbs(linkTarget) {
			targetCandidate = filepath.Clean(linkTarget)
		} else {
			targetCandidate = filepath.Join(linkParent, linkTarget)
		}
		resolvedTargetParent, err := filepath.EvalSymlinks(filepath.Dir(targetCandidate))
		if err != nil {
			return "", fmt.Errorf("cannot resolve symlink target parent %s: %w", filepath.Dir(targetCandidate), err)
		}
		finalTarget := filepath.Join(resolvedTargetParent, filepath.Base(targetCandidate))
		if !isWithinDestination(finalTarget) {
			return "", fmt.Errorf("symlink target escapes destination: %s", linkTarget)
		}
		return finalTarget, nil
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
		switch header.Typeflag {
		case tar.TypeDir:
			dirPath, err := resolveArchivePath(header.Name)
			if err != nil {
				return fmt.Errorf("ExtractFromTar: invalid directory path %s: %w", header.Name, err)
			}
			if err := os.MkdirAll(dirPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("ExtractFromTar: Mkdir() failed: %w", err)
			}
		case tar.TypeReg:
			filePath, err := resolveArchivePath(header.Name)
			if err != nil {
				return fmt.Errorf("ExtractFromTar: invalid file path %s: %w", header.Name, err)
			}
			if _, err := os.Lstat(filePath); err == nil {
				err = os.Remove(filePath)
				if err != nil {
					return fmt.Errorf("ExtractFromTar: cannot remove old file: %w", err)
				}
			}
			outFile, err := os.OpenFile(filePath, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
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
			linkPath, err := resolveArchivePath(header.Name)
			if err != nil {
				return fmt.Errorf("ExtractFromTar: invalid symlink path %s: %w", header.Name, err)
			}
			linkTarget, err := resolveLinkTarget(header.Name, header.Linkname)
			if err != nil {
				return fmt.Errorf("ExtractFromTar: invalid symlink target %s: %w", header.Linkname, err)
			}
			if _, err := os.Lstat(linkPath); err == nil {
				err = os.Remove(linkPath)
				if err != nil {
					return fmt.Errorf("ExtractFromTar: cannot remove old symlink: %w", err)
				}
			}
			if err := os.Symlink(linkTarget, linkPath); err != nil {
				return fmt.Errorf("ExtractFromTar: Symlink(%s, %s) failed: %w",
					linkPath, linkTarget, err)
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
