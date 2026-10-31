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

func resolveDestinationRoot(destination string) (string, error) {
	absDest, err := filepath.Abs(destination)
	if err != nil {
		return "", err
	}
	realDest, err := filepath.EvalSymlinks(absDest)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return absDest, nil
		}
		return "", err
	}
	return realDest, nil
}

func safeJoinWithinDestination(destinationRoot, archivePath string) (string, error) {
	if filepath.IsAbs(archivePath) {
		return "", fmt.Errorf("absolute archive path is not allowed: %s", archivePath)
	}
	candidate := filepath.Join(destinationRoot, archivePath)
	parent := filepath.Dir(candidate)

	realParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		realParent = parent
	}

	resolved := filepath.Join(realParent, filepath.Base(candidate))
	rel, err := filepath.Rel(destinationRoot, resolved)
	if err != nil {
		return "", err
	}
	rel = filepath.Clean(rel)
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive path escapes destination: %s", archivePath)
	}
	return resolved, nil
}

// ExtractFromTar extracts files from a tar reader into the destination directory
func ExtractFromTar(u io.Reader, destination string) error {
	destinationRoot, err := resolveDestinationRoot(destination)
	if err != nil {
		return fmt.Errorf("ExtractFromTar: failed to resolve destination: %w", err)
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

		outputPath, err := safeJoinWithinDestination(destinationRoot, header.Name)
		if err != nil {
			return fmt.Errorf("ExtractFromTar: invalid archive entry path %q: %w", header.Name, err)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(outputPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("ExtractFromTar: Mkdir() failed: %w", err)
			}
		case tar.TypeReg:
			if _, err := os.Lstat(outputPath); err == nil {
				err = os.Remove(outputPath)
				if err != nil {
					return fmt.Errorf("ExtractFromTar: cannot remove old file: %w", err)
				}
			}
			outFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
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
			linkTargetPath, err := safeJoinWithinDestination(destinationRoot, header.Linkname)
			if err != nil {
				return fmt.Errorf("ExtractFromTar: invalid symlink target %q: %w", header.Linkname, err)
			}
			if _, err := os.Lstat(outputPath); err == nil {
				err = os.Remove(outputPath)
				if err != nil {
					return fmt.Errorf("ExtractFromTar: cannot remove old symlink: %w", err)
				}
			}
			if err := os.Symlink(linkTargetPath, outputPath); err != nil {
				return fmt.Errorf("ExtractFromTar: Symlink(%s, %s) failed: %w",
					outputPath, linkTargetPath, err)
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
