// Copyright (c) 2017-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-cmp/cmp"
)

// ComputeShaFile computes the sha256 for the content of a file
func ComputeShaFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// CompareSha calculates the sha of a input file and compares with a sha
// stored in a sha file.
// If the inputFilename does not exist then it reports no change.
// If shaFilename output does not exist then it reports change.
func CompareSha(inputFilename string, shaFilename string) (change bool, newSha []byte, err error) {
	if _, err = os.Stat(inputFilename); err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		return
	}
	newSha, err = ComputeShaFile(inputFilename)
	if err != nil {
		return
	}

	if _, err = os.Stat(shaFilename); err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		change = true
		return
	}
	var oldSha []byte

	oldSha, err = ReadWithMaxSize(nil, shaFilename, 128)
	if err != nil {
		if os.IsNotExist(err) {
			err = nil
		}
		change = true
		return
	}
	if len(newSha) != len(oldSha) {
		err = fmt.Errorf("Sha differers in length %d vs %d",
			len(oldSha), len(newSha))
		change = true
		return
	}
	if !cmp.Equal(oldSha, newSha) {
		change = true
	}
	return
}

// SaveShaInFile saves the value to use used by future CompareSha calls.
func SaveShaInFile(filename string, sha []byte) error {
	// Create directory if needed.
	dirname := filepath.Dir(filename)
	if _, err := os.Stat(dirname); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		err = os.MkdirAll(dirname, 0755)
		if err != nil {
			return err
		}
	}
	err := WriteRename(filename, sha)
	if err != nil {
		return err
	}
	return nil
}
