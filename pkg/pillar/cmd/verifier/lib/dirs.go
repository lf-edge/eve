// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"os"
	"path"
)

func (v *Verifier) initializeDirs() error {
	// Remove any files which didn't make it past the verifier.
	if err := v.clearInProgressDownloadDirs(); err != nil {
		return err
	}
	// create the object download directories
	return v.createDownloadDirs()
}

// Create the object download directories we own
func (v *Verifier) createDownloadDirs() error {
	// now create the download dirs
	workingDirTypes := []string{v.GetVerifierDir(), v.GetVerifiedDir()}
	for _, dirName := range workingDirTypes {
		if _, err := os.Stat(dirName); err != nil {
			if err := os.MkdirAll(dirName, 0700); err != nil {
				return err
			}
		}
	}
	return nil
}

// clear in-progress object download directories
func (v *Verifier) clearInProgressDownloadDirs() error {

	// Now remove the in-progress dirs
	workingDirTypes := []string{v.GetVerifierDir()}
	for _, dirName := range workingDirTypes {
		if _, err := os.Stat(dirName); err == nil {
			if err := os.RemoveAll(dirName); err != nil {
				return err
			}
		}
	}
	return nil
}

// GetVerifierDir returns the verifier directory
func (v *Verifier) GetVerifierDir() string {
	return path.Join(v.basePath, "verifier")
}

// GetVerifiedDir returns the verified directory
func (v *Verifier) GetVerifiedDir() string {
	return path.Join(v.basePath, "verified")
}
