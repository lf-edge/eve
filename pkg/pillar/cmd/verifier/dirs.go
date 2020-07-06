// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"os"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

func initializeDirs() {
	// Remove any files which didn't make it past the verifier.
	clearInProgressDownloadDirs()
	// create the object download directories
	createDownloadDirs()
}

// Create the object download directories we own
func createDownloadDirs() {
	// now create the download dirs
	workingDirTypes := []string{getVerifierDir(), getVerifiedDir()}
	for _, dirName := range workingDirTypes {
		if _, err := os.Stat(dirName); err != nil {
			log.Infof("Create %s", dirName)
			if err := os.MkdirAll(dirName, 0700); err != nil {
				log.Fatal(err)
			}
		}
	}
}

// clear in-progress object download directories
func clearInProgressDownloadDirs() {

	// Now remove the in-progress dirs
	workingDirTypes := []string{getVerifierDir()}
	for _, dirType := range workingDirTypes {
		dirName := types.DownloadDirname + "/" + dirType
		if _, err := os.Stat(dirName); err == nil {
			if err := os.RemoveAll(dirName); err != nil {
				log.Fatal(err)
			}
		}
	}
}
