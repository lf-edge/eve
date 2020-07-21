// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"os"
	"path"

	log "github.com/sirupsen/logrus"
)

// Create the object download directories we own
func createDownloadDirs() {

	workingDirTypes := []string{getPendingDir()}

	// now create the download dirs
	for _, dirName := range workingDirTypes {
		if _, err := os.Stat(dirName); err != nil {
			log.Debugf("Create %s", dirName)
			if err := os.MkdirAll(dirName, 0700); err != nil {
				log.Fatal(err)
			}
		}
	}
}

// clear in-progress object download directories
func clearInProgressDownloadDirs() {

	// Now remove the in-progress dirs
	workingDirTypes := []string{getPendingDir()}

	for _, dirName := range workingDirTypes {
		if _, err := os.Stat(dirName); err == nil {
			if err := os.RemoveAll(dirName); err != nil {
				log.Fatal(err)
			}
		}
	}
}

func getPendingDir() string {
	return path.Join(downloaderBasePath, "pending")
}
