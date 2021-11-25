// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package downloader

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

const progressFileSuffix = ".progress"

// Create the object download directories we own
func createDownloadDirs() {

	workingDirTypes := []string{getPendingDir()}

	// now create the download dirs
	for _, dirName := range workingDirTypes {
		if _, err := os.Stat(dirName); err != nil {
			log.Tracef("Create %s", dirName)
			if err := os.MkdirAll(dirName, 0700); err != nil {
				log.Fatal(err)
			}
		}
	}
}

// clear in-progress object download directories
// it checks for progress files and remove objects if progress or object do not exist
// if ctx provided it go through DownloaderConfig and prepare existingTargets map
// to clean all files which are not inside config
func clearInProgressDownloadDirs(ctx *downloaderContext) {
	existingTargets := make(map[string]bool)
	if ctx != nil {
		dss := ctx.subDownloaderConfig.GetAll()
		for _, ds := range dss {
			obj := ds.(types.DownloaderConfig)
			existingTargets[obj.Target] = true
		}
	}

	// Now remove the in-progress dirs
	workingDirTypes := []string{getPendingDir()}

	for _, dirName := range workingDirTypes {
		if _, err := os.Stat(dirName); err == nil {
			err := filepath.Walk(dirName, func(walkPath string, fi os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if fi.IsDir() {
					return nil
				}
				// if progress file
				if strings.HasSuffix(walkPath, progressFileSuffix) {
					//check if progress file points onto existing file
					if _, err := os.Stat(strings.TrimSuffix(walkPath, progressFileSuffix)); err == nil {
						return nil
					}
					// if not exists, remove progress file
					return os.Remove(walkPath)
				}
				// skip ctx related checks if not provided
				if ctx == nil {
					return nil
				}
				//if no file in existing targets, remove it as garbage
				if _, ok := existingTargets[walkPath]; !ok {
					return os.Remove(walkPath)
				}
				return nil
			})
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

func getPendingDir() string {
	return path.Join(downloaderBasePath, "pending")
}
