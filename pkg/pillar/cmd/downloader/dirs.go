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
	// get files
	dirName := getPendingDir()
	files, err := os.ReadDir(dirName)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		log.Fatal(err)
	}
	// load all known download objects
	existingTargets := make(map[string]bool)
	if ctx != nil {
		dss := ctx.subDownloaderConfig.GetAll()
		for _, ds := range dss {
			obj := ds.(types.DownloaderConfig)
			existingTargets[obj.Target] = true
		}
	}
	// loop through files and check if they are in place
	for _, fi := range files {
		if fi.IsDir() {
			continue
		}
		filePath := filepath.Join(dirName, fi.Name())
		// if progress file
		if strings.HasSuffix(filePath, progressFileSuffix) {
			//check if progress file points onto existing file
			if _, err := os.Stat(strings.TrimSuffix(filePath, progressFileSuffix)); err == nil {
				continue
			}
			// if not exists, remove progress file
			err = os.RemoveAll(filePath)
			if err != nil {
				log.Fatal(err)
			}
			continue
		}
		// skip ctx related checks if not provided
		if ctx == nil {
			continue
		}
		//if no file in existing targets, remove it as garbage
		if _, ok := existingTargets[filePath]; !ok {
			err = os.RemoveAll(filePath)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

func getPendingDir() string {
	return path.Join(downloaderBasePath, "pending")
}
