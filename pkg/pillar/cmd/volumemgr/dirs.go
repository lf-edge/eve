// Copyright (c) 2019-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"os"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

func initializeDirs() {

	// first the certs directory
	if _, err := os.Stat(types.CertificateDirname); err != nil {
		log.Tracef("initializeDirs: Create %s", types.CertificateDirname)
		if err := os.MkdirAll(types.CertificateDirname, 0700); err != nil {
			log.Fatal(err)
		}
	}
	// Our destination volume directories
	volumeDirs := []string{
		types.VolumeEncryptedDirName,
		types.VolumeClearDirName,
	}
	for _, dirName := range volumeDirs {
		if _, err := os.Stat(dirName); err != nil {
			log.Functionf("Create %s", dirName)
			if err := os.MkdirAll(dirName, 0700); err != nil {
				log.Fatal(err)
			}
		}
	}
}

func initializeDatasets() {
	// Our destination volume datasets
	volumeDatasets := []string{
		types.VolumeClearZFSDataset,
		types.VolumeEncryptedZFSDataset,
	}
	for _, datasetName := range volumeDatasets {
		if !zfs.DatasetExist(log, datasetName) {
			if err := zfs.CreateDatasets(log, datasetName); err != nil {
				log.Fatalf("CreateDataset failed: %s", err)
			}
		} else {
			if err := zfs.MountDataset(datasetName); err != nil {
				// it may be mounted
				log.Functionf("MountDataset failed: %s", err)
			}
		}
	}
}
