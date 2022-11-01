// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"errors"
	"fmt"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cas"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

// GetVolumeSize returns the actual and maximum size of the volume
// plus a DiskType and a DirtyFlag
func GetVolumeSize(log *base.LogObject, casClient cas.CAS, fileLocation string) (uint64, uint64, string, bool, error) {
	info, err := os.Stat(fileLocation)
	if err != nil {
		return 0, 0, "", false, fmt.Errorf("GetVolumeSize failed for %s: %v",
			fileLocation, err)
	}
	// Assume this is a container
	if info.IsDir() {
		var size uint64
		snapshotID := containerd.GetSnapshotID(fileLocation)
		su, err := casClient.SnapshotUsage(snapshotID, true)
		if err == nil {
			size = uint64(su)
		} else {
			// we did not create snapshot yet
			log.Warnf("GetVolumeSize: Failed get snapshot usage: %s for %s. Error %s",
				snapshotID, fileLocation, err)
			size, err = diskmetrics.SizeFromDir(log, fileLocation)
		}
		return size, size, "CONTAINER", false, err
	}
	if info.Mode()&os.ModeDevice != 0 {
		//Assume this is zfs device
		imgInfo, err := zfs.GetZFSVolumeInfo(fileLocation)
		if err != nil {
			errStr := fmt.Sprintf("GetVolumeSize/GetZFSInfo failed for %s: %v",
				fileLocation, err)
			return 0, 0, "", false, errors.New(errStr)
		}
		return imgInfo.ActualSize, imgInfo.VirtualSize, imgInfo.Format,
			imgInfo.DirtyFlag, nil
	}
	imgInfo, err := diskmetrics.GetImgInfo(log, fileLocation)
	if err != nil {
		errStr := fmt.Sprintf("GetVolumeSize/GetImgInfo failed for %s: %v",
			fileLocation, err)
		return 0, 0, "", false, errors.New(errStr)
	}
	return imgInfo.ActualSize, imgInfo.VirtualSize, imgInfo.Format,
		imgInfo.DirtyFlag, nil
}
