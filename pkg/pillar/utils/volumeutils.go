// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"errors"
	"fmt"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
)

// GetVolumeSize returns the actual and maximum size of the volume
// plus a DiskType and a DirtyFlag
func GetVolumeSize(log *base.LogObject, name string) (uint64, uint64, string, bool, error) {
	info, err := os.Stat(name)
	if err != nil {
		errStr := fmt.Sprintf("GetVolumeSize failed for %s: %v",
			name, err)
		return 0, 0, "", false, errors.New(errStr)
	}
	if info.IsDir() {
		// Assume this is a container
		size, err := diskmetrics.SizeFromDir(log, name)
		return size, size, "CONTAINER", false, err
	}
	if info.Mode()&os.ModeDevice != 0 {
		//Assume this is zfs device
		imgInfo, err := zfs.GetZFSVolumeInfo(log, name)
		if err != nil {
			errStr := fmt.Sprintf("GetVolumeSize/GetZFSInfo failed for %s: %v",
				name, err)
			return 0, 0, "", false, errors.New(errStr)
		}
		return imgInfo.ActualSize, imgInfo.VirtualSize, imgInfo.Format,
			imgInfo.DirtyFlag, nil
	}
	imgInfo, err := diskmetrics.GetImgInfo(log, name)
	if err != nil {
		errStr := fmt.Sprintf("GetVolumeSize/GetImgInfo failed for %s: %v",
			name, err)
		return 0, 0, "", false, errors.New(errStr)
	}
	return imgInfo.ActualSize, imgInfo.VirtualSize, imgInfo.Format,
		imgInfo.DirtyFlag, nil
}
