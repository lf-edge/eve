// Copyright (c) 2017 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"errors"
	"fmt"

	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

// GetDiskSizeForAppInstance - Returns sum of all sizes of all disks in App Instance
func GetDiskSizeForAppInstance(status types.AppInstanceStatus) (
	uint64, error) {
	var totalSize uint64

	// Skip Containers. The images are private to rkt at this point.
	//  We don't have the right location nor the exact size of the image
	// Need to add container support innfuture to check disk size.
	if status.IsContainer {
		return totalSize, nil
	}
	for indx := range status.StorageStatusList {
		ssPtr := &status.StorageStatusList[indx]
		if ssPtr.ReadOnly {
			continue
		}
		fileLocation := ssPtr.ActiveFileLocation
		imageVirtualSize, err := diskmetrics.GetDiskVirtualSize(fileLocation)
		if err != nil {
			errStr := fmt.Sprintf("GetDiskSize: App: %s. Failed to get "+
				"Virtual Size for %s: %s", status.UUIDandVersion.UUID.String(),
				fileLocation, err)
			log.Errorf("GetDiskSize failed: %s", errStr)
			return 0, errors.New(errStr)
		}
		if imageVirtualSize > ssPtr.Maxsizebytes {
			totalSize += imageVirtualSize
		} else {
			totalSize += ssPtr.Maxsizebytes
		}
	}
	return totalSize, nil
}
