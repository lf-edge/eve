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
	for indx := range status.StorageStatusList {
		ssPtr := &status.StorageStatusList[indx]
		if ssPtr.IsContainer || ssPtr.ReadOnly {
			continue
		}
		fileLocation, err := VerifiedImageFileLocation(ssPtr.IsContainer,
			ssPtr.ContainerImageID, ssPtr.ImageSha256)
		if err != nil {
			err = fmt.Errorf("GetDiskSize: App: %s. Failed to get "+
				"VerifiedImageFileLocation. err: %s",
				status.UUIDandVersion.UUID.String(),
				err.Error())
			log.Errorf("VerifiedImageFileLocation failed: %s", err.Error())
			return 0, err
		}
		imageVirtualSize, err := diskmetrics.GetDiskVirtualSize(fileLocation)
		if err != nil {
			errStr := fmt.Sprintf("GetDiskSize: App: %s. Failed to get "+
				"Virtual Size. %s", status.UUIDandVersion.UUID.String(),
				err.Error())
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
