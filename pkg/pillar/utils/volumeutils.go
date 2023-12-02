// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"fmt"
	"os"
	"strings"

	"github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
)

// GetVolumeFormat returns format of the volume
func GetVolumeFormat(log *base.LogObject, fileLocation string) (config.Format, error) {

	// If kubevirt type, format is always PVC.
	if base.IsHVTypeKube() {
		// Might be cleaner to call GetImgInfo(), i'll cleanup in a later commit
		if strings.HasSuffix(fileLocation, ".cidata") {
			return config.Format_RAW, nil
		}
		return config.Format_PVC, nil
	}

	info, err := os.Stat(fileLocation)
	if err != nil {
		return config.Format_FmtUnknown, fmt.Errorf("GetVolumeFormat failed for %s: %v",
			fileLocation, err)
	}
	// Assume this is a container
	if info.IsDir() {
		return config.Format_CONTAINER, nil
	}

	// Assume this is zvol
	if info.Mode()&os.ModeDevice != 0 {
		return config.Format_RAW, nil
	}
	imgInfo, err := diskmetrics.GetImgInfo(log, fileLocation)
	if err != nil {
		return config.Format_FmtUnknown, fmt.Errorf("GetVolumeFormat/GetImgInfo failed for %s: %v",
			fileLocation, err)
	}
	parsedFormat, ok := config.Format_value[strings.ToUpper(imgInfo.Format)]
	if !ok {
		return config.Format_FmtUnknown, fmt.Errorf("GetVolumeFormat failed for %s: unknown format %s",
			fileLocation, imgInfo.Format)
	}
	return config.Format(parsedFormat), nil
}
