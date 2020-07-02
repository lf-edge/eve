// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/diskmetrics"
)

// dirSize returns the size of the directory
func dirSize(path string) (uint64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})
	return uint64(size), err
}

// GetVolumeSize returns the actual and maximum size of the volume
func GetVolumeSize(name string) (uint64, uint64, error) {
	info, err := os.Stat(name)
	if err != nil {
		errStr := fmt.Sprintf("GetVolumeMaxSize failed for %s: %v",
			name, err)
		return 0, 0, errors.New(errStr)
	}
	if info.IsDir() {
		size, err := dirSize(name)
		if err != nil {
			errStr := fmt.Sprintf("GetVolumeMaxSize failed for %s: %v",
				name, err)
			return 0, 0, errors.New(errStr)
		}
		return size, size, nil
	}
	imgInfo, err := diskmetrics.GetImgInfo(name)
	if err != nil {
		errStr := fmt.Sprintf("GetVolumeMaxSize failed for %s: %v",
			name, err)
		return 0, 0, errors.New(errStr)
	}
	return imgInfo.ActualSize, imgInfo.VirtualSize, nil
}

// Create9PAccessibleBlankVolume will create blank volume of given format and size
func Create9PAccessibleBlankVolume(volumePath, format string, maxSize uint64) error {
	if _, err := os.Stat(volumePath); err == nil {
		errStr := fmt.Sprintf("CreateBlankVolume failed for %s: volume already exists",
			volumePath)
		return errors.New(errStr)
	}
	output, err := exec.Command("/usr/bin/qemu-img", "create",
		"-f", strings.ToLower(format), "-o", fmt.Sprintf("size=%d", maxSize),
		volumePath).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("CreateBlankVolume failed for %s: %s, %s",
			volumePath, err, output)
		return errors.New(errStr)
	}
	return nil
}
