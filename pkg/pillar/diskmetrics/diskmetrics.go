// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

func GetImgInfo(log *base.LogObject, diskfile string) (*types.ImgInfo, error) {
	var imgInfo types.ImgInfo

	if _, err := os.Stat(diskfile); err != nil {
		return nil, err
	}
	output, err := base.Exec(log, "/usr/bin/qemu-img", "info", "-U", "--output=json",
		diskfile).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n",
			err, output)
		return nil, errors.New(errStr)
	}
	if err := json.Unmarshal(output, &imgInfo); err != nil {
		return nil, err
	}
	return &imgInfo, nil
}

// GetDiskVirtualSize - returns VirtualSize of the image
func GetDiskVirtualSize(log *base.LogObject, diskfile string) (uint64, error) {
	imgInfo, err := GetImgInfo(log, diskfile)
	if err != nil {
		return 0, err
	}
	return imgInfo.VirtualSize, nil
}

// CheckResizeDisk returns size and indicates do we need to resize disk to be at least maxsizebytes
func CheckResizeDisk(log *base.LogObject, diskfile string, maxsizebytes uint64) (uint64, bool, error) {
	vSize, err := GetDiskVirtualSize(log, diskfile)
	if err != nil {
		return 0, false, err
	}
	if vSize > maxsizebytes {
		log.Warnf("Virtual size (%d) of provided volume(%s) is larger than provided MaxVolSize (%d). "+
			"Will use virtual size.", vSize, diskfile, maxsizebytes)
		return vSize, false, nil
	}
	return maxsizebytes, vSize != maxsizebytes, nil
}

// ResizeImg calls qemu-img to resize disk file to new size
func ResizeImg(ctx context.Context, log *base.LogObject, diskfile string, newsize uint64) error {
	if _, err := os.Stat(diskfile); err != nil {
		return err
	}
	output, err := base.Exec(log, "/usr/bin/qemu-img", "resize", diskfile,
		strconv.FormatUint(newsize, 10)).WithContext(ctx).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n",
			err, output)
		return errors.New(errStr)
	}
	return nil
}

// CreateImg creates empty diskfile with defined format and size
func CreateImg(ctx context.Context, log *base.LogObject, diskfile string, format string, size uint64) error {
	output, err := base.Exec(log, "/usr/bin/qemu-img", "create", "-f", format, diskfile,
		strconv.FormatUint(size, 10)).WithContext(ctx).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n",
			err, output)
		return errors.New(errStr)
	}
	return nil
}

// RolloutImgToBlock do conversion of diskfile to outputFile with defined format
func RolloutImgToBlock(ctx context.Context, log *base.LogObject, diskfile, outputFile, outputFormat string) error {
	if _, err := os.Stat(diskfile); err != nil {
		return err
	}
	// writeback cache instead of default unsafe, out of order enabled, skip file creation
	// Timeout 2 hours
	args := []string{"convert", "--target-is-zero", "-t", "writeback", "-W", "-n", "-O", outputFormat, diskfile, outputFile}
	output, err := base.Exec(log, "/usr/bin/qemu-img", args...).WithContext(ctx).CombinedOutputWithCustomTimeout(432000)
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n",
			err, output)
		return errors.New(errStr)
	}
	return nil
}
