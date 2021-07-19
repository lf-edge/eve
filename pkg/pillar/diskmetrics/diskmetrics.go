// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
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

func ResizeImg(log *base.LogObject, diskfile string, newsize uint64) error {

	if _, err := os.Stat(diskfile); err != nil {
		return err
	}
	output, err := base.Exec(log, "/usr/bin/qemu-img", "resize", diskfile,
		strconv.FormatUint(newsize, 10)).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n",
			err, output)
		return errors.New(errStr)
	}
	return nil
}

//CreateImg creates empty diskfile with defined format and size
func CreateImg(log *base.LogObject, diskfile string, format string, size uint64) error {
	output, err := base.Exec(log, "/usr/bin/qemu-img", "create", "-f", format, diskfile,
		strconv.FormatUint(size, 10)).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n",
			err, output)
		return errors.New(errStr)
	}
	return nil
}

//ConvertImg do conversion of diskfile to outputFile with defined format
func ConvertImg(log *base.LogObject, diskfile, outputFile, outputFormat string) error {
	if _, err := os.Stat(diskfile); err != nil {
		return err
	}
	args := []string{"convert", "-O", outputFormat, diskfile, outputFile}
	output, err := base.Exec(log, "/usr/bin/qemu-img", args...).CombinedOutput()
	if err != nil {
		errStr := fmt.Sprintf("qemu-img failed: %s, %s\n",
			err, output)
		return errors.New(errStr)
	}
	return nil
}
