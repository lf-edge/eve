// Copyright (c) 2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package disks

import (
	"fmt"
	"os"
	"path/filepath"
)

// GetDiskNameByPartName returns disk name /dev/sda for part name /dev/sda1 if exists
// inside we resolve symlink for dev for example
// /dev/sda9 -> /sys/class/block/mmcblk1p9 ->
// ../../devices/platform/emmc2bus/fe340000.mmc/mmc_host/mmc1/mmc1:0001/block/mmcblk1/mmcblk1p9
// and check if the last part of the path is device, i.e. exists in /sys/block,
// if not, we use the part of the path before the last part
func GetDiskNameByPartName(name string) (string, error) {
	resolvedPath, err := filepath.EvalSymlinks(name)
	if err != nil {
		return "", fmt.Errorf("cannot eval symlink for %s: %s", name, err)
	}
	link, err := filepath.EvalSymlinks(filepath.Join("/sys/class/block", filepath.Base(resolvedPath)))
	if err != nil {
		return "", fmt.Errorf("cannot find block device: %s", err)
	}
	baseLink := filepath.Dir(link)
	//assume that it is partition, so use previous element of path as device
	pathToDev := filepath.Join("/dev", filepath.Base(baseLink))

	//check if it is block device, it indicates that we provide device, not partition
	_, err = os.Stat(filepath.Join("/sys/block", filepath.Base(link)))
	if err == nil {
		pathToDev = filepath.Join("/dev", filepath.Base(link))
	}
	s, err := os.Stat(pathToDev)
	if err != nil {
		return "", fmt.Errorf("cannot find device: %s", err)
	}
	if s.Mode()&os.ModeDevice != 0 {
		return pathToDev, nil
	}
	return "", fmt.Errorf("%s is not a device", pathToDev)
}

// GetRootDevice returns device EVE booted from, i.e. /dev/sda
func GetRootDevice() (string, error) {
	link, err := filepath.EvalSymlinks("/dev/root")
	if err != nil {
		return "", fmt.Errorf("cannot find root device: %s", err)
	}
	return GetDiskNameByPartName(link)
}
