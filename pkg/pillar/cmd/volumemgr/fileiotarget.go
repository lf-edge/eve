// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TargetCreate - Create fileio target for volume
func TargetCreate(status types.VolumeStatus) error {

	/*
		var script = [...]string{
			fmt.Sprintf(`mkdir -p /sys/kernel/config/target/core/fileio_0/%v`, status.DisplayName),
			fmt.Sprintf(`echo "fd_dev_name=%v,fd_dev_size=%v,fd_buffered_io=1" > /sys/kernel/config/target/core/fileio_0/%v/control`, status.PathName(), status.CurrentSize, status.DisplayName),
			fmt.Sprintf(`echo 4096 > /sys/kernel/config/target/core/fileio_0/%v/attrib/block_size`, status.DisplayName),
			fmt.Sprintf(`echo "%s" > /sys/kernel/config/target/core/fileio_0/%v/wwn/vpd_unit_serial`, status.VolumeID, status.DisplayName),
			fmt.Sprintf(`echo -n "%v" >/sys/kernel/config/target/core/fileio_0/%v/udev_path`, status.PathName(), status.DisplayName),
			fmt.Sprintf(`echo 1 > /sys/kernel/config/target/core/fileio_0/%v/enable`, status.DisplayName),
		}
		//*/

	var targetRoot = filepath.Join("/sys/kernel/config/target/core/fileio_0/", status.DisplayName)
	if err := os.MkdirAll(targetRoot, os.ModePerm); err != nil {
		log.Error(fmt.Sprintf("Error create catalog in sysfs for target filio [%v]", err))
	}

	var controlPath = filepath.Join(targetRoot, "control")
	var data = fmt.Sprintf("fd_dev_name=%s,fd_dev_size=%d,fd_buffered_io=1", status.PathName(), status.CurrentSize)
	if err := ioutil.WriteFile(controlPath, []byte(data), 0660); err != nil {
		log.Error("Error set control")
	}

	var bsPath = filepath.Join(targetRoot, "attrib", "block_size")
	if err := ioutil.WriteFile(bsPath, []byte("4096"), 0660); err != nil {
		log.Error("Error set bs")
	}

	var vpdUnitSerial = filepath.Join(targetRoot, "wwn", "vpd_unit_serial")
	if err := ioutil.WriteFile(vpdUnitSerial, []byte(status.VolumeID.String()), 0660); err != nil {
		log.Error("Error set UUID")
	}

	var udevPath = filepath.Join(targetRoot, "udev_path")
	if err := ioutil.WriteFile(udevPath, []byte(status.PathName()), 0660); err != nil {
		log.Error("Error set udev")
	}

	var enablePath = filepath.Join(targetRoot, "enable")
	if err := ioutil.WriteFile(enablePath, []byte("1"), 0660); err != nil {
		log.Error(err)
	}

	log.Error(fmt.Sprintf("Create target fileIO for [%v]:[%v] size=[%v] UUID:%s", status.DisplayName, status.PathName(), status.MaxVolSize, status.VolumeID))

	return nil
}
