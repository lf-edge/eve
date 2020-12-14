// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"os/exec"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// TargetCreate - Create fileio target for volume
func TargetCreate(status types.VolumeStatus) error {

	var script = [...]string{
		fmt.Sprintf(`mkdir -p /sys/kernel/config/target/core/fileio_0/%v`, status.DisplayName),
		fmt.Sprintf(`echo "fd_dev_name=%v,fd_dev_size=%v,fd_buffered_io=1" > /sys/kernel/config/target/core/fileio_0/%v/control`, status.PathName(), status.MaxVolSize, status.DisplayName),
		fmt.Sprintf(`echo 4096 > /sys/kernel/config/target/core/fileio_0/%v/attrib/block_size`, status.DisplayName),
		fmt.Sprintf(`echo "%s" > /sys/kernel/config/target/core/fileio_0/%v/wwn/vpd_unit_serial`, status.VolumeID, status.DisplayName),
		fmt.Sprintf(`echo -n "%v" >/sys/kernel/config/target/core/fileio_0/%v/udev_path`, status.PathName(), status.DisplayName),
		fmt.Sprintf(`echo 1 > /sys/kernel/config/target/core/fileio_0/%v/enable`, status.DisplayName),
	}

	for _, cmd := range script {
		if err := exec.Command("bash", "-c", cmd).Run(); err != nil {
			log.Error(fmt.Sprintf("Failed to execute command [%s]: %v", cmd, err))
		}
	}

	log.Error(fmt.Sprintf("Create target fileIO for [%v]:[%v] size=[%v] UUID:%v", status.DisplayName, status.PathName(), status.MaxVolSize, status.VolumeID))

	return nil
}
