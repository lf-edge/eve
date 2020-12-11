// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"os/exec"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// VhostCreate - Create vhost fabric and fileio target for volume
func vhostCreate(status types.VolumeStatus) (string, error) {
	var wwn = "naa.60014059811d880b"
	var wwnNexus = "naa.60014059811d865d"
	var wwnTarget = "9cfd76cc-06e6-49a5-b67b-025fbdb69fb1"

	var script = [...]string{
		fmt.Sprintf(`mkdir -p /sys/kernel/config/target/core/fileio_0/%v`, status.DisplayName),
		fmt.Sprintf(`echo "fd_dev_name=%v,fd_dev_size=%v,fd_buffered_io=1" > /sys/kernel/config/target/core/fileio_0/%v/control`, status.PathName(), status.MaxVolSize, status.DisplayName),
		fmt.Sprintf(`echo 4096 > /sys/kernel/config/target/core/fileio_0/%v/attrib/block_size`, status.DisplayName),
		fmt.Sprintf(`echo "%s" > /sys/kernel/config/target/core/fileio_0/%v/wwn/vpd_unit_serial`, wwnTarget, status.DisplayName),
		fmt.Sprintf(`echo -n "%v" >/sys/kernel/config/target/core/fileio_0/%v/udev_path`, status.PathName(), status.DisplayName),
		fmt.Sprintf(`echo 1 > /sys/kernel/config/target/core/fileio_0/%v/enable`, status.DisplayName),
		fmt.Sprintf(`mkdir -p /sys/kernel/config/target/vhost/%v/tpgt_1/lun/lun_0`, wwn),
		fmt.Sprintf(`echo -n 'scsi_host_id=1,scsi_channel_id=0,scsi_target_id=0,scsi_lun_id=0' > /sys/kernel/config/target/core/fileio_0/%v/control`, status.DisplayName),
		fmt.Sprintf(`echo -n %v > /sys/kernel/config/target/vhost/%v/tpgt_1/nexus`, wwnNexus, wwn),
		fmt.Sprintf(`cd /sys/kernel/config/target/vhost/%v/tpgt_1/lun/lun_0 && ln -s ../../../../../core/fileio_0/%v/ .`, wwn, status.DisplayName),
	}

	for _, cmd := range script {
		if err := exec.Command("bash", "-c", cmd).Run(); err != nil {
			logError("Failed to execute command [%s]: %v", cmd, err)
		}
	}

	return wwn, nil
}
