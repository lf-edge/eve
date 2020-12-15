// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"os/exec"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// VhostCreate - Create vhost fabric for volume
func VhostCreate(status types.DiskStatus) (string, error) {
	var wwn = "naa.60014059811d880b"
	var wwnNexus = "naa.60014059811d865d"

	var script = [...]string{
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

	logError("Create vhost for %v, wwn %v", status.DisplayName, wwn)
	return wwn, nil
}
