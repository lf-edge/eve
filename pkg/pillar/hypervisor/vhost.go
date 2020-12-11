// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// VhostCreate - Create vhost fabric for volume
func VhostCreate(status types.DiskStatus) (string, error) {
	if status.DisplayName == "" {
		return "", fmt.Errorf("Error creating VHost for %s: no DisplayName provided", status.MountDir)
	}

	var x = types.GenerateWWN(status.DisplayName)
	var wwn = x.DeviceWWN()
	var wwnNexus = x.NexusWWN()

	var targetRoot = filepath.Join("/hostfs/sys/kernel/config/target/core/fileio_0", status.DisplayName)
	var vhostRoot = filepath.Join("/hostfs/sys/kernel/config/target/vhost", wwn, "tpgt_1")
	var vhostLun = filepath.Join(vhostRoot, "/lun/lun_0")
	if err := os.MkdirAll(vhostLun, 0755); err != nil {
		return "", fmt.Errorf("Error creating catalog in sysfs for vhost filio: %v", err)
	}

	var controlPath = filepath.Join(targetRoot, "control")
	var data = "scsi_host_id=1,scsi_channel_id=0,scsi_target_id=0,scsi_lun_id=0"
	if err := ioutil.WriteFile(controlPath, []byte(data), 0660); err != nil {
		return "", fmt.Errorf("Error setting control: %v", err)
	}

	var nexusPath = filepath.Join(vhostRoot, "nexus")
	if err := ioutil.WriteFile(nexusPath, []byte(wwnNexus), 0660); err != nil {
		return "", fmt.Errorf("Error setting control: %v", err)
	}

	var newname = filepath.Join(vhostLun, status.DisplayName)
	if err := os.Symlink(targetRoot, newname); err != nil {
		return "", fmt.Errorf("Error creating symbolic link: %v", err)
	}

	return wwn, nil
}
