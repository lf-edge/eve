package zfs

import (
	"os"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/shirou/gopsutil/disk"
)

const sysfsPciDevices = "/sys/bus/pci/devices/"

var zfsManagerDir = "/run/zfsmanager"

// NVMEIsUsed checks if an NVME device is in a ZFS pool or mounted
func NVMEIsUsed(log *base.LogObject, zfsPoolStatusMap map[string]interface{}, pciID string) bool {
	if _, err := os.Stat(zfsManagerDir); os.IsNotExist(err) {
		log.Noticef("ZFS manager is not initialized yet")
		return true
	}

	// Get /dev/nvmX from pciID
	deviceName, err := getDeviceNameFromPciID(pciID)
	if err != nil {
		log.Errorf("Can't determine nvme device name for %s (%v)", pciID, err)
		return false
	}

	// Checking zfs pools
	for _, el := range zfsPoolStatusMap {
		zfsPoolStatus, ok := el.(types.ZFSPoolStatus)
		if !ok {
			log.Errorf("Could not convert to ZFSPoolStatus")
			continue
		}
		for _, disk := range zfsPoolStatus.Disks {
			if strings.Contains(disk.DiskName.LogicalName, deviceName) {
				return true
			}
		}
	}

	// Checking mounted partitions
	partitions, err := disk.Partitions(true)
	if err != nil {
		log.Errorf("Could not find mounted partitions error:%+v", err)
		return false
	}

	for _, partition := range partitions {
		if strings.Contains(partition.Device, deviceName) {
			return true
		}
	}

	return false
}

func getDeviceNameFromPciID(pciID string) (string, error) {
	// e.g., ls /sys/bus/pci/devices/<pciID>/nvme/
	//  -> nvme0
	deviceName := ""
	nvmePath, err := os.ReadDir(sysfsPciDevices + pciID + "/nvme")
	if err != nil {
		return "", err
	}
	for _, file := range nvmePath {
		deviceName = file.Name()
	}
	return deviceName, nil
}
