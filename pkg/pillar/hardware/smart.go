/*
 * Copyright (c) 2022. Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package hardware

import (
	"fmt"
	"time"

	smart "github.com/anatol/smart.go"
	"github.com/jaypipes/ghw"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

var logger *logrus.Logger
var log *base.LogObject

// ReadSMARTinfoForDisks - сollects disks information via API,
// returns types.DisksInformation
func ReadSMARTinfoForDisks() (*types.DisksInformation, error) {
	disksInfo := new(types.DisksInformation)
	// Get information about disks
	block, err := ghw.Block()
	if err != nil {
		return nil, fmt.Errorf("error getting block storage info: %v", err)
	}

	for _, disk := range block.Disks {
		diskName := fmt.Sprintf("/dev/%v", disk.Name)
		var diskSmartInfo *types.DiskSmartInfo

		dev, err := smart.Open(diskName)
		if err != nil {
			// When cannot open the disk, it means that it will not be
			// possible to get SMART information from it. It's ok
			diskSmartInfo = getInfoFromUnknownDisk(diskName, "unknown")
			disksInfo.Disks = append(disksInfo.Disks, diskSmartInfo)
			continue
		}
		diskType := dev.Type()
		dev.Close()

		if diskType == "sata" {
			diskSmartInfo, err = GetInfoFromSATAdisk(diskName)
			if err != nil {
				disksInfo.Disks = append(disksInfo.Disks, diskSmartInfo)
				continue
			}
		} else if diskType == "nvme" {
			diskSmartInfo, err = GetInfoFromNVMeDisk(diskName)
			if err != nil {
				disksInfo.Disks = append(disksInfo.Disks, diskSmartInfo)
				continue
			}
		} else if diskType == "scsi" {
			diskSmartInfo, err = GetInfoFromSCSIDisk(diskName)
			if err != nil {
				disksInfo.Disks = append(disksInfo.Disks, diskSmartInfo)
				continue
			}
		} else {
			diskSmartInfo = getInfoFromUnknownDisk(diskName, diskType)
			disksInfo.Disks = append(disksInfo.Disks, diskSmartInfo)
		}

		disksInfo.Disks = append(disksInfo.Disks, diskSmartInfo)
	}
	return disksInfo, nil
}

// getInfoFromUnknownDisk - takes a disk name (/dev/sda or /dev/nvme0n1)
// and disk type as input and returns *types.DiskSmartInfo
// indicating an unknown disk type
func getInfoFromUnknownDisk(diskName, diskType string) *types.DiskSmartInfo {
	diskInfo := new(types.DiskSmartInfo)
	diskInfo.DiskName = diskName
	diskInfo.DiskType = types.SmartDiskTypeUnknown
	diskInfo.Errors = fmt.Errorf("disk with name: %s have %s type", diskName, diskType)
	diskInfo.CollectingStatus = types.SmartCollectingStatusError
	diskInfo.TimeUpdate = uint64(time.Now().Unix())
	return diskInfo
}

// GetInfoFromSATAdisk - takes a disk name (/dev/sda or /dev/nvme0n1)
// as input and returns information on it
func GetInfoFromSATAdisk(diskName string) (*types.DiskSmartInfo, error) {
	diskInfo := new(types.DiskSmartInfo)
	dev, err := smart.OpenSata(diskName)
	if err != nil {
		diskInfo.DiskName = diskName
		diskInfo.Errors = fmt.Errorf("failed open SATA device with name: %s; error:%v", diskName, err)
		diskInfo.CollectingStatus = types.SmartCollectingStatusError
		diskInfo.TimeUpdate = uint64(time.Now().Unix())
		return diskInfo, diskInfo.Errors

	}
	defer dev.Close()

	diskInfo.DiskName = diskName
	diskInfo.DiskType = types.SmartDiskTypeSata

	devIdentify, err := dev.Identify()
	if err != nil {
		diskInfo.Errors = fmt.Errorf("failed identify SATA device with name: %s; error:%v", diskName, err)
		diskInfo.CollectingStatus = types.SmartCollectingStatusError
		diskInfo.TimeUpdate = uint64(time.Now().Unix())
		return diskInfo, diskInfo.Errors
	}

	smartAttrList, err := dev.ReadSMARTData()
	if err != nil {
		diskInfo.Errors = fmt.Errorf("failed read S.M.A.R.T. attr info from SATA device with name: %s; error:%v", diskName, err)
		diskInfo.CollectingStatus = types.SmartCollectingStatusError
		diskInfo.TimeUpdate = uint64(time.Now().Unix())
		return diskInfo, diskInfo.Errors
	}

	for _, smart := range smartAttrList.Attrs {
		smartAttr := new(types.DAttrTable)
		smartAttr.ID = int(smart.Id)
		smartAttr.Flags = int(smart.Flags)
		smartAttr.RawValue = int(smart.VendorBytes[0])
		smartAttr.Value = int(smart.Value)
		smartAttr.Worst = int(smart.Worst)
		diskInfo.SmartAttrs = append(diskInfo.SmartAttrs, smartAttr)
	}

	diskInfo.ModelNumber = devIdentify.ModelNumber()
	log.Noticef("Model number before massaging %s", diskInfo.ModelNumber)
	model := []byte(diskInfo.ModelNumber)
	diskInfo.ModelNumber = string(massageCompatible(model))
	log.Noticef("Model number after massaging %s", diskInfo.ModelNumber)

	diskInfo.SerialNumber = devIdentify.SerialNumber()
	log.Noticef("Serial number before massaging %s", diskInfo.SerialNumber)
	sn := []byte(diskInfo.SerialNumber)
	diskInfo.SerialNumber = string(massageCompatible(sn))
	log.Noticef("Serial number after massaging %s", diskInfo.SerialNumber)

	diskInfo.Wwn = devIdentify.WWN()
	diskInfo.TimeUpdate = uint64(time.Now().Unix())
	diskInfo.CollectingStatus = types.SmartCollectingStatusSuccess
	return diskInfo, nil
}

// GetInfoFromNVMeDisk - takes a disk name (/dev/sda or /dev/nvme0n1)
// as input and returns information on it
func GetInfoFromNVMeDisk(diskName string) (*types.DiskSmartInfo, error) {
	diskInfo := new(types.DiskSmartInfo)

	dev, err := smart.OpenNVMe(diskName)
	if err != nil {
		diskInfo.DiskName = diskName
		diskInfo.Errors = fmt.Errorf("failed open NVMe device with name: %s; error:%v", diskName, err)
		diskInfo.CollectingStatus = types.SmartCollectingStatusError
		diskInfo.TimeUpdate = uint64(time.Now().Unix())
		return diskInfo, diskInfo.Errors
	}
	defer dev.Close()

	identController, _, err := dev.Identify()
	if err != nil {
		diskInfo.DiskName = diskName
		diskInfo.Errors = fmt.Errorf("failed  NVMe identifye error:%v", err)
		diskInfo.CollectingStatus = types.SmartCollectingStatusError
		diskInfo.TimeUpdate = uint64(time.Now().Unix())
		return diskInfo, diskInfo.Errors
	}

	diskInfo.DiskName = diskName
	diskInfo.DiskType = types.SmartDiskTypeNvme
	diskInfo.ModelNumber = identController.ModelNumber()
	diskInfo.SerialNumber = identController.SerialNumber()

	smartAttr, err := dev.ReadSMART()
	if err != nil {
		diskInfo.Errors = fmt.Errorf("failed read S.M.A.R.T. attr info from NVMe device with name: %s; error:%v", diskName, err)
		diskInfo.CollectingStatus = types.SmartCollectingStatusError
		diskInfo.TimeUpdate = uint64(time.Now().Unix())
		return diskInfo, diskInfo.Errors
	}

	smartTemperature := new(types.DAttrTable)
	smartTemperature.ID = types.SmartAttrIDTemperatureCelsius
	smartTemperature.RawValue = int(smartAttr.Temperature)
	diskInfo.SmartAttrs = append(diskInfo.SmartAttrs, smartTemperature)

	smartPowerOnHours := new(types.DAttrTable)
	smartPowerOnHours.ID = types.SmartAttrIDPowerOnHours
	smartPowerOnHours.RawValue = int(smartAttr.PowerOnHours.Val[0])
	diskInfo.SmartAttrs = append(diskInfo.SmartAttrs, smartPowerOnHours)

	smartPowerCycles := new(types.DAttrTable)
	smartPowerCycles.ID = types.SmartAttrIDPowerCycleCount
	smartPowerCycles.RawValue = int(smartAttr.PowerCycles.Val[0])
	diskInfo.SmartAttrs = append(diskInfo.SmartAttrs, smartPowerCycles)
	diskInfo.TimeUpdate = uint64(time.Now().Unix())
	diskInfo.CollectingStatus = types.SmartCollectingStatusSuccess

	return diskInfo, nil
}

// GetInfoFromSCSIDisk - takes a disk name (/dev/sda or /dev/nvme0n1)
// as input and returns information on it
func GetInfoFromSCSIDisk(diskName string) (*types.DiskSmartInfo, error) {
	diskInfo := new(types.DiskSmartInfo)

	dev, err := smart.OpenScsi(diskName)
	if err != nil {
		diskInfo.DiskName = diskName
		diskInfo.Errors = fmt.Errorf("failed open SCSI device with name: %s; error:%v", diskName, err)
		diskInfo.CollectingStatus = types.SmartCollectingStatusError
		diskInfo.TimeUpdate = uint64(time.Now().Unix())
		return diskInfo, diskInfo.Errors
	}
	defer dev.Close()

	diskInfo.DiskName = diskName
	diskInfo.DiskType = types.SmartDiskTypeScsi
	diskInfo.SerialNumber, err = dev.SerialNumber()
	if err != nil {
		diskInfo.Errors = fmt.Errorf("failed get SCSI device with name: %s; error:%v", diskName, err)
		diskInfo.CollectingStatus = types.SmartCollectingStatusError
		diskInfo.TimeUpdate = uint64(time.Now().Unix())
		return diskInfo, diskInfo.Errors
	}
	diskInfo.TimeUpdate = uint64(time.Now().Unix())
	diskInfo.CollectingStatus = types.SmartCollectingStatusSuccess

	return diskInfo, nil
}

// GetSerialNumberForDisk takes a disk name (from dev directory,
// for example /dev/sda or /dev/sda1) as input and return serial number
func GetSerialNumberForDisk(diskName string) (string, error) {
	dev, err := smart.Open(diskName)
	if err != nil {
		return "", fmt.Errorf("disk with name: %s have unknown type", diskName)
	}
	diskType := dev.Type()
	dev.Close()

	var diskSmartInfo *types.DiskSmartInfo

	if diskType == "sata" {
		diskSmartInfo, err = GetInfoFromSATAdisk(diskName)
		if err != nil {
			return "", err
		}
	} else if diskType == "nvme" {
		diskSmartInfo, err = GetInfoFromNVMeDisk(diskName)
		if err != nil {
			return "", err
		}
	} else if diskType == "scsi" {
		diskSmartInfo, err = GetInfoFromSCSIDisk(diskName)
		if err != nil {
			return "", err
		}
	} else {
		return "",
			fmt.Errorf("failed to get serial number for %s disk with type %s", diskName, diskType)
	}

	return diskSmartInfo.SerialNumber, nil
}
