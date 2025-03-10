/*
 * Copyright (c) 2022. Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package hardware

import (
	"fmt"
	"reflect"
	"time"

	smart "github.com/anatol/smart.go"
	"github.com/jaypipes/ghw"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

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
			diskSmartInfo, _ = GetInfoFromSATAdisk(diskName)
		} else if diskType == "nvme" {
			diskSmartInfo, _ = GetInfoFromNVMeDisk(diskName)
		} else if diskType == "scsi" {
			diskSmartInfo, _ = GetInfoFromSCSIDisk(diskName)
		} else {
			diskSmartInfo = getInfoFromUnknownDisk(diskName, diskType)
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

// getSmartType returns "Pre-fail" if the ATA attribute flag for pre-failure is set,
// otherwise it returns "Old_age". According to the ATA spec, if bit 0 (prefailure) is set,
// the attribute is considered a pre-fail attribute.
// I have found this in smartmontools repo https://github.com/smartmontools/smartmontools.git
// smartmontools/smartmontools/atacmds.h:164:#define ATTRIBUTE_FLAGS_PREFAILURE(x) (x & 0x01)
// smartmontools/smartmontools/ataprint.cpp:1302: (ATTRIBUTE_FLAGS_PREFAILURE(attr.flags) ? "Pre-fail" : "Old_age"),
func getSmartType(flags uint16) string {
	if flags&0x1 != 0 {
		return "Pre-fail"
	}
	return "Old_age"
}

func smartAttrMap(id uint8) string {
	var smartAttrMapping = map[uint8]string{
		1:   "Raw_Read_Error_Rate",
		3:   "Spin_Up_Time",
		4:   "Start_Stop_Count",
		5:   "Reallocated_Sector_Ct",
		7:   "Seek_Error_Rate",
		9:   "Power_On_Hours",
		10:  "Spin_Retry_Count",
		12:  "Power_Cycle_Count",
		177: "Wear_Leveling_Count",
		179: "Used_Rsvd_Blk_Cnt_Tot",
		181: "Program_Fail_Cnt_Total",
		182: "Erase_Fail_Count_Total",
		183: "Runtime_Bad_Block",
		187: "Uncorrectable_Error_Cnt",
		188: "Command_Timeout",
		190: "Airflow_Temperature_Cel",
		192: "Power-Off_Retract_Count",
		193: "Load_Cycle_Count",
		194: "Temperature_Celsius",
		195: "ECC_Error_Rate",
		197: "Current_Pending_Sector",
		198: "Offline_Uncorrectable",
		199: "CRC_Error_Count",
		200: "Multi_Zone_Error_Rate",
		235: "POR_Recovery_Count",
		240: "Head_Flying_Hours",
		241: "Total_LBAs_Written",
		242: "Total_LBAs_Read",
	}
	if name, ok := smartAttrMapping[id]; ok {
		return name
	}
	return "Unknown_Attribute"
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
		smartAttr.AttributeName = smartAttrMap(smart.Id)
		smartAttr.Flags = smart.Flags
		smartAttr.RawValue = int(smart.VendorBytes[0])
		smartAttr.Value = smart.ValueRaw
		smartAttr.Worst = smart.Worst
		smartAttr.Type = getSmartType(smart.Flags)
		diskInfo.SmartAttrs = append(diskInfo.SmartAttrs, smartAttr)
	}

	diskInfo.ModelNumber = devIdentify.ModelNumber()
	diskInfo.SerialNumber = devIdentify.SerialNumber()
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

	// processSmartAttributes extracts SMART attributes from the NvmeSMARTLog struct and stores them in diskInfo.
	// Use reflection to inspect the structure of smartAttr at runtime
	val := reflect.ValueOf(*smartAttr) // Get the actual values of the fields
	typ := reflect.TypeOf(*smartAttr)  // Get the metadata (field names, types, etc.)

	// Iterate through all fields in the struct
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)     // Get the value of the current field
		fieldType := typ.Field(i) // Get metadata about the current field

		// Extract the raw value from the field
		var rawValue int
		switch field.Kind() {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			// Directly convert unsigned integer types to int
			rawValue = int(field.Uint())
		case reflect.Struct:
			// This is not accurate but Uint128 is huge so it should be safe.
			// Special handling for Uint128 type: extract the first value (assuming Val[0] holds meaningful data)
			rawValue = int(field.FieldByName("Val").Index(0).Uint())
		default:
			// Skip unsupported field types
			continue
		}

		// Create a new SMART attribute entry and populate it with extracted values
		smartEntry := new(types.DAttrTable)
		smartEntry.AttributeName = fieldType.Name                     // Use the field name as the attribute name
		smartEntry.RawValue = rawValue                                // Store the extracted value
		diskInfo.SmartAttrs = append(diskInfo.SmartAttrs, smartEntry) // Append to the list of SMART attributes
	}

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

// CheckSMARTinfoForDisk - verifies that S.M.A.R.T info is available for a disk
// returns true or false depending on if S.M.A.R.T info is available
func CheckSMARTinfoForDisk(diskName string) string {
	_, err := smart.Open(diskName)
	if err == nil {
		return "passed"
	}
	return "failed"
}
