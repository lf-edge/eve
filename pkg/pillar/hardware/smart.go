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
		6:   "Read_Channel_Margin",
		7:   "Seek_Error_Rate",
		8:   "Seek_Time_Perf",
		9:   "Power_On_Hours",
		10:  "Spin_Retry_Count",
		11:  "Recalibration_Retries",
		12:  "Power_Cycle_Count",
		13:  "Soft_Read_Error_Rate",
		22:  "Current_Helium_Level",
		23:  "Helium_Condition_Lower",
		24:  "Helium_Condition_Upper",
		171: "SSD_Program_Fail_Count",
		172: "SSD_Erase_Fail_Count",
		173: "SSD_Wear_Leveling_Count",
		174: "Unexpected_Power_Loss_Count",
		175: "Power_Loss_Protection_Failure",
		176: "Erase_Fail_Count",
		177: "Wear_Leveling_Count",
		178: "Used_Reserved_Block_Count",
		179: "Used_Rsvd_Blk_Cnt_Tot",
		180: "Unused_Reserved_Block_Count_sTotal",
		181: "Program_Fail_Cnt_Total",
		182: "Erase_Fail_Count_Total",
		183: "Runtime_Bad_Block",
		184: "IOEDC",
		185: "Head_Stability",
		186: "Induced_Op-Vibration_Detection",
		187: "Uncorrectable_Error_Cnt",
		188: "Command_Timeout",
		189: "High_Fly_Writes",
		190: "Airflow_Temperature_Cel",
		191: "G-sense_Error_Rate",
		192: "Power-Off_Retract_Count",
		193: "Load_Cycle_Count",
		194: "Temperature_Celsius",
		195: "ECC_Error_Rate",
		196: "Reallocation_Event_Count",
		197: "Current_Pending_Sector",
		198: "Offline_Uncorrectable",
		199: "CRC_Error_Count",
		200: "Multi_Zone_Error_Rate",
		201: "Soft_Read_Error_Rate_or",
		202: "Data_Address_Mark_errors",
		203: "Run_Out_Cancel",
		204: "Soft_ECC_Correction",
		205: "Thermal_Asperity_Rate",
		206: "Flying_Height",
		207: "Spin_High_Current",
		208: "Spin_Buzz",
		209: "Offline_Seek_Perf",
		210: "Vibration_During_Write",
		211: "Vibration_During_Write",
		212: "Shock_During_Write",
		220: "Disk_Shift",
		221: "G-Sense_Error_Rate",
		222: "Loaded_Hours",
		223: "Load/Unload_Retry_Cnt",
		224: "Load_Friction",
		225: "Load/Unload_Cycle_Cnt",
		226: "Load_In-time",
		227: "Torque_Amplification_Cnt",
		228: "Power-Off_Retract_Cycle",
		230: "GMR_Head_Amplitude",
		231: "Life_Left_(SSDs)",
		232: "Endurance_Remaining",
		233: "Media_Wearout_Indicator_(SSDs)",
		234: "Average_Max_erase_cnt",
		235: "POR_Recovery_Count",
		240: "Head_Flying_Hours",
		241: "Total_LBAs_Written",
		242: "Total_LBAs_Read",
		243: "Total_LBAs_Written_Expanded",
		244: "Total_LBAs_Read_Expanded",
		245: "Remaining_Rated_Write_Endurance",
		246: "Cumulative_host_sectors_written",
		247: "Host_program_page_cnt",
		248: "Bg_program_page_cnt",
		249: "NAND_Writes_(1GiB)",
		250: "Read_Error_Retry_Rate",
		251: "Min_Spares_Remaining",
		252: "Newly_Added_Bad_Flash_Block",
		254: "Free_Fall_Protection",
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
		// Decode RAW_VALUE based on known special attribute formats
		switch smart.Id {
		case 190, 194:
			// Temperature: only the first byte is the current temperature in °C
			smartAttr.RawValue = int(smart.VendorBytes[0])

		case 240:
			// Head_Flying_Hours: smartmontools uses first 3 bytes as a uint
			smartAttr.RawValue = int(smart.VendorBytes[0]) |
				int(smart.VendorBytes[1])<<8 |
				int(smart.VendorBytes[2])<<16

		default:
			// convert 6-byte byte array to the raw value (little-endian)
			smartAttr.RawValue = int(
				uint64(smart.VendorBytes[0]) |
					uint64(smart.VendorBytes[1])<<8 |
					uint64(smart.VendorBytes[2])<<16 |
					uint64(smart.VendorBytes[3])<<24 |
					uint64(smart.VendorBytes[4])<<32 |
					uint64(smart.VendorBytes[5])<<40)
		}
		smartAttr.Value = int64(smart.Current)
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
		smartEntry.AttributeName = fieldType.Name // Use the field name as the attribute name
		smartEntry.RawValue = rawValue            // Store the extracted value
		smartEntry.Value = int64(rawValue)        // Store the extracted value
		if "Temperature" == smartEntry.AttributeName {
			// Convert temperature from Kelvin to Celsius
			smartEntry.Value = int64(rawValue - 273)
		}
		diskInfo.SmartAttrs = append(diskInfo.SmartAttrs, smartEntry) // Append to the list of SMART attributes
	}

	// Add individual temperature sensors
	for i, t := range smartAttr.TempSensor {
		if t == 0 {
			break
		}
		attr := &types.DAttrTable{
			AttributeName: fmt.Sprintf("Temperature Sensor %d", i+1),
			RawValue:      int(t),
			Value:         int64(t - 273),
		}
		diskInfo.SmartAttrs = append(diskInfo.SmartAttrs, attr)
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
