/*
 * Copyright (c) 2022. Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package hardware

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	smart "github.com/anatol/smart.go"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

var (
	maxSmartCtlSize = 65536
	diskInfoDir     = "/persist/disks_info"
	pathDisksList   = "/persist/disks_info/SMART_device.json"
	cmd             = "/usr/sbin/smartctl"
)

// getPathForFileDisk return path for JSON file
// with S.M.A.R.T info for diskName
//
// "/dev/sda" -> "/persist/disks_info/-dev-sda.json"
func getPathForFileDisk(diskName string) string {
	return filepath.Join(diskInfoDir,
		strings.Replace(fmt.Sprintf("%s.json", diskName), "/", "-", -1))
}

func smartctlExec(filePath string, args ...string) error {
	jsonData, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("run command %s %v failed %v", cmd, args, err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("unable to create file: %v, err: %v", filePath, err)
	}
	defer file.Close()

	_, err = file.WriteString(string(jsonData))
	if err != nil {
		return fmt.Errorf("unable to write data in file: %v, err: %v", filePath, err)
	}

	return nil
}

// readFWithMaxSize returns the content but limits the size to maxReadSize
func readFWithMaxSize(filename string, maxReadSize int) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		err = fmt.Errorf("ReadWithMaxSize %s failed: %v", filename, err)
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	content := make([]byte, maxReadSize)
	n, err := r.Read(content)
	if err != nil {
		err = fmt.Errorf("ReadWithMaxSize %s failed: %v", filename, err)
		return nil, err
	}
	if n == maxReadSize {
		err = fmt.Errorf("ReadWithMaxSize %s truncated after %d bytes",
			filename, maxReadSize)
	} else {
		err = nil
	}
	return content[0:n], err
}

// GetDisksListFromSmartCtl returns a structure DisksList
func GetDisksListFromSmartCtl() (*types.DisksList, error) {
	args := []string{"--scan", "--json"}
	if err := smartctlExec(pathDisksList, args...); err != nil {
		return nil, fmt.Errorf("get disks list from smartctl filed. err: %s", err)
	}

	disks := new(types.DisksList)
	data, err := readFWithMaxSize(pathDisksList, maxSmartCtlSize)
	if err != nil {
		return nil, fmt.Errorf("read file %s filed. err: %s", pathDisksList, err)
	}

	if err := json.Unmarshal(data, &disks); err != nil {
		return nil, fmt.Errorf("error while parsing SMART data. file:%s err:%s", pathDisksList, err)
	}

	if disks.Smartctl.ExitStatus != 0 {
		return nil, fmt.Errorf("error-code: %d, info:%v",
			disks.Smartctl.ExitStatus,
			disks.Smartctl.Messages)
	}

	return disks, nil
}

func getAttrFromJSON(attrList types.SmartAttributes, id int) *info.SmartAttr {
	for _, data := range attrList.Table {
		if data.ID == id {
			attr := new(info.SmartAttr)
			attr.Id = uint32(data.ID)
			attr.Value = uint64(data.Value)
			attr.Worst = uint64(data.Worst)
			attr.Thresh = uint64(data.Thresh)
			attr.WhenFailed = data.WhenFailed
			attr.RawValue = uint64(data.Raw.Value)
			return attr
		}
	}
	return nil
}

func getSmartAttr(attrList types.SmartAttributes) *info.SmartMetric {
	smart := new(info.SmartMetric)
	smart.CurrentPendingSector = getAttrFromJSON(attrList, types.SMART_ATTR_ID_CURRENT_PENDING_SECTOR_CT)
	smart.PowerCycleCount = getAttrFromJSON(attrList, types.SMART_ATTR_ID_POWER_CYCLE_COUNT)
	smart.PowerOnHours = getAttrFromJSON(attrList, types.SMART_ATTR_ID_POWER_ON_HOURS)
	smart.ReallocatedSectorCt = getAttrFromJSON(attrList, types.SMART_ATTR_ID_REAL_LOCATED_SECTOR_CT)
	return smart
}

// ReadDiskSmartInfoFromJSON read JSON file and return *types.DeviceSmartInfo
func ReadDiskSmartInfoFromJSON(diskName string) (*types.DeviceSmartInfo, error) {
	path := getPathForFileDisk(diskName)
	data, err := readFWithMaxSize(path, maxSmartCtlSize)
	if err != nil {
		return nil, fmt.Errorf("read file with SMART info for %s disk failed. %s", path, err)
	}

	deviceInfo := new(types.DeviceSmartInfo)
	if err := json.Unmarshal(data, &deviceInfo); err != nil {
		return nil, fmt.Errorf("error while parsing SMART data. %s", err)
	}

	if deviceInfo.Smartctl.ExitStatus != 0 {
		return nil, fmt.Errorf("error-code: %d, info:%v",
			deviceInfo.Smartctl.ExitStatus,
			deviceInfo.Smartctl.Messages)
	}

	return deviceInfo, nil
}

// getAndComparisonSmartDataForDisk takes a disk name as input, then tries
// to collect old data and get new data, compares if necessary and
// always returns new data in the form of:
//
// *types.DeviceSmartInfo - regardless of the result, we always send last new data,
// except for situations with errors when receiving this data
//
// bool - Need to update information, true - necessary, false - data is the same
//
// error - Errors with getting new data, if any
func getAndComparisonSmartDataForDisk(diskName string) (*types.DeviceSmartInfo, bool, error) {
	needUpdate := false
	oldData, err := ReadDiskSmartInfoFromJSON(diskName)
	if err != nil {
		// it's normal situation
		needUpdate = true
	}

	// Get new S.M.A.R.T data for disks
	args := []string{"--all", diskName, "--json"}
	pathFile := getPathForFileDisk(diskName)
	if err := smartctlExec(pathFile, args...); err != nil {
		return nil, false, fmt.Errorf("get disk info from smartctl filed. err: %s", err)
	}

	newData, err := ReadDiskSmartInfoFromJSON(diskName)
	if err != nil {
		return nil, false, fmt.Errorf("new SMART data for disk %s not found", diskName)
	}

	if needUpdate {
		return newData, needUpdate, nil // no have old info, need send new info
	}

	if reflect.DeepEqual(oldData, newData) {
		needUpdate = false // the data is the same
	} else {
		needUpdate = true
	}

	// Regardless of the result, we always send last new data
	return newData, needUpdate, nil
}

// GetStorageDiskInfo takes a disk name as input, returns info.StorageDiskInfo
// сollects disks information via smartctl tools
func GetStorageDiskInfo(diskName string) (*info.StorageDiskInfo, error) {
	stDiskInfo := new(info.StorageDiskInfo)
	deviceInfo, _, err := getAndComparisonSmartDataForDisk(diskName)
	if err != nil {
		return nil, err
	}

	//if needUpdate {
	//	Here, if needed in the future, can implement
	//	logic with a reaction to data changes.
	//	But now the data will be sent anyway.
	//}

	stDiskInfo.DiskName = deviceInfo.Device.Name
	stDiskInfo.SerialNumber = deviceInfo.SerialNumber
	stDiskInfo.Model = deviceInfo.ModelName
	stDiskInfo.Wwn = fmt.Sprintf("%x%x%x",
		deviceInfo.Wwn.Naa,
		deviceInfo.Wwn.Oui,
		deviceInfo.Wwn.ID)
	stDiskInfo.SmartData = append(stDiskInfo.SmartData,
		getSmartAttr(deviceInfo.AtaSmartAttributes))
	return stDiskInfo, nil
}

// ReadSMARTinfoforDisks - сollects disks information via API,
// returns types.DisksInformation
func ReadSMARTinfoForDisks() (*types.DisksInformation, error) {
	disksInfo := new(types.DisksInformation)

	// Get information about disks
	list, err := GetDisksListFromSmartCtl()
	if err != nil {
		return disksInfo, fmt.Errorf("failed get list with disks err: %v", err)
	}

	for _, disk := range list.Devices {
		var diskSmartInfo *types.DiskSmartInfo

		dev, err := smart.Open(disk.Name)
		if err != nil {
			return disksInfo, fmt.Errorf("failed open disk %s err: %v", disk.Name, err)
		}
		diskType := dev.Type()
		dev.Close()

		if diskType == "sata" {
			diskSmartInfo, err = getInfoFromSATAdisk(disk.Name)
			if err != nil {
				disksInfo.Disks = append(disksInfo.Disks, diskSmartInfo)
				continue
			}
		} else if diskType == "nvme" {
			diskSmartInfo, err = getInfoFromNVMeDisk(disk.Name)
			if err != nil {
				disksInfo.Disks = append(disksInfo.Disks, diskSmartInfo)
				continue
			}
		}

		disksInfo.Disks = append(disksInfo.Disks, diskSmartInfo)
	}
	return disksInfo, nil
}

// getInfoFromSATAdisk - tеakes a disk name as input
// and returns information on it
func getInfoFromSATAdisk(diskName string) (*types.DiskSmartInfo, error) {
	diskInfo := new(types.DiskSmartInfo)
	dev, err := smart.OpenSata(diskName)
	if err != nil {
		diskInfo.Errors = fmt.Errorf("failed open SATA device with name: %s; error:%v", diskName, err)
		diskInfo.CollectingStatus = types.SMART_COLLECTING_STATUS_ERROR
		diskInfo.TimeUpdate = uint64(time.Now().Unix())
		return diskInfo, diskInfo.Errors

	}
	defer dev.Close()

	diskInfo.DiskName = diskName
	diskInfo.DiskType = types.SMART_SATA_DISK_TYPE

	devIdentify, err := dev.Identify()
	if err != nil {
		diskInfo.Errors = fmt.Errorf("failed identify SATA device with name: %s; error:%v", diskName, err)
		diskInfo.CollectingStatus = types.SMART_COLLECTING_STATUS_ERROR
		diskInfo.TimeUpdate = uint64(time.Now().Unix())
		return diskInfo, diskInfo.Errors
	}

	smartAttrList, err := dev.ReadSMARTData()
	if err != nil {
		diskInfo.Errors = fmt.Errorf("failed read S.M.A.R.T. attr info from SATA device with name: %s; error:%v", diskName, err)
		diskInfo.CollectingStatus = types.SMART_COLLECTING_STATUS_ERROR
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
	diskInfo.SerialNumber = devIdentify.SerialNumber()
	diskInfo.Wwn = devIdentify.WWN()
	diskInfo.TimeUpdate = uint64(time.Now().Unix())
	diskInfo.CollectingStatus = types.SMART_COLLECTING_STATUS_SUCCESS
	return diskInfo, nil
}

// getInfoFromNVMeDisk - tеakes a disk name as input
// and returns information on it
func getInfoFromNVMeDisk(diskName string) (*types.DiskSmartInfo, error) {
	diskInfo := new(types.DiskSmartInfo)

	dev, err := smart.OpenNVMe(diskName)
	if err != nil {
		diskInfo.Errors = fmt.Errorf("failed open NVMe device with name: %s; error:%v", diskName, err)
		diskInfo.CollectingStatus = types.SMART_COLLECTING_STATUS_ERROR
		return diskInfo, diskInfo.Errors
	}

	identController, _, err := dev.Identify()
	if err != nil {
		diskInfo.Errors = fmt.Errorf("failed  NVMe identifye error:%v", err)
		diskInfo.CollectingStatus = types.SMART_COLLECTING_STATUS_ERROR
		return diskInfo, diskInfo.Errors
	}

	diskInfo.DiskName = diskName
	diskInfo.DiskType = types.SMART_NVME_DISK_TYPE
	diskInfo.ModelNumber = identController.ModelNumber()
	diskInfo.SerialNumber = identController.SerialNumber()

	/* 	smartAttr, err := dev.ReadSMART()
	   	if err != nil {
	   		diskInfo.errors = fmt.Errorf("failed read S.M.A.R.T. attr info from NVMe device with name: %s; error:%v", diskName, err)
	   		diskInfo.collectingStatus = types.SMART_COLLECTING_STATUS_ERROR
	   		diskInfo.timeUpdate = uint64(time.Now().Unix())
	   		return diskInfo, diskInfo.errors
	   	} */

	return diskInfo, nil
}
