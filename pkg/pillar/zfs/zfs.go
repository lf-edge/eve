// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfs

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	libzfs "github.com/bicomsystems/go-libzfs"
	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/disks"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	log "github.com/sirupsen/logrus"
)

const volBlockSize = uint64(16 * 1024)

var (
	zfsPath   = []string{"/hostfs", "zfs"}
	zpoolPath = []string{"/hostfs", "zpool"}
)

//CreateDataset creates an empty dataset
func CreateDataset(log *base.LogObject, dataset string) (string, error) {
	args := append(zfsPath, "create", "-p", dataset)
	stdoutStderr, err := base.Exec(log, vault.ZfsPath, args...).CombinedOutput()
	return string(stdoutStderr), err
}

//MountDataset mounts dataset
func MountDataset(log *base.LogObject, dataset string) (string, error) {
	args := append(zfsPath, "mount", dataset)
	stdoutStderr, err := base.Exec(log, vault.ZfsPath, args...).CombinedOutput()
	return string(stdoutStderr), err
}

// GetZfsStatusStr returns detailed status of pool
func GetZfsStatusStr(log *base.LogObject, pool string) string {
	args := append(zpoolPath, "status", pool)
	stdoutStderr, err := base.Exec(log, vault.ZfsPath, args...).CombinedOutput()
	if err != nil {
		log.Errorf("zpool status error: %s", err)
		return ""
	}
	var status []string
	inStatus := false
	scanner := bufio.NewScanner(strings.NewReader(string(stdoutStderr)))
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		// we expect 'status:' in the beginning to start capture output
		if strings.HasPrefix(strings.TrimSpace(text), "status:") {
			inStatus = true
			text = strings.TrimPrefix(text, "status:")
		} else
		// status ends with 'action:' or 'config:' in the beginning of the line
		if strings.HasPrefix(text, "action:") ||
			strings.HasPrefix(text, "config:") {
			break
		}
		if inStatus {
			status = append(status, strings.TrimSpace(text))
		}
	}
	return strings.Join(status, " ")
}

//DestroyDataset removes dataset from zfs
//it runs 3 times in case of errors (we can hit dataset is busy)
func DestroyDataset(log *base.LogObject, dataset string) (string, error) {
	args := append(zfsPath, "destroy", dataset)
	var err error
	var stdoutStderr []byte
	tries := 0
	maxTries := 3
	for {
		stdoutStderr, err = base.Exec(log, vault.ZfsPath, args...).CombinedOutput()
		if err == nil {
			return string(stdoutStderr), nil
		}
		tries++
		if tries > maxTries {
			break
		}
		time.Sleep(time.Second)
	}
	return string(stdoutStderr), err
}

//GetDatasetOptions get dataset options from zfs
//will return error if not exists
func GetDatasetOptions(log *base.LogObject, dataset string) (map[string]string, error) {
	args := append(zfsPath, "get", "-Hp", "-o", "property,value", "all", dataset)
	stdoutStderr, err := base.Exec(log, vault.ZfsPath, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("cannot obtain options of %s, output=%s, error=%s",
			dataset, stdoutStderr, err)
	}
	processedValues := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(stdoutStderr)))
	for scanner.Scan() {
		err = nil
		currentLine := scanner.Text()
		split := strings.Split(currentLine, "\t")
		if len(split) < 2 {
			return nil, fmt.Errorf("cannot process line %s: not in format <key>\\t<value>", currentLine)
		}
		processedValues[split[0]] = split[1]
	}
	return processedValues, nil
}

//GetDatasetOption get dataset option value from zfs
//will return error if not exists
func GetDatasetOption(log *base.LogObject, dataset string, option string) (string, error) {
	args := append(zfsPath, "get", "-Hp", "-o", "value", option, dataset)
	stdoutStderr, err := base.Exec(log, vault.ZfsPath, args...).CombinedOutput()
	if err != nil {
		return string(stdoutStderr), err
	}
	return strings.TrimSpace(string(stdoutStderr)), nil
}

//CreateVolumeDataset creates dataset of zvol type in zfs
func CreateVolumeDataset(log *base.LogObject, dataset string, size uint64, compression string) (string, error) {
	alignedSize := alignUpToBlockSize(size)

	args := append(zfsPath, "create", "-p",
		"-V", strconv.FormatUint(alignedSize, 10),
		"-o", "volmode=dev",
		"-o", fmt.Sprintf("compression=%s", compression),
		"-o", fmt.Sprintf("volblocksize=%d", volBlockSize),
		"-o", "logbias=throughput",
		"-o", "redundant_metadata=most",
		dataset)

	stdoutStderr, err := base.Exec(log, vault.ZfsPath, args...).CombinedOutput()
	if err != nil {
		return string(stdoutStderr), err
	}
	return string(stdoutStderr), nil
}

//GetVolumesInDataset obtains volumes list from dataset
func GetVolumesInDataset(log *base.LogObject, dataset string) ([]string, error) {
	args := append(zfsPath, "list", "-Hr",
		"-o", "name",
		"-t", "volume",
		dataset)
	stdoutStderr, err := base.Exec(log, vault.ZfsPath, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("GetVolumesInDataset: output=%s error=%s", stdoutStderr, err)
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(stdoutStderr))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

//GetDatasetByDevice returns dataset for provided device path
func GetDatasetByDevice(device string) string {
	if !strings.HasPrefix(device, types.ZVolDevicePrefix) {
		return ""
	}
	return strings.TrimLeft(strings.TrimLeft(device, types.ZVolDevicePrefix), "/")
}

//GetZVolDeviceByDataset return path to device for provided dataset
func GetZVolDeviceByDataset(dataset string) string {
	return filepath.Join(types.ZVolDevicePrefix, dataset)
}

//GetZFSVolumeInfo provides information for zfs device
func GetZFSVolumeInfo(log *base.LogObject, device string) (*types.ImgInfo, error) {
	imgInfo := types.ImgInfo{
		Format:    "raw",
		Filename:  device,
		DirtyFlag: false,
	}
	dataset := GetDatasetByDevice(device)
	if dataset == "" {
		return nil, fmt.Errorf("GetDatasetByDevice returns empty for device: %s",
			device)
	}
	logicalreferenced, err := GetDatasetOption(log, dataset, "logicalreferenced")
	if err != nil {
		return nil, fmt.Errorf("GetZFSVolumeInfo GetDatasetOption failed: %s", err)
	}
	imgInfo.ActualSize, err = strconv.ParseUint(logicalreferenced, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("GetZFSVolumeInfo: failed to parse referenced: %s", err)
	}
	volSize, err := GetDatasetOption(log, dataset, "volsize")
	if err != nil {
		return nil, fmt.Errorf("GetZFSVolumeInfo GetDatasetOption failed: %s", err)
	}
	imgInfo.VirtualSize, err = strconv.ParseUint(volSize, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("GetZFSVolumeInfo: failed to parse volsize: %s", err)
	}
	volBlockSize, err := GetDatasetOption(log, dataset, "volblocksize")
	if err != nil {
		return nil, fmt.Errorf("GetZFSVolumeInfo GetDatasetOption failed: %s", err)
	}
	imgInfo.ClusterSize, err = strconv.ParseUint(volBlockSize, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("GetZFSVolumeInfo: failed to parse volblocksize: %s", err)
	}
	return &imgInfo, nil
}

func alignUpToBlockSize(size uint64) uint64 {
	return (size + volBlockSize - 1) & ^(volBlockSize - 1)
}

// GetZfsVersion return zfs kernel module version
func GetZfsVersion() (string, error) {
	dataBytes, err := ioutil.ReadFile("/hostfs/sys/module/zfs/version")
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("zfs-kmod-%s", strings.TrimSpace(string(dataBytes))), nil
}

// GetZfsCompressratio takes a zpool name as input and returns compressratio
// property for zpool
func GetZfsCompressratio(zpoolName string) (float64, error) {
	dataset, err := libzfs.DatasetOpen(zpoolName)
	if err != nil {
		return 0, fmt.Errorf("get zfs dataset for counting failed %v", err)
	}
	defer dataset.Close()

	compressratio, err := dataset.GetProperty(libzfs.DatasetPropCompressratio)
	if err != nil {
		return 0, fmt.Errorf("get property Compressratio for dataset %s failed %v", zpoolName, err)
	}

	return strconv.ParseFloat(compressratio.Value, 64)
}

func countingVolumesInDataset(count int, list libzfs.Dataset) (int, error) {
	for _, dataset := range list.Children {
		pr, err := dataset.GetProperty(libzfs.DatasetPropType)
		if err != nil {
			return count, fmt.Errorf("get property for dataset failed %v", err)
		}
		if pr.Value == "filesystem" {
			count, err = countingVolumesInDataset(count, dataset)
			if err != nil {
				return count, fmt.Errorf("get zfs dataset for counting failed %v", err)
			}
		} else if pr.Value == "volume" {
			count++
		}
	}
	return count, nil
}

// GetZfsCountVolume takes a datasetName name as input and returns the number of zvols.
// Returns 0 if there are no zvols or an have error.
func GetZfsCountVolume(datasetName string) (uint32, error) {
	count := 0
	dataset, err := libzfs.DatasetOpen(datasetName)
	if err != nil {
		return 0, fmt.Errorf("get zfs dataset for counting failed %v", err)
	}
	defer dataset.Close()

	count, err = countingVolumesInDataset(count, dataset)
	if err != nil {
		return uint32(count), err
	}

	return uint32(count), nil
}

// getRaidTypeFromStr takes a RAID name as input and returns current RAID type
func getRaidTypeFromStr(raidName string) info.StorageRaidType {
	if len(raidName) == 0 {
		return info.StorageRaidType_STORAGE_RAID_TYPE_NORAID
	} else if strings.Contains(raidName, "raidz1") {
		return info.StorageRaidType_STORAGE_RAID_TYPE_RAIDZ1
	} else if strings.Contains(raidName, "raidz2") {
		return info.StorageRaidType_STORAGE_RAID_TYPE_RAIDZ2
	} else if strings.Contains(raidName, "raidz3") {
		return info.StorageRaidType_STORAGE_RAID_TYPE_RAIDZ3
	} else if strings.Contains(raidName, "mirror") {
		return info.StorageRaidType_STORAGE_RAID_TYPE_RAID_MIRROR
	}

	return info.StorageRaidType_STORAGE_RAID_TYPE_NORAID
}

// GetZpoolRaidType takes a libzfs.VDevTree as input and returns current RAID type.
// At the moment, while will start from the fact that for one pool, have one RAID
func GetZpoolRaidType(vdevs libzfs.VDevTree) info.StorageRaidType {
	for _, vdev := range vdevs.Devices {
		if vdev.Type == libzfs.VDevTypeMirror || vdev.Type == libzfs.VDevTypeRaidz {
			return getRaidTypeFromStr(vdev.Name)
		}
		break
	}

	return info.StorageRaidType_STORAGE_RAID_TYPE_NORAID
}

// GetZfsDeviceStatusFromStr takes a string with status as input and returns status
func GetZfsDeviceStatusFromStr(statusStr string) info.StorageStatus {
	if len(statusStr) == 0 {
		return info.StorageStatus_STORAGE_STATUS_UNSPECIFIED
	} else if strings.TrimSpace(statusStr) == "ONLINE" {
		return info.StorageStatus_STORAGE_STATUS_ONLINE
	} else if strings.TrimSpace(statusStr) == "DEGRADED" {
		return info.StorageStatus_STORAGE_STATUS_DEGRADED
	} else if strings.TrimSpace(statusStr) == "FAULTED" {
		return info.StorageStatus_STORAGE_STATUS_FAULTED
	} else if strings.TrimSpace(statusStr) == "OFFLINE" {
		return info.StorageStatus_STORAGE_STATUS_OFFLINE
	} else if strings.TrimSpace(statusStr) == "UNAVAIL" {
		return info.StorageStatus_STORAGE_STATUS_UNAVAIL
	} else if strings.TrimSpace(statusStr) == "REMOVED" {
		return info.StorageStatus_STORAGE_STATUS_REMOVED
	} else if strings.TrimSpace(statusStr) == "SUSPENDED" {
		return info.StorageStatus_STORAGE_STATUS_SUSPENDED
	}

	return info.StorageStatus_STORAGE_STATUS_UNSPECIFIED
}

// GetZfsDiskAndStatus takes a libzfs.VDevTree as input and returns
// *info.StorageDiskState.
func GetZfsDiskAndStatus(disk libzfs.VDevTree) (*info.StorageDiskState, error) {
	if disk.Type != libzfs.VDevTypeDisk {
		return nil, fmt.Errorf("%s is not a disk", disk.Name)
	}
	rootDevice, err := disks.GetRootDevice()
	if err != nil {
		log.Errorf("cannot get root device: %s", err)
	}
	diskZfsName := disk.Name
	// ensure that we convert from partition to device
	diskName, err := disks.GetDiskNameByPartName(diskZfsName)
	if err != nil {
		log.Errorf("cannot get disk name for %s: %s", diskZfsName, err)
	} else {
		// check if zfs is not on partition of root device
		if diskName != rootDevice {
			diskZfsName = diskName
		}
	}

	serialNumber, err := hardware.GetSerialNumberForDisk(disk.Name)
	if err != nil {
		serialNumber = "unknown"
	}

	rDiskStatus := new(info.StorageDiskState)
	rDiskStatus.DiskName = new(evecommon.DiskDescription)
	rDiskStatus.DiskName.Name = *proto.String(diskZfsName)
	rDiskStatus.DiskName.Serial = *proto.String(serialNumber)
	rDiskStatus.Status = GetZfsDeviceStatusFromStr(disk.Stat.State.String())
	return rDiskStatus, nil
}
