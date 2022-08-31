// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfs

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	libzfs "github.com/bicomsystems/go-libzfs"
	"github.com/golang/protobuf/proto"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/disks"
	"github.com/prometheus/procfs/blockdevice"
	log "github.com/sirupsen/logrus"
)

const volBlockSize = uint64(16 * 1024)

// CreateDataset creates an empty dataset
func CreateDataset(log *base.LogObject, dataset string) (string, error) {
	args := []string{"create", "-p", dataset}
	stdoutStderr, err := base.Exec(log, types.ZFSBinary, args...).CombinedOutput()
	return string(stdoutStderr), err
}

// MountDataset mounts dataset
func MountDataset(log *base.LogObject, dataset string) (string, error) {
	args := []string{"mount", dataset}
	stdoutStderr, err := base.Exec(log, types.ZFSBinary, args...).CombinedOutput()
	return string(stdoutStderr), err
}

// GetZfsStatusStr returns detailed status of pool
func GetZfsStatusStr(log *base.LogObject, pool string) string {
	args := []string{"status", pool}
	stdoutStderr, err := base.Exec(log, types.ZPoolBinary, args...).CombinedOutput()
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

// DestroyDataset removes dataset from zfs
// it runs 3 times in case of errors (we can hit dataset is busy)
func DestroyDataset(log *base.LogObject, dataset string) (string, error) {
	args := []string{"destroy", dataset}
	var err error
	var stdoutStderr []byte
	tries := 0
	maxTries := 3
	for {
		stdoutStderr, err = base.Exec(log, types.ZFSBinary, args...).CombinedOutput()
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

// DatasetExist return true if dataset exists or false when it does not exist
func DatasetExist(log *base.LogObject, datasetPath string) bool {
	dataset, err := libzfs.DatasetOpen(datasetPath)
	if err != nil {
		return false
	}
	defer dataset.Close()

	// Get one property to finally make sure that everything is in order.
	_, err = dataset.GetProperty(libzfs.DatasetPropName)
	if err != nil {
		log.Errorf("DatasetExist(%s): Get property name failed. %s",
			datasetPath, err.Error())
		return false
	}

	return true
}

// CreateVolumeDataset creates dataset of zvol type in zfs
func CreateVolumeDataset(log *base.LogObject, dataset string, size uint64, compression string) (string, error) {
	alignedSize := alignUpToBlockSize(size)

	args := []string{"create", "-p",
		"-V", strconv.FormatUint(alignedSize, 10),
		"-o", "volmode=dev",
		"-o", fmt.Sprintf("compression=%s", compression),
		"-o", fmt.Sprintf("volblocksize=%d", volBlockSize),
		"-o", "logbias=throughput",
		"-o", "redundant_metadata=most",
		dataset}

	stdoutStderr, err := base.Exec(log, types.ZFSBinary, args...).CombinedOutput()
	if err != nil {
		return string(stdoutStderr), err
	}
	return string(stdoutStderr), nil
}

func findVolumesInDataset(volumeList []string, list libzfs.Dataset) ([]string, error) {
	for _, dataset := range list.Children {
		pr, err := dataset.GetProperty(libzfs.DatasetPropType)
		if err != nil {
			return volumeList, fmt.Errorf("get property for dataset failed %v", err)
		}
		if pr.Value == "filesystem" {
			volumeList, err = findVolumesInDataset(volumeList, dataset)
			if err != nil {
				return volumeList, fmt.Errorf("get zfs dataset for counting failed %v", err)
			}
		} else if pr.Value == "volume" {
			propName, err := dataset.GetProperty(libzfs.DatasetPropName)
			if err != nil {
				return volumeList, err
			}
			volumeList = append(volumeList, propName.Value)
		}
	}
	return volumeList, nil
}

// GetVolumesFromDataset obtains volumes list from dataset
func GetVolumesFromDataset(datasetName string) ([]string, error) {
	var volumeList []string

	dataset, err := libzfs.DatasetOpen(datasetName)
	if err != nil {
		return volumeList,
			fmt.Errorf("get zfs dataset for counting failed %v", err)
	}
	defer dataset.Close()

	volumeList, err = findVolumesInDataset(volumeList, dataset)
	if err != nil {
		return volumeList, err
	}

	return volumeList, nil
}

// GetDatasetByDevice returns dataset for provided device path
func GetDatasetByDevice(device string) string {
	if !strings.HasPrefix(device, types.ZVolDevicePrefix) {
		return ""
	}
	return strings.TrimLeft(strings.TrimLeft(device, types.ZVolDevicePrefix), "/")
}

// GetZVolDeviceByDataset return path to device for provided dataset
func GetZVolDeviceByDataset(dataset string) string {
	return filepath.Join(types.ZVolDevicePrefix, dataset)
}

// GetZFSVolumeInfo provides information for zfs device
func GetZFSVolumeInfo(device string) (*types.ImgInfo, error) {
	imgInfo := types.ImgInfo{
		Format:    "raw",
		Filename:  device,
		DirtyFlag: false,
	}
	datasetFullName := GetDatasetByDevice(device)
	if datasetFullName == "" {
		return nil, fmt.Errorf("GetDatasetByDevice returns empty for device: %s",
			device)
	}

	// datasetFullName == persist/.../.../volume
	dataset, err := libzfs.DatasetOpen(datasetFullName)
	if err != nil {
		return nil,
			fmt.Errorf("open dataset %s error: %v", datasetFullName, err)
	}
	defer dataset.Close()

	propUsedds, err := dataset.GetProperty(libzfs.DatasetPropUsedds)
	if err != nil {
		return nil,
			fmt.Errorf("get property Usedbydataset for dataset: %s failed %w",
				datasetFullName, err)
	}
	imgInfo.ActualSize, err = strconv.ParseUint(propUsedds.Value, 10, 64)
	if err != nil {
		return nil,
			fmt.Errorf("GetZFSVolumeInfo: failed to parse Usedbydataset: %s", err)
	}

	propVolSize, err := dataset.GetProperty(libzfs.DatasetPropVolsize)
	if err != nil {
		return nil,
			fmt.Errorf("get property propVolSize for dataset %s failed %v",
				datasetFullName, err)
	}
	imgInfo.VirtualSize, err = strconv.ParseUint(propVolSize.Value, 10, 64)
	if err != nil {
		return nil,
			fmt.Errorf("GetZFSVolumeInfo: failed to parse volsize: %s", err)
	}

	propVolblocksize, err := dataset.GetProperty(libzfs.DatasetPropVolblocksize)
	if err != nil {
		return nil,
			fmt.Errorf("get property propVolblocksize for dataset %s failed %v",
				datasetFullName, err)
	}
	imgInfo.ClusterSize, err = strconv.ParseUint(propVolblocksize.Value, 10, 64)
	if err != nil {
		return nil,
			fmt.Errorf("GetZFSVolumeInfo: failed to parse volblocksize: %s", err)
	}

	return &imgInfo, nil
}

func alignUpToBlockSize(size uint64) uint64 {
	return (size + volBlockSize - 1) & ^(volBlockSize - 1)
}

//RemoveVDev removes vdev from the pool
func RemoveVDev(log *base.LogObject, pool, vdev string) (string, error) {
	args := []string{"remove", pool, vdev}
	stdoutStderr, err := base.Exec(log, types.ZPoolBinary, args...).CombinedOutput()
	if err != nil {
		return string(stdoutStderr), err
	}
	return strings.TrimSpace(string(stdoutStderr)), nil
}

//AttachVDev attach newVdev to existing vdev
func AttachVDev(log *base.LogObject, pool, vdev, newVdev string) (string, error) {
	args := []string{"attach", pool, vdev, newVdev}
	stdoutStderr, err := base.Exec(log, types.ZPoolBinary, args...).CombinedOutput()
	if err != nil {
		return string(stdoutStderr), err
	}
	return strings.TrimSpace(string(stdoutStderr)), nil
}

//AddVDev add newVdev to pool
func AddVDev(log *base.LogObject, pool, vdev string) (string, error) {
	args := []string{"add", "-f", pool, vdev}
	stdoutStderr, err := base.Exec(log, types.ZPoolBinary, args...).CombinedOutput()
	if err != nil {
		return string(stdoutStderr), err
	}
	return strings.TrimSpace(string(stdoutStderr)), nil
}

//ReplaceVDev replaces vdev from the pool
func ReplaceVDev(log *base.LogObject, pool, oldVdev, newVdev string) (string, error) {
	args := []string{"replace", pool, oldVdev, newVdev}
	stdoutStderr, err := base.Exec(log, types.ZPoolBinary, args...).CombinedOutput()
	if err != nil {
		return string(stdoutStderr), err
	}
	return strings.TrimSpace(string(stdoutStderr)), nil
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

// GetRaidTypeFromStr takes a RAID name as input and returns current RAID type
func GetRaidTypeFromStr(raidName string) types.StorageRaidType {
	if len(raidName) == 0 {
		return types.StorageRaidTypeNoRAID
	} else if strings.Contains(raidName, "raidz1") {
		return types.StorageRaidTypeRAID5
	} else if strings.Contains(raidName, "raidz2") {
		return types.StorageRaidTypeRAID6
	} else if strings.Contains(raidName, "raidz3") {
		return types.StorageRaidTypeRAID7
	} else if strings.Contains(raidName, "mirror") {
		return types.StorageRaidTypeRAID1
	}

	return types.StorageRaidTypeNoRAID
}

// GetZpoolRaidType takes a libzfs.VDevTree as input and returns current RAID type.
// return RAID0 in case of mixed topology as we can mix nested topology into the stripe
func GetZpoolRaidType(vdevs libzfs.VDevTree) types.StorageRaidType {
	vdevsCount := 0
	for _, vdev := range vdevs.Devices {
		if vdev.Type == libzfs.VDevTypeMirror || vdev.Type == libzfs.VDevTypeRaidz || vdev.Type == libzfs.VDevTypeDisk {
			vdevsCount++
		}
	}
	if vdevsCount > 1 {
		return types.StorageRaidTypeRAID0
	}
	for _, vdev := range vdevs.Devices {
		if vdev.Type == libzfs.VDevTypeMirror || vdev.Type == libzfs.VDevTypeRaidz {
			return GetRaidTypeFromStr(vdev.Name)
		}
		break
	}
	return types.StorageRaidTypeNoRAID
}

// GetZfsDeviceStatusFromStr takes a string with status as input and returns status
func GetZfsDeviceStatusFromStr(statusStr string) types.StorageStatus {
	if len(statusStr) == 0 {
		return types.StorageStatusUnspecified
	} else if strings.TrimSpace(statusStr) == "ONLINE" {
		return types.StorageStatusOnline
	} else if strings.TrimSpace(statusStr) == "DEGRADED" {
		return types.StorageStatusDegraded
	} else if strings.TrimSpace(statusStr) == "FAULTED" {
		return types.StorageStatusFaulted
	} else if strings.TrimSpace(statusStr) == "OFFLINE" {
		return types.StorageStatusOffline
	} else if strings.TrimSpace(statusStr) == "UNAVAIL" {
		return types.StorageStatusUnavail
	} else if strings.TrimSpace(statusStr) == "REMOVED" {
		return types.StorageStatusRemoved
	} else if strings.TrimSpace(statusStr) == "SUSPENDED" {
		return types.StorageStatusSuspended
	}

	return types.StorageStatusUnspecified
}

// GetZfsDeviceMetrics read libzfs.VDevStat and return metrics
// (*types.DiskMetrics) for only one device in zfs pool.
func GetZfsDeviceMetrics(stat libzfs.VDevStat, diskName string) *types.ZDeviceMetrics {
	devMetrics := new(types.ZDeviceMetrics)
	devMetrics.Alloc = stat.Alloc
	devMetrics.Space = stat.Space
	devMetrics.DSpace = stat.DSpace
	devMetrics.RSize = stat.RSize
	devMetrics.ESize = stat.ESize
	devMetrics.ChecksumErrors = stat.ChecksumErrors
	devMetrics.ReadErrors = stat.ReadErrors
	devMetrics.WriteErrors = stat.WriteErrors
	for i := 0; i < types.ZIOTypeMax; i++ {
		devMetrics.Ops[i] = stat.Ops[i]
		devMetrics.Bytes[i] = stat.Bytes[i]
	}

	// Only for block devices (Ex. /dev/sd*)
	if diskName != "" {
		shortName := filepath.Base(diskName)
		fs, err := blockdevice.NewFS("/proc", "/sys")
		if err != nil {
			log.Errorf("failed to get block device stats for %s. Error:%v", diskName, err)
			return devMetrics
		}
		stats, err := fs.ProcDiskstats()
		if err != nil {
			log.Errorf("failed to get diskstats %v", err)
			return devMetrics
		}

		for _, stat := range stats {
			if shortName == stat.Info.DeviceName {
				devMetrics.IOsInProgress = stat.IOStats.IOsInProgress
				devMetrics.ReadTicks = stat.IOStats.ReadTicks
				devMetrics.WriteTicks = stat.IOStats.WriteTicks
				devMetrics.IOsTotalTicks = stat.IOStats.IOsTotalTicks
				devMetrics.WeightedIOTicks = stat.IOStats.WeightedIOTicks
			}
		}
	}
	return devMetrics
}

// GetZfsDiskAndStatus takes a libzfs.VDevTree as input and returns
// *info.StorageDiskState.
func GetZfsDiskAndStatus(disk libzfs.VDevTree) (*types.StorageDiskState, error) {
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

	rDiskStatus := new(types.StorageDiskState)
	rDiskStatus.DiskName = new(types.DiskDescription)
	rDiskStatus.DiskName.Name = *proto.String(diskZfsName)
	rDiskStatus.DiskName.Serial = *proto.String(serialNumber)
	rDiskStatus.AuxState = types.VDevAux(disk.Stat.Aux + 1) // + 1 given the presence of VDevAuxUnspecified on the EVE side
	rDiskStatus.Status = GetZfsDeviceStatusFromStr(disk.Stat.State.String())
	return rDiskStatus, nil
}

// GetDatasetUsageStat returns UsageStat for provided datasetName
// for dataset with RefReservation it will return dataset.RefReservation as UsageStat.Total and UsageStat.Used
// for dataset without RefReservation it will calculate UsageStat.Total as sum of dataset.Used and dataset.Available
// and use dataset.LogicalUsed as UsageStat.Used to not count empty blocks of child zvols
func GetDatasetUsageStat(datasetName string) (*types.UsageStat, error) {
	var usageStat types.UsageStat
	dataset, err := libzfs.DatasetOpen(datasetName)
	if err != nil {
		return nil, err
	}
	defer dataset.Close()
	refReservation, err := dataset.GetProperty(libzfs.DatasetPropRefreservation)
	if err != nil {
		return nil, err
	}
	refReservationBytes, err := strconv.ParseUint(refReservation.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse used: %s", err)
	}
	// special case for dataset with reservation
	if refReservationBytes > 0 {
		usageStat.Total = refReservationBytes
		usageStat.Used = refReservationBytes
		usageStat.Free = 0
		return &usageStat, nil
	}
	used, err := dataset.GetProperty(libzfs.DatasetPropUsed)
	if err != nil {
		return nil, err
	}
	usedBytes, err := strconv.ParseUint(used.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse used: %s", err)
	}
	logicalUsed, err := dataset.GetProperty(libzfs.DatasetPropLogicalused)
	if err != nil {
		return nil, err
	}
	logicalUsedBytes, err := strconv.ParseUint(logicalUsed.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse logicalUsed: %s", err)
	}
	available, err := dataset.GetProperty(libzfs.DatasetPropAvailable)
	if err != nil {
		return nil, err
	}
	availableBytes, err := strconv.ParseUint(available.Value, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse available: %s", err)
	}
	usageStat.Total = usedBytes + availableBytes
	usageStat.Used = logicalUsedBytes
	usageStat.Free = usageStat.Total - usageStat.Used
	return &usageStat, nil
}

// GetAllDeviceMetricsFromZpool - returns metrics for all devices in zfs pool/dataset
func GetAllDeviceMetricsFromZpool(vdev libzfs.VDevTree) *types.ZFSPoolMetrics {
	metrics := new(types.ZFSPoolMetrics)
	// If this is a RAID or mirror, look at the disks it consists of
	if vdev.Type == libzfs.VDevTypeMirror ||
		vdev.Type == libzfs.VDevTypeRaidz ||
		vdev.Type == libzfs.VDevTypeRoot {
		for _, disk := range vdev.Devices {
			metrics.ChildrenDataset = append(metrics.ChildrenDataset,
				GetAllDeviceMetricsFromZpool(disk))
		}
		metrics.DisplayName = vdev.Name
		metrics.CollectionTime = time.Now()
		metrics.Metrics = GetZfsDeviceMetrics(vdev.Stat, "")
	} else if vdev.Type == libzfs.VDevTypeDisk {
		diskName, err := disks.GetDiskNameByPartName(vdev.Name)
		if err != nil {
			log.Errorf("cannot get disk name for %s: %s", vdev.Name, err)
			diskName = vdev.Name
		}
		metrics.DisplayName = diskName
		metrics.CollectionTime = time.Now()
		metrics.Metrics = GetZfsDeviceMetrics(vdev.Stat, vdev.Name)
	}
	return metrics
}
