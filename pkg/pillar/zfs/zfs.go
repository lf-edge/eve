// Copyright (c) 2021-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	libzfs "github.com/andrewd-zededa/go-libzfs"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/disks"
	"github.com/prometheus/procfs/blockdevice"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const volBlockSize = uint64(16 * 1024)

// taken from mkimage-raw-efi/install kubevirt RESERVE_EVE_STORAGE_SIZEGB
const reserveEveStorageSizeGb = uint64(20 * 1024 * 1024 * 1024)

// CreateDatasets - creates all the non-existing parent datasets.
// Datasets created in this manner are automatically mounted
// according to the mountpoint property inherited from their parent.
// Analogue of the "zfs create -p ..." command
func CreateDatasets(log *base.LogObject, datasetName string) error {
	dName := ""
	datasetParts := strings.Split(datasetName, "/")
	for _, el := range datasetParts {
		dName = filepath.Join(dName, el)
		if DatasetExist(log, dName) {
			continue
		} else {
			if err := CreateDataset(dName); err != nil {
				return err
			}
		}
	}

	return nil
}

// CreateDataset create and mount an empty dataset
func CreateDataset(datasetName string) error {
	props := make(map[libzfs.Prop]libzfs.Property)
	dataset, err := libzfs.DatasetCreate(datasetName,
		libzfs.DatasetTypeFilesystem, props)
	if err != nil {
		return err
	}
	defer dataset.Close()

	return MountDataset(datasetName)
}

// CreateSnapshot creates a snapshot of the dataset
// Returns the name of the created snapshot that can be used to rollback
func CreateSnapshot(datasetName string) (snapshotName string, err error) {
	now := time.Now()
	snapshotName = now.Format("20060102-150405")
	// add milliseconds to snapshot name
	snapshotName += fmt.Sprintf("%03d", now.Nanosecond()/int(time.Millisecond))
	snapshotPath := datasetName + "@" + snapshotName
	props := make(map[libzfs.Prop]libzfs.Property) // Just use default properties
	snap, err := libzfs.DatasetSnapshot(snapshotPath, true, props)
	if err != nil {
		return
	}
	defer snap.Close()
	snapshotName, err = snap.Path()
	return
}

// RollbackToSnapshot rolls back the dataset to the snapshot
func RollbackToSnapshot(datasetName, snapshotName string) error {
	// Find the snapshot dataset by name
	snap, err := libzfs.DatasetOpen(snapshotName)
	if err != nil {
		return err
	}
	defer snap.Close()
	dataset, err := libzfs.DatasetOpen(datasetName)
	if err != nil {
		return err
	}
	defer dataset.Close()
	// Rollback to the snapshot
	err = dataset.Rollback(&snap, false)
	return err
}

// IsDatasetTypeZvol returns true if dataset is a zvol
func IsDatasetTypeZvol(datasetName string) (bool, error) {
	dataset, err := libzfs.DatasetOpen(datasetName)
	if err != nil {
		return false, err
	}
	defer dataset.Close()
	return (dataset.Type == libzfs.DatasetTypeVolume), nil
}

// CreateVaultDataset create and mount an empty vault dataset
func CreateVaultDataset(datasetName, zfsKeyFile string) error {
	props := make(map[libzfs.Prop]libzfs.Property)

	props[libzfs.DatasetPropEncryption] = libzfs.Property{
		Value: "aes-256-gcm"}
	props[libzfs.DatasetPropKeyLocation] = libzfs.Property{
		Value: "file://" + zfsKeyFile}
	props[libzfs.DatasetPropKeyFormat] = libzfs.Property{
		Value: "raw"}

	dataset, err := libzfs.DatasetCreate(datasetName,
		libzfs.DatasetTypeFilesystem, props)
	if err != nil {
		return err
	}
	defer dataset.Close()

	return MountDataset(datasetName)
}

// GetDatasetAvailableBytes Read Zfs dataset 'available' space property, parse as uint64
func GetDatasetAvailableBytes(datasetName string) (uint64, error) {
	ds, err := libzfs.DatasetOpen(datasetName)
	if err != nil {
		return 0, fmt.Errorf("Open dataset %s failure: %v", datasetName, err)
	}
	defer ds.Close()
	zpoolPropAvailBytes, err := ds.GetProperty(libzfs.DatasetPropAvailable)
	if err != nil {
		return 0, fmt.Errorf("Read dataset %s available space failure: %v", datasetName, err)
	}
	size, err := strconv.ParseUint(zpoolPropAvailBytes.Value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("dataset %s available space parse failure: %v", datasetName, err)
	}
	return size, nil
}

// GetZvolPath Helper to build the /dev/zvol/<dataset> path
func GetZvolPath(datasetName string) string {
	return types.ZVolDevicePrefix + "/" + datasetName
}

// CreateVaultVolumeDataset Create an empty vault zvol
func CreateVaultVolumeDataset(log *base.LogObject, datasetName string, zfsKeyFile string, encrypted bool, sizeBytes uint64) error {
	// Shave off reserved + Can't align up if we're already at max space.
	sizeBytes = sizeBytes - reserveEveStorageSizeGb - (volBlockSize * 1024)
	alignedSize := alignUpToBlockSize(sizeBytes)
	props := make(map[libzfs.Prop]libzfs.Property)

	if encrypted {
		props[libzfs.DatasetPropEncryption] = libzfs.Property{
			Value: "aes-256-gcm"}
		props[libzfs.DatasetPropKeyLocation] = libzfs.Property{
			Value: "file://" + zfsKeyFile}
		props[libzfs.DatasetPropKeyFormat] = libzfs.Property{
			Value: "raw"}
	}
	props[libzfs.DatasetPropVolsize] = libzfs.Property{
		Value: strconv.FormatUint(alignedSize, 10)}
	props[libzfs.DatasetPropVolblocksize] = libzfs.Property{
		Value: strconv.FormatUint(volBlockSize, 10)}
	props[libzfs.DatasetPropVolmode] = libzfs.Property{
		Value: "dev"}
	props[libzfs.DatasetPropCompression] = libzfs.Property{
		Value: "zstd"}

	dataset, err := libzfs.DatasetCreate(datasetName, libzfs.DatasetTypeVolume, props)
	if err != nil {
		return fmt.Errorf("CreateVaultVolumeDataset datasetName:%s, zfsKeyFile:%s, size:%d, encrypted:%t, creation error:%v",
			datasetName, zfsKeyFile, sizeBytes, encrypted, err)
	}
	defer dataset.Close()
	return nil
}

// MountDataset mounts dataset
func MountDataset(datasetName string) error {
	dataset, err := libzfs.DatasetOpen(datasetName)
	if err != nil {
		return err
	}
	defer dataset.Close()

	mounted, where := dataset.IsMounted()
	if mounted {
		return fmt.Errorf("Dataset %s is already mounted at %s",
			datasetName, where)
	}

	// Mount on the same path as the name
	return dataset.Mount("", 0)
}

// UnmountDataset unmount this filesystem and any children
// inheriting the mountpoint property.
func UnmountDataset(datasetName string) error {
	dataset, err := libzfs.DatasetOpen(datasetName)
	if err != nil {
		return err
	}
	defer dataset.Close()

	mounted, _ := dataset.IsMounted()
	if !mounted {
		return nil
	}

	return dataset.UnmountAll(0)
}

// DestroyDataset removes dataset from zfs
// it runs 3 times in case of errors (we can hit dataset is busy)
func DestroyDataset(datasetName string) error {
	var err error
	var dataset libzfs.Dataset
	for i := 0; i < 3; i++ {
		dataset, err = libzfs.DatasetOpen(datasetName)
		if err != nil {
			// dataset does not exist
			return err
		}
		defer dataset.Close()

		// DestroyRecursive recursively destroy children of
		// dataset and this dataset.
		if err = dataset.DestroyRecursive(); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}

	return err
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

// SetReserved sets the reserved percentage. The datasetName is the
// parent (e.g., "persist").
func SetReserved(datasetName string, percentage uint64) error {
	usageStat, err := GetDatasetUsageStat(datasetName)
	if err != nil {
		log.Errorf("SetReserved get for %s failed: %s", datasetName, err)
		return err
	}
	datasetName += "/reserved"
	usageStatReserved, err := GetDatasetUsageStat(datasetName)
	if err != nil {
		log.Errorf("SetReserved get for %s failed: %s", datasetName, err)
		return err
	}
	reservation := usageStat.Total * percentage / 100
	log.Infof("Reserving %d current %d",
		reservation, usageStatReserved.Total)
	if reservation == usageStatReserved.Total {
		return nil
	}
	dataset, err := libzfs.DatasetOpen(datasetName)
	if err != nil {
		return err
	}
	defer dataset.Close()
	err = dataset.SetProperty(libzfs.DatasetPropRefreservation,
		strconv.FormatUint(reservation, 10))
	return err
}

// CreateVolumeDataset creates dataset of zvol type in zfs
func CreateVolumeDataset(log *base.LogObject, datasetName string, size uint64, compression string) error {
	alignedSize := alignUpToBlockSize(size)

	// Create fs datasets if they don't exist
	if err := CreateDatasets(log, filepath.Dir(datasetName)); err != nil {
		return err
	}

	props := make(map[libzfs.Prop]libzfs.Property)
	props[libzfs.DatasetPropVolsize] = libzfs.Property{
		Value: strconv.FormatUint(alignedSize, 10)}
	props[libzfs.DatasetPropVolblocksize] = libzfs.Property{
		Value: strconv.FormatUint(volBlockSize, 10)}
	props[libzfs.DatasetPropReservation] = libzfs.Property{
		Value: strconv.FormatUint(alignedSize, 10)}
	props[libzfs.DatasetPropVolmode] = libzfs.Property{
		Value: "dev"}
	props[libzfs.DatasetPropLogbias] = libzfs.Property{
		Value: "throughput"}
	props[libzfs.DatasetPropRedundantMetadata] = libzfs.Property{
		Value: "most"}
	props[libzfs.DatasetPropCompression] = libzfs.Property{
		Value: compression}

	dataset, err := libzfs.DatasetCreate(datasetName, libzfs.DatasetTypeVolume, props)
	if err != nil {
		return err
	}
	defer dataset.Close()

	return nil
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

// GetDatasetKeyStatus returns status of dataset key or error
func GetDatasetKeyStatus(datasetName string) (string, error) {
	dataset, err := libzfs.DatasetOpen(datasetName)
	if err != nil {
		return "", err
	}
	defer dataset.Close()

	keyStatus, err := dataset.GetProperty(libzfs.DatasetPropKeyStatus)
	if err != nil {
		return "",
			fmt.Errorf("DatasetExist(%s): Get property KeyStatus failed. %s",
				datasetName, err.Error())

	}

	return keyStatus.Value, nil
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

// RemoveVDev removes vdev from the pool
func RemoveVDev(log *base.LogObject, pool, vdev string) (string, error) {
	args := []string{"remove", pool, vdev}
	stdoutStderr, err := base.Exec(log, types.ZPoolBinary, args...).CombinedOutput()
	if err != nil {
		return string(stdoutStderr), err
	}
	return strings.TrimSpace(string(stdoutStderr)), nil
}

// AttachVDev attach newVdev to existing vdev
func AttachVDev(log *base.LogObject, pool, vdev, newVdev string) (string, error) {
	args := []string{"attach", pool, vdev, newVdev}
	stdoutStderr, err := base.Exec(log, types.ZPoolBinary, args...).CombinedOutput()
	if err != nil {
		return string(stdoutStderr), err
	}
	return strings.TrimSpace(string(stdoutStderr)), nil
}

// AddVDev add newVdev to pool
func AddVDev(log *base.LogObject, pool, vdev string) (string, error) {
	args := []string{"add", "-f", pool, vdev}
	stdoutStderr, err := base.Exec(log, types.ZPoolBinary, args...).CombinedOutput()
	if err != nil {
		return string(stdoutStderr), err
	}
	return strings.TrimSpace(string(stdoutStderr)), nil
}

// ReplaceVDev replaces vdev from the pool
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
	dataBytes, err := os.ReadFile("/hostfs/sys/module/zfs/version")
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

// GetZfsVDevMetrics read libzfs.VDevStat or /proc/diskstats
// and return metrics (*types.DiskMetrics) for only one device in zfs pool.
func GetZfsVDevMetrics(zStat libzfs.VDevStat, diskName string,
	fromZfs bool) *types.ZFSVDevMetrics {
	devMetrics := new(types.ZFSVDevMetrics)

	if fromZfs {
		devMetrics.Alloc = zStat.Alloc
		devMetrics.Space = zStat.Space
		devMetrics.DSpace = zStat.DSpace
		devMetrics.RSize = zStat.RSize
		devMetrics.ESize = zStat.ESize
		devMetrics.ChecksumErrors = zStat.ChecksumErrors
		devMetrics.ReadErrors = zStat.ReadErrors
		devMetrics.WriteErrors = zStat.WriteErrors
		for i := 0; i < types.ZIOTypeMax; i++ {
			devMetrics.Ops[i] = zStat.Ops[i]
			devMetrics.Bytes[i] = zStat.Bytes[i]
		}
	}
	// Only for block devices (Ex. /dev/sd*, /dev/zd*, /dev/nvme*...)
	if diskName != "" {
		diskWasFound := false
		shortDiskName := filepath.Base(diskName)
		fs, err := blockdevice.NewFS("/proc", "/sys")
		if err != nil {
			log.Errorf("failed to get block device stats for %s. Error:%v",
				diskName, err)
			return devMetrics
		}
		stats, err := fs.ProcDiskstats()
		if err != nil {
			log.Errorf("failed to get diskstats %v", err)
			return devMetrics
		}

		for _, stat := range stats {
			if shortDiskName == stat.Info.DeviceName {
				diskWasFound = true
				if !fromZfs { // only for zVolumes /dev/zd*
					sectorSize, err := GetZVolSectorSize(shortDiskName)
					if err != nil {
						log.Errorf("failed to get sector size for %s. Error:%v",
							shortDiskName, err)
					}

					// Other metrics for zvol (total, free, used space)
					// are collected elsewhere.
					devMetrics.Ops[types.ZIOTypeRead] = stat.IOStats.ReadIOs * sectorSize
					devMetrics.Ops[types.ZIOTypeWrite] = stat.IOStats.WriteIOs * sectorSize
					devMetrics.Bytes[types.ZIOTypeRead] = stat.IOStats.ReadSectors
					devMetrics.Bytes[types.ZIOTypeWrite] = stat.IOStats.WriteSectors
				}
				devMetrics.IOsInProgress = stat.IOStats.IOsInProgress
				devMetrics.ReadTicks = stat.IOStats.ReadTicks
				devMetrics.WriteTicks = stat.IOStats.WriteTicks
				devMetrics.IOsTotalTicks = stat.IOStats.IOsTotalTicks
				devMetrics.WeightedIOTicks = stat.IOStats.WeightedIOTicks
			}
		}

		if !diskWasFound {
			log.Errorf("failed to get diskstats for %s from /proc/diskstats", diskName)
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
	rDiskStatus.AuxStateStr = *proto.String(GetVDevAuxMsgStr(rDiskStatus.AuxState))
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

// GetZVolSectorSize return hw_sector_size for zvol
func GetZVolSectorSize(zVolName string) (uint64, error) {
	dataBytes, err := os.ReadFile(
		fmt.Sprintf("/sys/block/%s/queue/hw_sector_size",
			filepath.Base(zVolName)))
	if err != nil {
		return 0, err
	}

	sectorSizeStr := strings.TrimSpace(string(dataBytes))
	sectorSize, err := strconv.ParseUint(sectorSizeStr, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("failed to parse sector size: %s", err)
	}

	return sectorSize, nil
}

// GetZvolMetrics returns metrics for a zvol.
func GetZvolMetrics(status types.VolumeStatus, poolName string) (*types.StorageZVolMetrics, error) {
	var tmpStat libzfs.VDevStat
	zvolMetric := new(types.StorageZVolMetrics)
	fullZvolPath := status.ZVolName()

	// Сheck fullZvolPath on poolName
	// So far we have architecturally only one pool named "persist"
	// and this condition should always work, since .ZVolName() refers
	// to the paths that are written in the pillar/types/locationconsts.go
	// file (i.e. always to "persist").
	if !strings.HasPrefix(fullZvolPath, poolName) {
		return nil, fmt.Errorf("zvol %s is not on pool %s", fullZvolPath, poolName)
	}

	zvolMetric.VolumeID = status.VolumeID
	// Get device name
	diskName, err := os.Readlink(filepath.Join("/dev/zvol", fullZvolPath))
	if err != nil {
		log.Errorf("cannot get disk name for zvol: %s: err:%s", fullZvolPath, err)
		return zvolMetric, err
	}

	zvolMetric.Metrics = GetZfsVDevMetrics(tmpStat, filepath.Base(diskName), false)
	return zvolMetric, nil
}

func getZfsDisksMetrics(disk libzfs.VDevTree) *types.StorageDiskMetrics {
	disksMetrics := new(types.StorageDiskMetrics)
	rootDevice, err := disks.GetRootDevice()
	if err != nil {
		log.Errorf("cannot get root device: %s", err)
	}
	// ensure that we convert from partition to device
	diskName, err := disks.GetDiskNameByPartName(disk.Name)
	if err != nil {
		log.Errorf("cannot get disk name for %s: %s", disk.Name, err)
		diskName = disk.Name
	}

	if diskName == rootDevice {
		// if this disk is the root device, we need to use
		// the source name with the partition number (if have)
		diskName = disk.Name
	}

	serialNumber, err := hardware.GetSerialNumberForDisk(disk.Name)
	if err != nil {
		serialNumber = "unknown"
	}

	disksMetrics.DiskName = new(types.DiskDescription)
	disksMetrics.DiskName.Name = *proto.String(diskName)
	disksMetrics.DiskName.Serial = *proto.String(serialNumber)
	disksMetrics.Metrics = GetZfsVDevMetrics(disk.Stat, disk.Name, true)
	return disksMetrics
}

func getZpoolChildrenMetrics(vdev libzfs.VDevTree) *types.StorageChildrenMetrics {
	сhildrenMetrics := new(types.StorageChildrenMetrics)
	сhildrenMetrics.GUID = vdev.GUID
	сhildrenMetrics.DisplayName = vdev.Name
	сhildrenMetrics.Metrics = GetZfsVDevMetrics(vdev.Stat, "", true)

	for _, vdev := range vdev.Devices {
		if vdev.Type == libzfs.VDevTypeMirror ||
			vdev.Type == libzfs.VDevTypeRaidz {
			сhildrenMetrics.Children = append(сhildrenMetrics.Children,
				getZpoolChildrenMetrics(vdev))
		} else if vdev.Type == libzfs.VDevTypeDisk {
			сhildrenMetrics.Disks = append(сhildrenMetrics.Disks,
				getZfsDisksMetrics(vdev))
		}
	}

	return сhildrenMetrics
}

// GetZpoolMetrics returns metrics for provided zpool
func GetZpoolMetrics(vdev libzfs.VDevTree) *types.ZFSPoolMetrics {
	zPoolMetrics := new(types.ZFSPoolMetrics)
	// Pool always goes first in the VDevsTree
	zPoolMetrics.PoolName = vdev.Name
	zPoolMetrics.CollectionTime = time.Now()
	zPoolMetrics.Metrics = GetZfsVDevMetrics(vdev.Stat, "", true)

	for _, vdev := range vdev.Devices {
		if vdev.Type == libzfs.VDevTypeMirror ||
			vdev.Type == libzfs.VDevTypeRaidz {
			zPoolMetrics.ChildrenDataset = append(zPoolMetrics.ChildrenDataset,
				getZpoolChildrenMetrics(vdev))
		} else if vdev.Type == libzfs.VDevTypeDisk {
			zPoolMetrics.Disks = append(zPoolMetrics.Disks,
				getZfsDisksMetrics(vdev))
		}
	}

	return zPoolMetrics
}

// GetZpoolStatusMsgStr returns a verbose zpool status message
// The state messages were taken as a basis
// from the zfs/cmd/zpool/zpool_main.c file
func GetZpoolStatusMsgStr(status types.PoolStatus) string {
	switch status {
	case types.PoolStatusUnspecified:
		return "Unspecified"
	case types.PoolStatusCorruptCache:
		return "Corrupt /kernel/drv/zpool.cache"
	case types.PoolStatusMissingDevR:
		return "One or more devices with replicas are missing from the system."
	case types.PoolStatusMissingDevNr:
		return "One or more devices with no replicas " +
			"are missing from the system."
	case types.PoolStatusCorruptLabelR:
		return "One or more devices could not be used because the label " +
			"is missing or invalid. Sufficient replicas exist for the " +
			"pool to continue functioning in a degraded state."
	case types.PoolStatusCorruptLabelNr:
		return "One or more devices could not be used because the label is " +
			"missing or invalid. There are insufficient replicas for " +
			"the pool to continue functioning."
	case types.PoolStatusBadGUIDSum:
		return "One or more devices are missing from the system."
	case types.PoolStatusCorruptPool:
		return "The pool metadata is corrupted and the pool cannot be opened."
	case types.PoolStatusCorruptData:
		return "One or more devices has experienced an error resulting " +
			"in data corruption."
	case types.PoolStatusFailingDev:
		return "One or more devices has experienced an unrecoverable error."
	case types.PoolStatusVersionNewer:
		return "The pool has been upgraded to a newer, incompatible on-disk " +
			"version. The pool cannot be accessed on this system."
	case types.PoolStatusHostidMismatch:
		return "The pool was last accessed by another system."
	case types.PoolStatusHosidActive:
		return "The pool is currently imported by another system."
	case types.PoolStatusHostidRequired:
		return "The pool has the multihost property on. It cannot be safely " +
			"imported when the system hostid is not set."
	case types.PoolStatusIoFailureWait:
		return "One or more devices are faulted in response to IO failures. " +
			"Failmode 'wait'"
	case types.PoolStatusIoFailureContinue:
		return "One or more devices are faulted in response to IO failures. " +
			"Failmode 'continue'"
	case types.PoolStatusIOFailureMMP:
		return "The pool is suspended because multihost writes failed or " +
			"were delayed another system could import the pool undetected."
	case types.PoolStatusBadLog:
		return "An intent log record cannot be read."
	case types.PoolStatusErrata:
		return "Errata detected"
	case types.PoolStatusUnsupFeatRead:
		return "The pool uses the following feature(s) not supported " +
			"on this system"
	case types.PoolStatusUnsupFeatWrite:
		return "The pool can only be accessed in read-only mode on " +
			"this system. It cannot be accessed in read-write mode " +
			"because it uses the following feature(s) " +
			"not supported on this system"
	case types.PoolStatusFaultedDevR:
		return "One or more devices are faulted in response to " +
			"persistent errors. Sufficient replicas exist for " +
			"the pool to continue functioning in a degraded state."
	case types.PoolStatusFaultedDevNr:
		return "One or more devices are faulted in response to " +
			"persistent errors. There are insufficient replicas for " +
			"the pool to continue functioning."
	case types.PoolStatusVersionOlder:
		return "The pool is formatted using a legacy on-disk version."
	case types.PoolStatusFeatDisabled:
		return "Some supported and requested features are not enabled " +
			"on the pool. The pool can still be used, but some " +
			"features are unavailable."
	case types.PoolStatusResilvering:
		return "One or more devices is currently being resilvered."
	case types.PoolStatusOfflineDev:
		return "One or more devices has been taken offline by the administrator."
	case types.PoolStatusRemovedDev:
		return "One or more devices has been removed by the administrator."
	case types.PoolStatusRebuilding:
		return "One or more devices were being resilvered."
	case types.PoolStatusRebuildScrub:
		return "One or more devices have been sequentially resilvered, " +
			"scrubbing the pool is recommended."
	case types.PoolStatusNonNativeAshift:
		return "One or more devices are configured to use a non-native " +
			"block size. Expect reduced performance"
	case types.PoolStatusCompatibilityErr:
		return "Error reading or parsing the file(s) indicated by the " +
			"'compatibility' property."
	case types.PoolStatusIncompatibleFeat:
		return "One or more features are enabled on the pool despite not " +
			"being requested by the 'compatibility' property."
	case types.PoolStatusOk:
		return "OK"
	}

	return "Unspecified"
}

// GetVDevAuxMsgStr returns a verbose VDev aux message
// The state messages were taken as a basis
// from zfs/include/sys/fs/zfs.h
func GetVDevAuxMsgStr(state types.VDevAux) string {
	switch state {
	case types.VDevAuxUnspecified:
		return "Unspecified"
	case types.VDevAuxStatusOk:
		return "No error."
	case types.VDevAuxOpenFailed:
		return "Cannot open."
	case types.VDevAuxCorruptData:
		return "Corrupt data. Bad label or disk contents."
	case types.VDevAuxNoReplicas:
		return "Insufficient number of replicas."
	case types.VDevAuxBadGUIDSum:
		return "VDev GUID sum doesn't match."
	case types.VDevAuxTooSmall:
		return "VDev size is too small."
	case types.VDevAuxBadLabel:
		return "The label is OK but invalid."
	case types.VDevAuxVersionNewer:
		return "On-disk version is too new."
	case types.VDevAuxVersionOlder:
		return "On-disk version is too old."
	case types.VDevAuxUnsupFeat:
		return "Unsupported features."
	case types.VDevAuxSpared:
		return "Hot spare used in another pool."
	case types.VDevAuxErrExceeded:
		return "Too many errors."
	case types.VDevAuxIOFailure:
		return "I/O failure."
	case types.VDevAuxBadLog:
		return "Cannot read log chain(s)."
	case types.VDevAuxExternal:
		return "External diagnosis or forced fault."
	case types.VDevAuxSplitPool:
		return "VDev was split off into another pool."
	case types.VdevAuxBadAshift:
		return "VDev ashift is invalid."
	case types.VdevAuxExternalPersist:
		return "Persistent forced fault."
	case types.VdevAuxActive:
		return "VDev active on a different host."
	case types.VdevAuxChildrenOffline:
		return "All children are offline."
	case types.VdevAuxAshiftTooBig:
		return "VDev's min block size is too large."
	}

	return "Unspecified"
}
