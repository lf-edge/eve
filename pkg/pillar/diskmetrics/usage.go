// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/containerd/containerd/mount"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/vault"
	"github.com/lf-edge/eve/pkg/pillar/zfs"
	"github.com/shirou/gopsutil/disk"
)

// StatAllocatedBytes returns the allocated size of a file in bytes
// This value will be less than fileInfo.Size() for thinly allocated files
func StatAllocatedBytes(path string) (uint64, error) {
	var stat syscall.Stat_t
	err := syscall.Stat(path, &stat)
	if err != nil {
		return uint64(0), err
	}
	return uint64(stat.Blocks * int64(stat.Blksize)), nil
}

// SizeFromDir performs a du -s equivalent operation.
// Didn't use ioutil.ReadDir and filepath.Walk because they sort (quick_sort) all files per directory
// which is an unnecessary costly operation.
func SizeFromDir(log *base.LogObject, dirname string) (uint64, error) {
	var totalUsed uint64
	fileInfo, err := os.Stat(dirname)
	if err != nil {
		err = fmt.Errorf("Stat %s: %v", dirname, err)
		return totalUsed, err
	}
	if !fileInfo.IsDir() {
		return uint64(fileInfo.Size()), nil
	}
	f, err := os.Open(dirname)
	if err != nil {
		err = fmt.Errorf("Exception while opening %s: %v", dirname, err)
		return totalUsed, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("cannot close dir %s: %s", dirname, err)
		}
	}()
	for {
		locations, err := f.Readdir(10)
		if err == io.EOF {
			break
		}
		if err != nil {
			return totalUsed, err
		}
		for _, location := range locations {
			filename := dirname + "/" + location.Name()
			log.Tracef("Looking in %s\n", filename)
			if location.IsDir() {
				size, _ := SizeFromDir(log, filename)
				log.Tracef("Dir %s size %d\n", filename, size)
				totalUsed += size
			} else {
				// FileInfo.Size() returns the provisioned size
				// Sparse files will have a smaller allocated size than provisioned
				// Use full syscall.Stat_t to get the allocated size
				allocatedBytes, err := StatAllocatedBytes(filename)
				if err != nil {
					log.Errorf("StatAllocatedBytes: %s failed %s treating as fully allocated\n", filename, err)
					allocatedBytes = uint64(location.Size())
				}
				// Fully Allocated: don't use allocated bytes
				// stat math of %b*%B as it will over-account space
				if allocatedBytes >= uint64(location.Size()) {
					allocatedBytes = uint64(location.Size())
				}
				log.Tracef("File %s Size %d\n", filename, allocatedBytes)
				totalUsed += allocatedBytes
			}
		}
	}
	return totalUsed, nil
}

// PartitionSize - Given "sdb1" return the size of the partition; "sdb"
// to size of disk. Returns size and a bool to indicate that it is a partition.
func PartitionSize(log *base.LogObject, part string) (uint64, bool) {
	out, err := base.Exec(log, "lsblk", "-nbdo", "SIZE", "/dev/"+part).Output()
	if err != nil {
		log.Errorf("lsblk -nbdo SIZE %s failed %s\n", "/dev/"+part, err)
		return 0, false
	}
	res := strings.Split(string(out), "\n")
	val, err := strconv.ParseUint(strings.TrimSpace(res[0]), 10, 64)
	if err != nil {
		log.Errorf("parseUint(%s) failed %s\n", strings.TrimSpace(res[0]), err)
		return 0, false
	}
	isPart := strings.EqualFold(diskType(log, part), "part")
	return val, isPart
}

// diskType returns a string like "disk", "part", "loop"
func diskType(log *base.LogObject, part string) string {
	out, err := base.Exec(log, "lsblk", "-nbdo", "TYPE", "/dev/"+part).Output()
	if err != nil {
		log.Errorf("lsblk -nbdo TYPE %s failed %s\n", "/dev/"+part, err)
		return ""
	}
	return strings.TrimSpace(string(out))
}

// FindDisksPartitions returns the names of all disks and all partitions
// Return an array of names like "sda", "sdb1"
func FindDisksPartitions(log *base.LogObject) []string {
	out, err := base.Exec(log, "lsblk", "-nlo", "NAME").Output()
	if err != nil {
		log.Errorf("lsblk -nlo NAME failed %s", err)
		return nil
	}
	res := strings.Split(string(out), "\n")
	// Remove blank/empty string after last CR
	res = res[:len(res)-1]
	return res
}

// FindLargestDisk determines the name of the largest disk
// The assumption is that this is not a removalable disk like a USB disk
// with the installer image
func FindLargestDisk(log *base.LogObject) string {

	var maxsize uint64
	var maxdisk string
	disksAndPartitions := FindDisksPartitions(log)
	for _, part := range disksAndPartitions {
		if !strings.EqualFold(diskType(log, part), "disk") {
			continue
		}
		size, _ := PartitionSize(log, part)
		if size > maxsize {
			maxsize = size
			maxdisk = part
		}
	}
	return maxdisk
}

// DirUsage calculates usage of directory
// it checks if provided directory is zfs mountpoint and take usage from zfs in that case
func DirUsage(log *base.LogObject, dir string) (uint64, error) {
	if vault.ReadPersistType() != types.PersistZFS || !strings.HasPrefix(dir, types.PersistDir) {
		return SizeFromDir(log, dir)
	}
	mi, err := mount.Lookup(dir)
	if err != nil {
		// Lookup do not return error in case of dir is not mountpoint
		// it returns the longest found parent mountpoint for provided dir
		log.Errorf("dirUsage: Lookup returns error (%s), fallback to SizeFromDir", err)
		return SizeFromDir(log, dir)
	}
	// if it is zfs mountpoint and we mount exactly the directory of interest (not parent folder)
	if mi.FSType == types.PersistZFS.String() && mi.Mountpoint == dir {
		usageStat, err := zfs.GetDatasetUsageStat(strings.TrimPrefix(dir, "/"))
		if err != nil {
			return 0, err
		}
		return usageStat.Used, nil
	}
	return SizeFromDir(log, dir)
}

// Dom0DiskReservedSize returns reserved space for EVE-OS
func Dom0DiskReservedSize(log *base.LogObject, globalConfig *types.ConfigItemValueMap, deviceDiskSize uint64) uint64 {
	dom0MinDiskUsagePercent := globalConfig.GlobalValueInt(
		types.Dom0MinDiskUsagePercent)
	diskReservedForDom0 := uint64(float64(deviceDiskSize) *
		(float64(dom0MinDiskUsagePercent) * 0.01))
	maxDom0DiskSize := uint64(globalConfig.GlobalValueInt(
		types.Dom0DiskUsageMaxBytes))
	if diskReservedForDom0 > maxDom0DiskSize {
		log.Tracef("diskSizeReservedForDom0 - diskReservedForDom0 adjusted to "+
			"maxDom0DiskSize (%d)", maxDom0DiskSize)
		diskReservedForDom0 = maxDom0DiskSize
	}
	return diskReservedForDom0
}

// PersistUsageStat returns usage stat for persist
// We need to handle ZFS differently since the mounted /persist does not indicate
// usage of zvols and snapshots
// Note that we subtract usage of persist/reserved dataset (about 20% of persist capacity)
func PersistUsageStat(log *base.LogObject) (*types.UsageStat, error) {
	if vault.ReadPersistType() != types.PersistZFS {
		deviceDiskUsage, err := disk.Usage(types.PersistDir)
		if err != nil {
			return nil, err
		}
		usageStat := &types.UsageStat{
			Total: deviceDiskUsage.Total,
			Used:  deviceDiskUsage.Used,
			Free:  deviceDiskUsage.Free,
		}
		return usageStat, nil
	}
	usageStat, err := zfs.GetDatasetUsageStat(types.PersistDataset)
	if err != nil {
		return nil, err
	}
	usageStatReserved, err := zfs.GetDatasetUsageStat(types.PersistReservedDataset)
	if err != nil {
		log.Errorf("GetDatasetUsageStat: %s", err)
	} else {
		// subtract reserved dataset Total from persist Total
		// we use LogicalUsed for usageStat.Total of persist for usageStat.Free calculation
		// so need to subtract
		usageStat.Free -= usageStatReserved.Total
		usageStat.Total -= usageStatReserved.Total
	}
	return usageStat, nil
}
