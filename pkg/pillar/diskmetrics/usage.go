// Copyright (c) 2018-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

// #include <sys/param.h>
import "C"

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/containerd/containerd/mount"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/persist"
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
	// From POSIX standard for st_blocks block size:
	// Traditionally, some implementations defined
	// the multiplier for st_blocks in <sys/param.h>
	// as the symbol DEV_BSIZE.
	return uint64(stat.Blocks * C.DEV_BSIZE), nil
}

// SizeFromDir performs a du -s equivalent operation.
// Didn't use os.ReadDir and filepath.Walk because they sort (quick_sort) all files per directory
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
				// The selection of these two persist directories is intended to pick a balance
				// between:
				// 		- calling syscall.Stat() on every file which is heavy on time and compute
				//		- not calling syscall.Stat() on anything which can overestimate storage allocated
				//			because the difference between allocated and provisioned storage is
				//			not accounted for.
				//
				// It is believed that the majority of sparsefile usage (by provisioned GB)
				// will be in the clear and vault volumes base directories so a lot of compute time
				// can be saved by not checking detailed allocated bytes information in deeper
				// directories.
				if strings.HasPrefix(dirname, types.VolumeEncryptedDirName) ||
					strings.HasPrefix(dirname, types.VolumeClearDirName) {
					// FileInfo.Size() returns the provisioned size
					// Sparse files will have a smaller allocated size than provisioned
					// Use full syscall.Stat_t to get the allocated size
					allocatedBytes, err := StatAllocatedBytes(filename)
					if err != nil {
						allocatedBytes = uint64(location.Size())
					}
					// Fully Allocated: don't use allocated bytes
					// stat math of %b*%B as it will over-account space
					if allocatedBytes >= uint64(location.Size()) {
						allocatedBytes = uint64(location.Size())
					}
					log.Tracef("File %s Size %d\n", filename, allocatedBytes)
					totalUsed += allocatedBytes
				} else {
					log.Tracef("File %s Size %d\n", filename, location.Size())
					totalUsed += uint64(location.Size())
				}
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
	if persist.ReadPersistType() != types.PersistZFS || !strings.HasPrefix(dir, types.PersistDir) {
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
// We check that the currently used aka dynamic number does not exceed
// the statically configured percentage and number
func Dom0DiskReservedSize(log *base.LogObject, globalConfig *types.ConfigItemValueMap, deviceDiskSize uint64, dynamicUsedByDom0 uint64) uint64 {
	dom0MinDiskUsagePercent := globalConfig.GlobalValueInt(
		types.Dom0MinDiskUsagePercent)
	diskReservedForDom0 := uint64(float64(deviceDiskSize) *
		(float64(dom0MinDiskUsagePercent) * 0.01))
	staticMaxDom0DiskSize := uint64(globalConfig.GlobalValueInt(
		types.Dom0DiskUsageMaxBytes))
	newlogReserved := uint64(globalConfig.GlobalValueInt(types.LogRemainToSendMBytes))
	// Always leave space for /persist/newlogd
	maxDom0DiskSize := newlogReserved
	// Select the larger of the current overhead usage and the configured
	// max overhead. If using the static then ensure that we do not exceed
	// the dom0MinDiskUsagePercent percentage of /persist
	if staticMaxDom0DiskSize < dynamicUsedByDom0 {
		log.Noticef("Dom0DiskReservedSize using dynamic %d",
			dynamicUsedByDom0)
		maxDom0DiskSize += dynamicUsedByDom0
	} else if diskReservedForDom0 > staticMaxDom0DiskSize {
		maxDom0DiskSize += staticMaxDom0DiskSize
		log.Noticef("Dom0DiskReservedSize using static %d",
			staticMaxDom0DiskSize)
	} else {
		log.Noticef("Dom0DiskReservedSize %d percent of %d = %d, HIT max %d",
			dom0MinDiskUsagePercent, deviceDiskSize, diskReservedForDom0, maxDom0DiskSize)
		maxDom0DiskSize += diskReservedForDom0
	}
	return maxDom0DiskSize
}

// PersistUsageStat returns usage stat for persist
// We need to handle ZFS differently since the mounted /persist does not indicate
// usage of zvols and snapshots
// Note that we subtract usage of persist/reserved dataset (about 20% of persist capacity)
func PersistUsageStat(log *base.LogObject) (*types.UsageStat, error) {
	if persist.ReadPersistType() != types.PersistZFS {
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

// PathAndSize is returned by FindLargeFiles
type PathAndSize struct {
	Path string
	Size int64
}

// FindLargeFiles walks a directory and reports all files larger than minSize
// unless they are in an excluded (sub)directory
func FindLargeFiles(root string, minSize int64, excludePaths []string) ([]PathAndSize, error) {
	var list []PathAndSize
	walkErr := filepath.WalkDir(filepath.Clean(root), func(path string, di fs.DirEntry, err error) error {
		// if there is any problem with path we stop
		if err != nil {
			return err
		}

		// Part of excludePath?
		for _, ex := range excludePaths {
			if filepath.HasPrefix(path, ex) {
				return filepath.SkipDir
			}
		}
		// We don't report any directories
		if di.IsDir() {
			return nil
		}

		info, err := os.Stat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			// Ignore if a file disappeared while we walk
			return nil
		}
		if info.Size() > minSize {
			list = append(list,
				PathAndSize{Path: path, Size: info.Size()})
		}
		return nil
	})

	return list, walkErr
}
