// Copyright (c) 2018-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

// #include <sys/param.h>
import "C"

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

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

// walkTickInterval bounds how often a walk reports progress. Reporting per
// directory entry would cost more than the walk itself, while the watchdog
// tolerates minutes of silence, so seconds of granularity are ample.
const walkTickInterval = 5 * time.Second

// walkHeartbeat rate-limits the progress callback threaded through a directory
// walk. A nil *walkHeartbeat is usable and reports nothing.
type walkHeartbeat struct {
	tick func()
	next time.Time
}

func newWalkHeartbeat(tick func()) *walkHeartbeat {
	if tick == nil {
		return nil
	}
	return &walkHeartbeat{tick: tick}
}

func (h *walkHeartbeat) beat() {
	if h == nil {
		return
	}
	now := time.Now()
	if now.Before(h.next) {
		return
	}
	h.next = now.Add(walkTickInterval)
	h.tick()
}

// SizeFromDir performs a du -s equivalent operation: a sum over the tree
// under dirname, following no symbolic link.
//
// The walk is filepath.Walk rather than WalkDir: the sum needs the FileInfo
// of every entry, so the lstat WalkDir defers would be issued anyway.
//
// tick, when not nil, is called as the walk advances, at most once every
// walkTickInterval; a caller whose goroutine is watched by the watchdog uses it
// to report liveness while measuring a tree that takes minutes. It fires only
// after a directory read returns, so a walk stuck in the kernel stays silent and
// the watchdog still catches it.
func SizeFromDir(log *base.LogObject, dirname string, tick func()) (uint64, error) {
	root, err := os.Lstat(dirname)
	if err != nil {
		return 0, fmt.Errorf("Stat %s: %v", dirname, err)
	}
	if !root.IsDir() {
		return uint64(root.Size()), nil
	}
	hb := newWalkHeartbeat(tick)
	var totalUsed uint64
	walkErr := filepath.Walk(dirname, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// A directory that cannot be read, or an entry gone since its
			// directory was read, counts for what was summed so far; only
			// the root is reported.
			if path == dirname {
				return err
			}
			log.Tracef("Skipping %s: %v\n", path, err)
			return nil
		}
		hb.beat()
		if info.IsDir() {
			return nil
		}
		size := fileSize(path, info)
		log.Tracef("File %s Size %d\n", path, size)
		totalUsed += size
		return nil
	})
	return totalUsed, walkErr
}

// fileSize returns the bytes the file at path takes. Under the volume
// directories that is its allocated size, since the provisioned size of a
// sparse image overstates what it takes on disk; elsewhere it is the size in
// its directory entry, as a second stat of every file would cost more than
// the precision is worth there.
func fileSize(path string, info os.FileInfo) uint64 {
	size := uint64(info.Size())
	if !strings.HasPrefix(path, types.VolumeEncryptedDirName) &&
		!strings.HasPrefix(path, types.VolumeClearDirName) {
		return size
	}
	// Blocks can exceed the size of a fully allocated file, which would
	// over-account it.
	if allocated, err := StatAllocatedBytes(path); err == nil && allocated < size {
		return allocated
	}
	return size
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

// DiskPartition is a block device or partition discovered by lsblk,
// optionally enriched with GPT identity fields.
type DiskPartition struct {
	Name           string // E.g., "sda3"
	PartitionLabel string // GPT PARTLABEL; "" for non-GPT
	PartitionType  string // GPT partition type GUID; "" for non-GPT
	PartitionUUID  string // GPT PARTUUID; "" for non-GPT
}

// FindDisksPartitions returns every block device and partition the kernel
// exposes, enriched with GPT identity when available. Whole-disk entries
// and partitions on non-GPT disks leave the partition* fields empty.
func FindDisksPartitions(log *base.LogObject) []DiskPartition {
	out, err := base.Exec(log, "lsblk", "-J", "-l",
		"-o", "NAME,PARTLABEL,PARTTYPE,PARTUUID").Output()
	if err != nil {
		log.Errorf("lsblk -J -l -o NAME,PARTLABEL,PARTTYPE,PARTUUID failed: %s", err)
		return nil
	}
	parts, err := parseLsblkPartitions(out)
	if err != nil {
		log.Errorf("lsblk JSON decode failed: %s", err)
		return nil
	}
	return parts
}

// parseLsblkPartitions decodes the JSON produced by
// `lsblk -J -l -o NAME,PARTLABEL,PARTTYPE,PARTUUID` into DiskPartition
// records. Split out from FindDisksPartitions so the parsing can be
// unit-tested without shelling out to lsblk.
func parseLsblkPartitions(out []byte) ([]DiskPartition, error) {
	var parsed struct {
		BlockDevices []struct {
			Name      string `json:"name"`
			PartLabel string `json:"partlabel"`
			PartType  string `json:"parttype"`
			PartUUID  string `json:"partuuid"`
		} `json:"blockdevices"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, err
	}
	result := make([]DiskPartition, 0, len(parsed.BlockDevices))
	for _, e := range parsed.BlockDevices {
		result = append(result, DiskPartition{
			Name:           e.Name,
			PartitionLabel: e.PartLabel,
			PartitionType:  e.PartType,
			PartitionUUID:  e.PartUUID,
		})
	}
	return result, nil
}

// FindLargestDisk determines the name of the largest disk
// The assumption is that this is not a removalable disk like a USB disk
// with the installer image
func FindLargestDisk(log *base.LogObject) string {

	var maxsize uint64
	var maxdisk string
	disksAndPartitions := FindDisksPartitions(log)
	for _, part := range disksAndPartitions {
		if !strings.EqualFold(diskType(log, part.Name), "disk") {
			continue
		}
		size, _ := PartitionSize(log, part.Name)
		if size > maxsize {
			maxsize = size
			maxdisk = part.Name
		}
	}
	return maxdisk
}

// DirUsage calculates usage of directory.
// When dir holds a whole filesystem, usage comes from that filesystem - one
// dataset query for ZFS, one statfs otherwise - rather than from walking the
// tree. Anything else is walked with SizeFromDir, which is what tick is for.
func DirUsage(log *base.LogObject, dir string, tick func()) (uint64, error) {
	mi, err := mount.Lookup(dir)
	if err != nil {
		// Lookup do not return error in case of dir is not mountpoint
		// it returns the longest found parent mountpoint for provided dir
		log.Errorf("dirUsage: Lookup returns error (%s), fallback to SizeFromDir", err)
		return SizeFromDir(log, dir, tick)
	}
	if isWholeFilesystem(mi, dir) {
		// The dataset name is derived from the path, which only holds inside
		// the persist pool.
		if mi.FSType == types.PersistZFS.String() &&
			strings.HasPrefix(dir, types.PersistDir) {
			usageStat, err := zfs.GetDatasetUsageStat(strings.TrimPrefix(dir, "/"))
			if err != nil {
				return 0, err
			}
			return usageStat.Used, nil
		}
		usage, err := disk.Usage(dir)
		if err == nil {
			return usage.Used, nil
		}
		log.Errorf("dirUsage: disk.Usage(%s) returns error (%s), fallback to SizeFromDir",
			dir, err)
	}
	return SizeFromDir(log, dir, tick)
}

// isWholeFilesystem reports whether mi describes a filesystem mounted in its
// entirety at dir, so that filesystem-wide usage accounts for exactly the tree
// under dir. A Root other than "/" is a bind mount of a subtree, whose backing
// filesystem also holds data outside dir.
func isWholeFilesystem(mi mount.Info, dir string) bool {
	return mi.Mountpoint == dir && mi.Root == "/"
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
	// The config item is in MBytes. newlogd clamps its own quota to a tenth
	// of /persist, so anything above that could never be used.
	newlogReserved := min(
		1000000*uint64(globalConfig.GlobalValueInt(types.LogRemainToSendMBytes)),
		deviceDiskSize/10)
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
// unless they are in an excluded (sub)directory.
// tick has the same meaning as in SizeFromDir.
func FindLargeFiles(root string, minSize int64, excludePaths []string,
	tick func()) ([]PathAndSize, error) {
	var list []PathAndSize
	hb := newWalkHeartbeat(tick)
	walkErr := filepath.WalkDir(filepath.Clean(root), func(path string, di fs.DirEntry, err error) error {
		// if there is any problem with path we stop
		if err != nil {
			return err
		}
		hb.beat()

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
