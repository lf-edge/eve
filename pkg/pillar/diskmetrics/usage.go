// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
)

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
				log.Tracef("File %s Size %d\n", filename, location.Size())
				totalUsed += uint64(location.Size())
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
