// Copyright (c) 2018-2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"io/ioutil"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

func SizeFromDir(dirname string) uint64 {
	var totalUsed uint64
	locations, err := ioutil.ReadDir(dirname)
	if err != nil {
		//log.Debugf("Dir %s is missing. Set the size to zero\n", dirname)
		return totalUsed
	}
	for _, location := range locations {
		filename := dirname + "/" + location.Name()
		log.Debugf("Looking in %s\n", filename)
		if location.IsDir() {
			size := SizeFromDir(filename)
			log.Debugf("Dir %s size %d\n", filename, size)
			totalUsed += size
		} else {
			log.Debugf("File %s Size %d\n", filename, location.Size())
			totalUsed += uint64(location.Size())
		}
	}
	return totalUsed
}

// PartitionSize - Given "sdb1" return the size of the partition; "sdb"
// to size of disk. Returns size and a bool to indicate that it is a partition.
func PartitionSize(part string) (uint64, bool) {
	out, err := exec.Command("lsblk", "-nbdo", "SIZE", "/dev/"+part).Output()
	if err != nil {
		log.Errorf("lsblk -nbdo SIZE %s failed %s\n", "/dev/"+part, err)
		return 0, false
	}
	res := strings.Split(string(out), "\n")
	val, err := strconv.ParseUint(res[0], 10, 64)
	if err != nil {
		log.Errorf("parseUint(%s) failed %s\n", res[0], err)
		return 0, false
	}
	isPart := strings.EqualFold(diskType(part), "part")
	return val, isPart
}

// diskType returns a string like "disk", "part", "loop"
func diskType(part string) string {
	out, err := exec.Command("lsblk", "-nbdo", "TYPE", "/dev/"+part).Output()
	if err != nil {
		log.Errorf("lsblk -nbdo TYPE %s failed %s\n", "/dev/"+part, err)
		return ""
	}
	return strings.TrimSpace(string(out))
}

// FindDisksPartitions returns the names of all disks and all partitions
// Return an array of names like "sda", "sdb1"
func FindDisksPartitions() []string {
	out, err := exec.Command("lsblk", "-nlo", "NAME").Output()
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
func FindLargestDisk() string {

	var maxsize uint64
	var maxdisk string
	disksAndPartitions := FindDisksPartitions()
	for _, part := range disksAndPartitions {
		if !strings.EqualFold(diskType(part), "disk") {
			continue
		}
		size, _ := PartitionSize(part)
		if size > maxsize {
			maxsize = size
			maxdisk = part
		}
	}
	return maxdisk
}
