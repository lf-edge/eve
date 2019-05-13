// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Read the symlinks in /sys/class/net/*/device to print a mapping
// from ifname to PCI-ID

package types

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"path"
	"regexp"
	"strings"
)

const basePath = "/sys/class/net"
const pciPath = "/sys/bus/pci/devices"

// Returns the long and short PCI IDs
func ifNameToPci(ifName string) (string, string, error) {
	// Match for PCI IDs
	re := regexp.MustCompile("([0-9a-f]){4}:([0-9a-f]){2}:([0-9a-f]){2}.[ls0-9a-f]")
	devPath := basePath + "/" + ifName + "/device"
	info, err := os.Lstat(devPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Errorln(err)
		}
		return "", "", err
	}
	if (info.Mode() & os.ModeSymlink) == 0 {
		log.Errorf("Skipping non-symlink %s\n", devPath)
		return "", "", errors.New(fmt.Sprintf("Not a symlink %s", devPath))
	}
	link, err := os.Readlink(devPath)
	if err != nil {
		return "", "", err
	}
	target := path.Base(link)
	if re.MatchString(target) {
		return target, strings.SplitAfterN(target, ":", 2)[1], nil
	} else {
		return target, "",
			errors.New(fmt.Sprintf("Not PCI %s", target))
	}
}

// Check if an ID like 0000:03:00.0 exists
func pciLongExists(long string) bool {
	path := pciPath + "/" + long
	_, err := os.Stat(path)
	return err == nil

}

// Return a string likely to be unique for the device.
// Used to make sure devices don't move around
// Returns exist bool, string
func PciLongToUnique(long string) (bool, string) {

	if !pciLongExists(long) {
		return false, ""
	}
	devPath := pciPath + "/" + long + "/firmware_node"
	info, err := os.Lstat(devPath)
	if err != nil {
		log.Errorln(err)
		return false, ""
	}
	if (info.Mode() & os.ModeSymlink) == 0 {
		log.Errorf("Skipping non-symlink %s\n", devPath)
		return true, ""
	}
	link, err := os.Readlink(devPath)
	if err != nil {
		log.Errorln(err)
		return true, ""
	}
	return true, link
}

// Returns the long and short PCI IDs; if Lookup is set there can be a PCI ID for
// each member.
// Check if PCI ID exists on system. Returns null strings for non-PCI
// devices since we can't check if they exist.
func IoBundleToPci(ib *IoBundle) ([]string, []string, error) {
	var long, short string
	var longs, shorts []string
	if ib.Lookup {
		longs = make([]string, len(ib.Members))
		shorts = make([]string, len(ib.Members))
		var err error
		for i, m := range ib.Members {
			long, short, err = ifNameToPci(m)
			if err == nil {
				longs[i] = long
				shorts[i] = short
			}
		}
		if err != nil {
			return nil, nil, err
		}
	} else if ib.PciShort != "" {
		if !pciLongExists(ib.PciLong) {
			errStr := fmt.Sprintf("PCI device %s does not exist",
				ib.PciLong)
			return nil, nil, errors.New(errStr)
		}
		longs = make([]string, 1)
		shorts = make([]string, 1)
		longs[0] = ib.PciLong
		shorts[0] = ib.PciShort
	}
	for i := range shorts {
		if !pciLongExists(longs[i]) {
			return nil, nil, errors.New(fmt.Sprintf("PCI device (%s) does not exist", longs[i]))
		}
	}
	return longs, shorts, nil
}
