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

// Returns the long PCI IDs
func ifNameToPci(ifName string) (string, error) {
	// Match for PCI IDs
	re := regexp.MustCompile("([0-9a-f]){4}:([0-9a-f]){2}:([0-9a-f]){2}.[ls0-9a-f]")
	devPath := basePath + "/" + ifName + "/device"
	info, err := os.Lstat(devPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Errorln(err)
		}
		return "", err
	}
	if (info.Mode() & os.ModeSymlink) == 0 {
		log.Errorf("Skipping non-symlink %s\n", devPath)
		return "", fmt.Errorf("Not a symlink %s", devPath)
	}
	link, err := os.Readlink(devPath)
	if err != nil {
		return "", err
	}
	target := path.Base(link)
	if re.MatchString(target) {
		return target, nil
	} else {
		return target, fmt.Errorf("Not PCI %s", target)
	}
}

// PCILongToShort returns the PCI ID without the domain id
func PCILongToShort(long string) string {
	return strings.SplitAfterN(long, ":", 2)[1]
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

// IoBundleToPci returns the long PCI ID if the bundle refers to a PCI controller.
// Checks if PCI ID exists on system. Returns null strings for non-PCI
// devices since we can't check if they exist.
// This can handle aliases like Ifname.
func IoBundleToPci(ib *IoBundle) (string, error) {

	var long string
	if ib.PciLong != "" {
		long = ib.PciLong
		// Check if model matches
		if ib.Ifname != "" {
			l, err := ifNameToPci(ib.Ifname)
			if err != nil {
				if long != l {
					log.Warnf("Ifname and PciLong mismatch: %s vs %s for %s",
						l, long, ib.Ifname)
				}
			}
		}
	} else if ib.Ifname != "" {
		var err error
		long, err = ifNameToPci(ib.Ifname)
		if err != nil {
			return long, err
		}
	} else {
		return "", nil
	}
	if !pciLongExists(long) {
		errStr := fmt.Sprintf("PCI device name %s id %s does not exist",
			ib.Name, long)
		return long, errors.New(errStr)
	}
	return long, nil
}
