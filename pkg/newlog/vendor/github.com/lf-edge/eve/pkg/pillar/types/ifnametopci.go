// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Read the symlinks in /sys/class/net/*/device to print a mapping
// from ifname to PCI-ID

package types

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/eriknordmark/netlink"
	"github.com/lf-edge/eve/pkg/pillar/base"
)

const basePath = "/sys/class/net"
const pciPath = "/sys/bus/pci/devices"

// Returns the long PCI IDs
func ifNameToPci(log *base.LogObject, ifName string) (string, error) {
	// Match for PCI IDs
	re := regexp.MustCompile("([0-9a-f]){4}:([0-9a-f]){2}:([0-9a-f]){2}.[ls0-9a-f]")
	devPath := basePath + "/" + ifName + "/device"
	info, err := os.Lstat(devPath)
	if err != nil {
		if !strings.HasPrefix(ifName, "eth") {
			if !os.IsNotExist(err) {
				log.Errorln(err)
			}
			return "", err
		}
		// Try alternate since the PCI device can be kethN
		// if ifName is ethN
		ifName = "k" + ifName
		devPath = basePath + "/" + ifName + "/device"
		info, err = os.Lstat(devPath)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Errorln(err)
			}
			return "", err
		}
		log.Noticef("ifNameToPci using alternate %s", ifName)
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
func PciLongToUnique(log *base.LogObject, long string) (bool, string) {

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

// PciLongToIfname return the interface name for a network PCI device.
// This is used to make sure devices don't move around
// Returns exist bool, string
func PciLongToIfname(log *base.LogObject, long string) (bool, string) {

	if !pciLongExists(long) {
		return false, ""
	}
	devPath := pciPath + "/" + long + "/net"
	locations, err := ioutil.ReadDir(devPath)
	if err != nil {
		log.Errorf("Dir %s is missing", devPath)
		return false, ""
	}
	if len(locations) == 0 {
		log.Errorf("Dir %s is empty", devPath)
		return false, ""
	}
	if len(locations) != 1 {
		log.Errorf("Dir %s has multiple: %d", devPath, len(locations))
		for _, location := range locations {
			log.Errorf("Dir %s has %s", devPath, location)
		}
		return false, ""
	}
	ifname := locations[0].Name()
	log.Functionf("PciLongToIfname(%s) %s", long, ifname)
	return true, ifname
}

// IoBundleToPci returns the long PCI ID if the bundle refers to a PCI controller.
// Checks if PCI ID exists on system. Returns null strings for non-PCI
// devices since we can't check if they exist.
// This can handle aliases like Ifname.
func IoBundleToPci(log *base.LogObject, ib *IoBundle) (string, error) {

	var long string
	if ib.PciLong != "" {
		long = ib.PciLong
		// Check if model matches
		if ib.Ifname != "" {
			l, err := ifNameToPci(log, ib.Ifname)
			rename := false
			if err == nil {
				if long != l {
					log.Warnf("Ifname and PciLong mismatch: %s vs %s for %s",
						l, long, ib.Ifname)
					rename = true
				}
			} else {
				rename = true
			}
			if rename {
				found, ifname := PciLongToIfname(log, long)
				if found && ib.Ifname != ifname {
					log.Warnf("%s/%s moved to %s",
						ib.Ifname, long, ifname)
					IfRename(log, ifname, ib.Ifname)
				}
			}
		}
	} else if ib.Ifname != "" {
		var err error
		long, err = ifNameToPci(log, ib.Ifname)
		if err != nil {
			return long, err
		}
	} else {
		return "", nil
	}
	if !pciLongExists(long) {
		errStr := fmt.Sprintf("PCI device ifname %s long %s does not exist",
			ib.Ifname, long)
		return long, errors.New(errStr)
	}
	return long, nil
}

// IfRename brings down the interface, renames it, and brings it back up
func IfRename(log *base.LogObject, ifname string, newIfname string) error {

	log.Functionf("IfRename %s to %s", ifname, newIfname)
	link, err := netlink.LinkByName(ifname)
	if link == nil {
		log.Errorf("LinkByname on %s failed: %s", ifname, err)
		return err
	}
	if err := netlink.LinkSetDown(link); err != nil {
		log.Errorf("LinkSetDown on %s failed: %s", ifname, err)
		return err
	}
	err = netlink.LinkSetName(link, newIfname)
	if err != nil {
		log.Errorf("LinkSetName failed: %s", err)
		// Restore
		netlink.LinkSetUp(link)
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		log.Errorf("LinkSetUp on %s failed: %s", ifname, err)
		return err
	}
	return nil
}
