// Copyright (c) 2018 Zededa, Inc.
// All rights reserved.

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
			log.Println(err)
		}
		return "", "", err
	}
	if (info.Mode() & os.ModeSymlink) == 0 {
		log.Printf("Skipping non-symlink %s\n", devPath)
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

// Returns the long and short PCI IDs.
// Check if PCI ID exists on system. Returns null strings for non-PCI
// devices since we can't check if they exist.
// If there are multiple members in the bundle we return the PCI ID for
// the first one we find.
func IoBundleToPci(ib *IoBundle) (string, string, error) {
	var long, short string
	if ib.Lookup {
		var err error
		for _, m := range ib.Members {
			long, short, err = ifNameToPci(m)
			if err == nil {
				break
			}
		}
		if err != nil {
			return "", "", err
		}
	} else if ib.PciShort != "" {
		long = ib.PciLong
		short = ib.PciShort
	}
	if short != "" {
		if !pciLongExists(long) {
			return "", "", errors.New(fmt.Sprintf("PCI device does not exist", long))
		}
	}
	return long, short, nil
}
