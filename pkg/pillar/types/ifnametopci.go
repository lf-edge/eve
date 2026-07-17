// Copyright (c) 2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Read the symlinks in /sys/class/net/*/device to print a mapping
// from ifname to PCI-ID

package types

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/sriov"
	"github.com/vishvananda/netlink"
)

// basePath and pciPath are the sysfs roots for interface and PCI lookups.
// They are variables (not constants) so tests can redirect them at a
// fabricated sysfs tree; production never changes them.
var basePath = "/sys/class/net"
var pciPath = "/sys/bus/pci/devices"

// ExtractUSBBusnumPort extracts busnum and port number out of a sysfs device path
func ExtractUSBBusnumPort(path string) (uint16, string, error) {
	var busnum uint16

	re := regexp.MustCompile(`\/usb\d+(\/\d+\-[\d\.]+)*(\/(\d+)\-([\d\.]+))\/`)

	matches := re.FindStringSubmatch(path)
	if len(matches) < 3 {
		return busnum, "", fmt.Errorf("could not extract usb portnum from %s", path)
	}
	port := matches[len(matches)-1]
	busnumString := matches[len(matches)-2]
	busnum64, err := strconv.ParseUint(busnumString, 10, 16)
	if err != nil {
		return 0, port, fmt.Errorf("could not extract usb busnum from %s", path)
	}
	busnum = uint16(busnum64)

	return busnum, port, nil
}

// IfNameToPciAndUsbAddr returns the long-form PCI address and USB address (if
// any) of the device backing ifName. An L3 port bridged by nim (renamed to
// "k"+ifName) is resolved transparently. Not reliable for cellular modems
// (returns the PCIe bridge, not the modem); use WwanNetworkStatus.PhysAddrs.PCI.
func IfNameToPciAndUsbAddr(log *base.LogObject, ifName string) (string, string, error) {
	// Match for PCI IDs
	re := regexp.MustCompile("([0-9a-f]){4}:([0-9a-f]){2}:([0-9a-f]){2}.[ls0-9a-f]")
	var usbAddr string
	ifPath := basePath + "/" + ifName
	devPath := ifPath + "/device"
	info, err := os.Lstat(devPath)
	if err != nil {
		if !strings.HasPrefix(ifName, "eth") {
			if !os.IsNotExist(err) {
				log.Errorln(err)
			}
			return "", usbAddr, err
		}
		// Try alternate since the PCI device can be kethN
		// if ifName is ethN
		ifName = "k" + ifName
		ifPath = basePath + "/" + ifName
		devPath = ifPath + "/device"
		info, err = os.Lstat(devPath)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Errorln(err)
			}
			return "", usbAddr, err
		}
		log.Noticef("ifNameToPci using alternate %s", ifName)
	}
	if (info.Mode() & os.ModeSymlink) == 0 {
		log.Errorf("Skipping non-symlink %s\n", devPath)
		return "", usbAddr, fmt.Errorf("Not a symlink %s", devPath)
	}
	link, err := os.Readlink(devPath)
	if err != nil {
		return "", usbAddr, err
	}

	ifPathLink, err := os.Readlink(ifPath)
	if err != nil {
		log.Warnf("readlink of %s failed: %+v", ifPath, err)
		ifPathLink = ifPath
	}
	// convert from /sys/class/net/... to path including PCI address and USB address
	// (e.g.: /devices/pci0000:00/0000:00:14.0/usb2/)
	absIfPathLink, err := filepath.Abs(filepath.Join(ifPathLink, link))
	if err != nil {
		absIfPathLink = link
		log.Warnf("getting absolute path of %s failed: %+v", link, err)
	}
	busnum, portnum, err := ExtractUSBBusnumPort(absIfPathLink)
	if err == nil {
		usbAddr = fmt.Sprintf("%d:%s", busnum, portnum)
	}
	target := path.Base(link)
	if re.MatchString(target) {
		return target, usbAddr, nil
	}
	log.Noticef("Not PCI %s - try fallback for %s", target, ifName)
	// Try fallback to handle nested virtualization
	info, err = os.Lstat(ifPath)
	if err != nil {
		log.Noticef("Fallback failed: %s", err)
		return target, usbAddr, fmt.Errorf("Not PCI %s", target)
	}
	if (info.Mode() & os.ModeSymlink) == 0 {
		log.Noticef("Fallback not symlink")
		return target, usbAddr, fmt.Errorf("Not PCI %s", target)
	}
	link, err = os.Readlink(ifPath)
	if err != nil {
		log.Noticef("Fallback readlink failed: %s", err)
		return target, usbAddr, fmt.Errorf("Not PCI %s", target)
	}
	link = path.Clean(link)
	components := strings.Split(link, "/")
	for _, c := range components {
		if re.MatchString(c) {
			log.Noticef("Fallback found %s", c)
			return c, usbAddr, nil
		}
	}
	return target, usbAddr, fmt.Errorf("Not PCI %s", target)
}

// Returns the long PCI IDs for Virtual function
func vfIfNameToPci(ifName string) (string, error) {
	index, parentIface, err := sriov.ParseVfIfaceName(ifName)
	if err != nil {
		return "", err
	}
	vfList, err := sriov.GetVf(parentIface)
	if err != nil {
		return "", err
	}
	vfIface := vfList.GetInfo(index)
	if vfIface == nil {
		return "", fmt.Errorf("Could not obtain information for %d vf for iface %s", index, parentIface)
	}
	return vfIface.PciLong, nil
}

// PCILongToShort returns the PCI ID without the domain id
func PCILongToShort(long string) string {
	return strings.SplitAfterN(long, ":", 2)[1]
}

// PCISameController compares the PCI-ID without comparing the controller
func PCISameController(long1 string, long2 string) bool {
	if long1 == "" || long2 == "" {
		return false
	}
	ctrl1 := strings.SplitAfter(long1, ".")[0]
	ctrl2 := strings.SplitAfter(long2, ".")[0]
	return ctrl1 == ctrl2
}

// PCIGetIOMMUGroup returns IOMMU group tag as seen by the control domain
func PCIGetIOMMUGroup(long string) (string, error) {
	pathDev := pciPath + "/" + long + "/iommu_group"
	if iommuPath, err := os.Readlink(pathDev); err != nil {
		return "", fmt.Errorf("can't determine iommu group for %s (%v)", long, err)
	} else {
		return path.Base(iommuPath), nil
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
	locations, err := os.ReadDir(devPath)
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
func IoBundleToPci(log *base.LogObject, ib *IoBundle) (string, error) { //nolint:gocyclo
	var long string
	if ib.PciLong != "" {
		long = ib.PciLong
		// Check if model matches
		if ib.Ifname != "" {
			var l string
			var err error
			if ib.Type == IoNetEthVF {
				l, err = vfIfNameToPci(ib.Ifname)
			} else {
				l, ib.UsbAddr, err = IfNameToPciAndUsbAddr(log, ib.Ifname)
			}
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
			var renameWarn []string
			if rename {
				found, ifname := PciLongToIfname(log, long)
				if found && ib.Ifname != ifname {
					log.Warnf("%s/%s moved to %s",
						ib.Ifname, long, ifname)
					// Renaming to match the model is an auto-adjustment; warn so
					// the controller sees it.
					renameWarn = []string{fmt.Sprintf(
						"adapter %s (logicallabel %s): model interface name %q does "+
							"not match kernel name %q for PCI %s; renamed to match the model",
						ib.Phylabel, ib.Logicallabel, ib.Ifname, ifname, long)}
					IfRename(log, ifname, ib.Ifname)
				}
			}
			// Reconcile the rename warning (self-clears when no longer renaming).
			ib.Error.SetSourceErrors(ErrIoBundleRename{}, true, false, renameWarn)
		}
	} else if ib.Ifname != "" {
		var err error
		if ib.Type == IoNetEthVF {
			long, err = vfIfNameToPci(ib.Ifname)
			if err != nil {
				return long, ErrIoBundleMissingDevice{msg: err.Error()}
			}
		} else {
			long, ib.UsbAddr, err = IfNameToPciAndUsbAddr(log, ib.Ifname)
			if err != nil {
				return long, ErrIoBundleMissingDevice{msg: err.Error()}
			}
		}
	} else {
		return "", nil
	}
	if !pciLongExists(long) {
		return long, ErrIoBundleMissingDevice{msg: fmt.Sprintf(
			"PCI device %s/%s long %s does not exist",
			ib.Phylabel, ib.Logicallabel, long)}
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

// PCIIsBootVga return 'true' if VGA device is a console device
func PCIIsBootVga(log *base.LogObject, long string) (bool, error) {
	log.Functionf("PCIIsBootVga %s", long)

	bootVgaFile := pciPath + "/" + long + "/boot_vga"
	if isBoot, err := os.ReadFile(bootVgaFile); err != nil {
		return false, err
	} else {
		return strings.TrimSpace(strings.TrimSuffix(string(isBoot), "\n")) == "1", err
	}
}
