// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

// define a path in sysfs to the PCI devices
const sysfsPciDevices = "/sys/bus/pci/devices/"

// define go constants for the flags as defined in include/linux/pci_ids.h
//
//revive:disable:var-naming
const (
	IORESOURCE_BITS      = 0x000000ff
	IORESOURCE_TYPE_BITS = 0x00001f00
	IORESOURCE_IO        = 0x00000100
	IORESOURCE_MEM       = 0x00000200
	IORESOURCE_REG       = 0x00000300
	IORESOURCE_IRQ       = 0x00000400
	IORESOURCE_DMA       = 0x00000800
	IORESOURCE_BUS       = 0x00001000
	IORESOURCE_MEM_64    = 0x00100000
)

// https://elixir.bootlin.com/linux/latest/source/include/linux/pci_ids.h#L57
const (
	PCI_BASE_CLASS_BRIDGE = "0x06"
)

//revive:enable:var-naming
type pciResource struct {
	start uint64
	end   uint64
	flags uint64
	index int
}

// implement some useful functions on pciResource
func (r pciResource) size() uint64 {
	return r.end - r.start + 1
}

// returns true if the resource is valid
func (r pciResource) valid() bool {
	return r.flags != 0 && r.start != 0 && r.end != 0
}

// returns true if the resource is MEM
func (r pciResource) isMem() bool {
	return r.flags&IORESOURCE_TYPE_BITS == IORESOURCE_MEM
}

func addNoDuplicatePCI(list []pciDevice, tap pciDevice) []pciDevice {

	for _, t := range list {
		if t.pciLong == tap.pciLong {
			return list
		}
	}
	return append(list, tap)
}

type pciDevice struct {
	pciLong string
	ioType  types.IoType
}

// check if the PCI device is a VGA device
// check availability of the VGA file in the sysfs filesystem
func (d pciDevice) isVGA() bool {
	bootVgaFile := filepath.Join(sysfsPciDevices, d.pciLong, "boot_vga")
	return utils.FileExists(nil, bootVgaFile)
}

// read vendor ID
func (d pciDevice) vid() (string, error) {
	vendorID, err := os.ReadFile(filepath.Join(sysfsPciDevices, d.pciLong, "vendor"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.TrimSuffix(string(vendorID), "\n")), nil
}

// read device ID
func (d pciDevice) devid() (string, error) {
	devID, err := os.ReadFile(filepath.Join(sysfsPciDevices, d.pciLong, "device"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.TrimSuffix(string(devID), "\n")), nil
}

// isBridge checks if the given PCI device is a bridge.
// It reads the device's class from the sysfs filesystem and returns true if the class
// starts with "0x06", which is the PCI base class code for bridges.
// ./class file contains 3 bytes of class code as following
// base_class,subclass,prog-if
// e.g. 0x06,0x04,0x00 - PCI bridge
func (d pciDevice) isBridge() (bool, error) {
	class, err := os.ReadFile(filepath.Join(sysfsPciDevices, d.pciLong, "class"))

	if err != nil {
		logrus.Errorf("Can't read PCI device class %s: %v\n",
			d.pciLong, err)
		return true, err // assume it is a bridge
	}

	if strings.HasPrefix(string(class), PCI_BASE_CLASS_BRIDGE) {
		return true, nil
	}

	return false, nil
}

// check if the PCI device a boot_vga device
// read the boot_vga file from the sysfs filesystem
// and return true if the file contains "1"
func (d pciDevice) isBootVGA() (bool, error) {
	bootVGA, err := os.ReadFile(filepath.Join(sysfsPciDevices, d.pciLong, "boot_vga"))

	if err != nil {
		logrus.Errorf("Can't read PCI device boot_vga %s: %v\n",
			d.pciLong, err)
		return false, err
	}

	if strings.TrimSpace(string(bootVGA)) == "1" {
		return true, nil
	}

	return false, nil
}

// readResources reads all resources of the PCI device in a list of structs {start, end, flags}
func (d pciDevice) readResources() ([]pciResource, error) {
	var resources []pciResource
	var resourceIndexes []int

	contains := func(slice []int, item int) bool {
		for _, s := range slice {
			if s == item {
				return true
			}
		}
		return false
	}

	path := filepath.Join(sysfsPciDevices, d.pciLong)

	// read directory for device and collect valid resource indexes
	files, err := os.ReadDir(path)
	if err != nil {
		return nil, logError("Can't read PCI device directory %s: %v\n",
			path, err)
	}

	// collect indexes of valid resources
	for _, file := range files {
		name := file.Name()
		// skip files that are not resources or are write-combining that mapped to the same addresses
		if !strings.HasPrefix(name, "resource") || strings.HasSuffix(name, "_wc") {
			continue
		}
		// trim prefix and convert to integer
		resourceIndex := strings.TrimPrefix(name, "resource")
		if resourceIndex == "" {
			continue
		}

		index, err := strconv.Atoi(resourceIndex)
		if err != nil {
			return nil, logError("Can't convert PCI device resource index %s: %v\n",
				resourceIndex, err)
		}
		resourceIndexes = append(resourceIndexes, index)
	}

	data, err := os.ReadFile(filepath.Join(path, "resource"))
	if err != nil {
		return nil, logError("Can't read PCI device resource file %s: %v\n",
			path, err)
	}

	lines := strings.Split(string(data), "\n")

	for index, line := range lines {
		var start, end, flags uint64

		if strings.TrimSpace(line) == "" {
			continue
		}

		// check if the resource index is valid
		if !contains(resourceIndexes, index) {
			continue
		}

		_, err = fmt.Sscanf(line, "0x%016x 0x%016x 0x%016x", &start, &end, &flags)
		if err != nil {
			return nil, logError("Can't decode PCI device resource %s: [%s] %v\n",
				line, path, err)
		}

		resources = append(resources, pciResource{start: start, end: end, flags: flags, index: index})
	}

	return resources, nil
}
