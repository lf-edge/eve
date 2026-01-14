// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/zededa/ghw"
	"github.com/zededa/ghw/pkg/option"
	"github.com/zededa/ghw/pkg/usb"
)

func trimSysPath(path string) string {
	relPath := strings.TrimLeft(path, sysFSPath)

	return relPath
}

func extractPCIaddress(path string) string {
	re := regexp.MustCompile(`\/?devices\/pci[\d:.]*\/(\d{4}:[a-f\d:\.]+)\/`)

	relPath := trimSysPath(path)
	matches := re.FindStringSubmatch(relPath)
	if len(matches) != 2 {
		return ""
	}
	pciAddress := matches[1]

	return pciAddress
}

func extractUSBPort(path string) string {
	_, port, err := types.ExtractUSBBusnumPort(path)

	if err != nil {
		log.Warn(err)
	}

	return port
}

func walkUSBPorts() []*usbdevice {
	uds := make([]*usbdevice, 0)

	info, err := ghw.USB(option.WithDisableTools())
	if err != nil {
		log.Warnf("requesting USB info failed: %+v", err)
		return []*usbdevice{}
	}

	for _, dev := range info.Devices {
		ud := ghwUSBDevice2usbdevice(dev)
		if ud == nil {
			continue
		}

		uds = append(uds, ud)
	}
	return uds
}

func ghwUSBDevice2usbdevice(dev *usb.Device) *usbdevice {
	devnum, err := strconv.ParseUint(dev.Devnum, 10, 16)
	if err != nil {
		// ignore hubs, devices with invalid devnum
		return nil
	}

	// continue even if parsing vendor/product fails, because in the case of passthrough
	// by port it still works
	vendorID, err := strconv.ParseUint(dev.VendorID, 16, 32)
	if err != nil {
		log.Warnf("could not parse vendor id '%s' as uint32: %+v", dev.VendorID, err)
	}
	productID, err := strconv.ParseUint(dev.ProductID, 16, 32)
	if err != nil {
		log.Warnf("could not parse product id '%s' as uint32: %+v", dev.ProductID, err)
	}

	var usbControllerPCIAddress string
	if dev.Parent.PCI != nil {
		usbControllerPCIAddress = dev.Parent.PCI.String()
	}
	ud := usbdevice{
		busnum:                  dev.Busnum,
		portnum:                 dev.Port,
		devnum:                  uint16(devnum),
		vendorID:                uint32(vendorID),
		productID:               uint32(productID),
		devicetype:              dev.Type,
		usbControllerPCIAddress: usbControllerPCIAddress,
		ueventFilePath:          dev.UEventFilePath,
	}
	return &ud
}

func ueventFile2usbDevice(ueventFilePath string) *usbdevice {
	info, err := ghw.USB(option.WithUSBUeventPath(ueventFilePath), option.WithDisableTools())
	if err != nil {
		log.Warnf("could not retrieve usb device for '%s': %v", ueventFilePath, err)
		return nil
	}

	for _, dev := range info.Devices {
		ud := ghwUSBDevice2usbdevice(dev)
		if ud != nil {
			return ud
		}
	}

	return nil
}

func parseProductString(product string) (uint32, uint32) {
	var vendorID uint32
	var productID uint32

	vals := strings.SplitN(product, "/", 3)
	if len(vals) < 2 {
		return 0, 0
	}

	for i, v := range []*uint32{&vendorID, &productID} {

		val64, err := strconv.ParseUint(vals[i], 16, 32)
		if err != nil {
			return 0, 0
		}

		*v = uint32(val64)
	}

	return vendorID, productID
}
