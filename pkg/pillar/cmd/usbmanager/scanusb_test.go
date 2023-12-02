// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"strings"
	"testing"
)

func TestExtractUSBPort(t *testing.T) {
	t.Parallel()

	table := []struct {
		path string
		port string
	}{
		{"/sys/devices/pci0000:00/0000:00:14.0/usb3/3-6/uevent", "6"},
		{"/sys/devices/pci0000:00/0000:00:14.0/usb3/3-3/3-3.1/uevent", "3.1"},
	}

	for _, test := range table {
		port := extractUSBPort(test.path)
		if port != test.port {
			t.Fatalf("expected port %s but got %s, path is %s", test.port, port, test.path)
		}
	}
}

func TestExtractPCIAddress(t *testing.T) {
	// /sys/devices/platform/soc@0/32f10108.usb/38200000.dwc3/xhci-hcd.1.auto/usb3/3-1/3-1.4/3-1.4:1.0/uevent
	table := []struct {
		path       string
		pciAddress string
	}{
		{"/sys/devices/pci0000:00/0000:00:14.0/usb3/3-6/uevent", "0000:00:14.0"},
		{"/sys/devices/pci0000:00/0000:00:14.0/usb3/3-3/3-3.1/uevent", "0000:00:14.0"},
		{"/sys/devices/platform/soc@0/32f10108.usb/38200000.dwc3/xhci-hcd.1.auto/usb3/3-1/3-1.4/3-1.4:1.0/uevent", ""},
	}

	for _, test := range table {
		port := extractPCIaddress(test.path)
		if port != test.pciAddress {
			t.Fatalf("expected port %s but got %s, path is %s", test.pciAddress, port, test.path)
		}
	}
}

func TestUeventFile2usbDeviceImplWithoutPCIAddress(t *testing.T) {
	fileFp := strings.NewReader(`
MAJOR=189
MINOR=132
DEVNAME=bus/usb/002/005
DEVTYPE=usb_device
DRIVER=usb
PRODUCT=951/1666/1
TYPE=0/0/0
BUSNUM=002
DEVNUM=005
`)
	ud := ueventFile2usbDeviceImpl("/sys/devices/platform/3610000.xhci/usb2/2-3/2-3.1/uevent", fileFp)

	if ud.busnum != 2 {
		t.Fatalf("wrong busnum, got %d", ud.busnum)
	}
	if ud.devnum != 5 {
		t.Fatalf("wrong devnum, got %d", ud.devnum)
	}
	if ud.vendorID != 2385 {
		t.Fatalf("wrong vendor id, got %d", ud.vendorID)
	}
	if ud.productID != 5734 {
		t.Fatalf("wrong product id, got %d", ud.productID)
	}
	if ud.devicetype != "0/0/0" {
		t.Fatalf("wrong type, got %s", ud.devicetype)
	}
	if ud.usbControllerPCIAddress != "" {
		t.Fatalf("wrong pci address , got %s", ud.usbControllerPCIAddress)
	}
}
