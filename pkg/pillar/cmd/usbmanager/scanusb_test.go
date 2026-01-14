// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
	const fileContent = `
MAJOR=189
MINOR=132
DEVNAME=bus/usb/002/005
DEVTYPE=usb_device
DRIVER=usb
PRODUCT=951/1666/1
TYPE=0/0/0
BUSNUM=002
DEVNUM=005
`
	const sysfsPath = "/sys/devices/platform/3610000.xhci/usb2/2-3/2-3.1/uevent"
	tmpSysfsPath := filepath.Join(t.TempDir(), sysfsPath)
	err := os.MkdirAll(tmpSysfsPath, 0o700)
	if err != nil {
		t.Fatalf("could not mkdir '%s': %v", tmpSysfsPath, err)
	}
	ueventPath := filepath.Join(tmpSysfsPath, "uevent")
	err = os.WriteFile(ueventPath, []byte(fileContent), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	ud := ueventFile2usbDeviceOwnImpl(ueventPath)
	if ud == nil {
		t.Fatalf("ueventFile2usbDeviceOwnImpl(%q) returned nil", ueventPath)
	}

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

func ueventFile2usbDeviceOwnImpl(ueventFilePath string) *usbdevice {
	var busnum uint16
	var devnum uint16
	var vendorID uint32
	var productID uint32
	var product string
	var devicetype string

	busnumSet := false
	devnumSet := false
	productSet := false

	ueventFp, err := os.Open(ueventFilePath)
	if err != nil {
		return nil
	}
	defer ueventFp.Close()

	sc := bufio.NewScanner(ueventFp)
	for sc.Scan() {
		vals := strings.SplitN(sc.Text(), "=", 2)
		if len(vals) != 2 {
			continue
		}

		if vals[1] == "" {
			continue
		}

		if vals[0] == "BUSNUM" {
			val64, err := strconv.ParseUint(vals[1], 10, 16)
			if err != nil {
				log.Warnf("could not parse BUSNUM %+v", vals)
				return nil
			}
			busnum = uint16(val64)
			busnumSet = true
		}
		if vals[0] == "DEVNUM" {
			val64, err := strconv.ParseUint(vals[1], 10, 16)
			if err != nil {
				log.Warnf("could not parse DEVNUM %+v", vals)
				return nil
			}
			devnum = uint16(val64)
			devnumSet = true
		}
		if vals[0] == "PRODUCT" {
			product = vals[1]
			vendorID, productID = parseProductString(product)
			if vendorID != 0 || productID != 0 {
				productSet = true
			}
		}
		if vals[0] == "TYPE" {
			devicetype = vals[1]
		}
	}

	if sc.Err() != nil {
		log.Warnf("Parsing of %s failed: %v", ueventFilePath, sc.Err())
		return nil
	}

	if !busnumSet || !devnumSet || !productSet {
		return nil
	}

	pciAddress := extractPCIaddress(ueventFilePath)

	portnum := extractUSBPort(ueventFilePath)

	ud := usbdevice{
		busnum:                  busnum,
		devnum:                  devnum,
		portnum:                 portnum,
		vendorID:                vendorID,
		productID:               productID,
		devicetype:              devicetype,
		usbControllerPCIAddress: pciAddress,
		ueventFilePath:          filepath.Clean(ueventFilePath),
	}

	return &ud
}

func usbDeviceFromSysPath(t *testing.T, relPortPath string) *usbdevice {
	portPath, err := os.Readlink(relPortPath)
	if err != nil {
		panic(err)
	}

	inSysPath := filepath.Join("bus", "usb", "devices")
	usbDevicesPath := filepath.Join(sysFSPath, inSysPath)
	portPath = filepath.Join(usbDevicesPath, portPath)

	ueventFilePath := filepath.Join(portPath, "uevent")
	ownUd := ueventFile2usbDeviceOwnImpl(ueventFilePath)
	ghwUd := ueventFile2usbDevice(ueventFilePath)
	if ownUd == nil && ghwUd == nil {
		return nil
	}
	if *ownUd != *ghwUd {
		t.Fatalf("the two implementations gave different results:\nghw: %+v\nown: %+v", ghwUd, ownUd)
	}

	return ghwUd
}

func walkUSBPortsOwnImpl(t *testing.T) []*usbdevice {
	uds := make([]*usbdevice, 0)

	inSysPath := filepath.Join("bus", "usb", "devices")
	usbDevicesPath := filepath.Join(sysFSPath, inSysPath)

	files, err := os.ReadDir(usbDevicesPath)
	if err != nil {
		return []*usbdevice{}
	}

	re := regexp.MustCompile(`^\d+-\d+`)
	for _, file := range files {
		if len(file.Name()) == 0 {
			continue
		}

		if !re.Match([]byte(file.Name())) {
			continue
		}

		relPortPath := filepath.Join(usbDevicesPath, file.Name())
		ud := usbDeviceFromSysPath(t, relPortPath)
		if ud != nil {
			uds = append(uds, ud)
		}
	}

	return uds
}

func dumpUd(ud *usbdevice) string {
	return fmt.Sprintf(
		"busnum: %d portnum: %s devnum: %d vendorId: %s productId: %s devicetype: %s pciAddr: %s ueventFilepath: %s",
		ud.busnum,
		ud.portnum,
		ud.devnum,
		ud.vendorIDString(),
		ud.productIDString(),
		ud.devicetype,
		ud.usbControllerPCIAddress,
		ud.ueventFilePath,
	)
}

func TestWalkUSBPorts(t *testing.T) {
	ghwUds := walkUSBPorts()
	ourUds := walkUSBPortsOwnImpl(t)

	sort.Slice(ghwUds, func(i, j int) bool {
		ud1, ud2 := ghwUds[i], ghwUds[j]

		return compareUd(ud1, ud2)
	})

	sort.Slice(ourUds, func(i, j int) bool {
		ud1, ud2 := ourUds[i], ourUds[j]

		return compareUd(ud1, ud2)
	})

	fail := func() {
		t.Logf("ghw: %+v\n", ghwUds)
		t.Logf("our: %+v\n", ourUds)

		t.Fatalf("different usb devices found in two implementations")
	}
	if len(ghwUds) != len(ourUds) {
		fail()
	}

	for i := range ourUds {
		ourUd := ourUds[i]
		ghwUd := ghwUds[i]

		if *ourUd != *ghwUd {
			t.Logf("devices are different:\n%+v\nvs.\n%+v\n----\n", dumpUd(ourUd), dumpUd(ghwUd))
			fail()
		}
	}
}

func compareUd(ud1 *usbdevice, ud2 *usbdevice) bool {
	if ud1.busnum != ud2.busnum {
		return ud1.busnum < ud2.busnum
	}

	return ud1.devnum < ud2.devnum
}
