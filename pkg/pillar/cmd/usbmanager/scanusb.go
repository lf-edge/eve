// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
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

	inSysPath := filepath.Join("bus", "usb", "devices")
	usbDevicesPath := filepath.Join(sysFSPath, inSysPath)

	files, err := os.ReadDir(usbDevicesPath)
	if err != nil {
		log.Fatal(err)
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
		//fmt.Printf("%s -> %s\n", vals[0], vals[1])
		ud := usbDeviceFromSysPath(relPortPath)
		if ud != nil {
			uds = append(uds, ud)
		}
	}

	return uds
}

func usbDeviceFromSysPath(relPortPath string) *usbdevice {
	portPath, err := os.Readlink(relPortPath)
	if err != nil {
		fmt.Printf("err: %+v\n", err)
		return nil
	}

	inSysPath := filepath.Join("bus", "usb", "devices")
	usbDevicesPath := filepath.Join(sysFSPath, inSysPath)
	portPath = filepath.Join(usbDevicesPath, portPath)

	ueventFilePath := filepath.Join(portPath, "uevent")
	return ueventFile2usbDevice(ueventFilePath)
}

func ueventFile2usbDevice(ueventFilePath string) *usbdevice {
	ueventFp, err := os.Open(ueventFilePath)
	if err != nil {
		return nil
	}
	defer ueventFp.Close()

	return ueventFile2usbDeviceImpl(ueventFilePath, ueventFp)
}

func ueventFile2usbDeviceImpl(ueventFilePath string, ueventFp io.Reader) *usbdevice {

	var busnum uint16
	var devnum uint16
	var vendorID uint32
	var productID uint32
	var product string
	var devicetype string

	busnumSet := false
	devnumSet := false
	productSet := false

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
				panic(err)
			}
			busnum = uint16(val64)
			busnumSet = true
		}
		if vals[0] == "DEVNUM" {
			val64, err := strconv.ParseUint(vals[1], 10, 16)
			if err != nil {
				panic(err)
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
