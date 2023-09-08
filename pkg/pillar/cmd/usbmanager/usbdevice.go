// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"fmt"
	"net/url"
	"strings"
)

type usbType int32

const (
	other  usbType = -1
	device usbType = 0
	audio  usbType = 1
	hid    usbType = 3
	hub    usbType = 9
)

type usbAction uint8

func (ud usbdevice) String() string {
	return fmt.Sprintf("busnum: %s devnum: %s product: %s/%s parentPCIAddress: %s ueventFilePath: %s", ud.busnumString(), ud.devnumString(), ud.vendorIDString(), ud.productIDString(), ud.usbControllerPCIAddress, ud.ueventFilePath)
}

func (ud usbdevice) vendorIDString() string {
	return fmt.Sprintf("%04x", ud.vendorID)
}

func (ud usbdevice) productIDString() string {
	return fmt.Sprintf("%04x", ud.productID)
}

func (ud usbdevice) vendorAndproductIDString() string {
	return fmt.Sprintf("%s:%s", ud.vendorIDString(), ud.productIDString())
}

func (ud usbdevice) busnumAndDevnumString() string {
	return fmt.Sprintf("%s:%s", ud.busnumString(), ud.devnumString())
}

func (ud usbdevice) busnumString() string {
	return fmt.Sprintf("%03x", ud.busnum)
}

func (ud usbdevice) devnumString() string {
	return fmt.Sprintf("%03x", ud.devnum)
}

func (ud usbdevice) qemuDeviceName() string {
	id := fmt.Sprintf("USB%s@%d/%d", ud.usbControllerPCIAddress, ud.busnum, ud.devnum)
	id = url.QueryEscape(id)
	id = strings.ReplaceAll(id, "%", "")
	id = strings.ReplaceAll(id, "-", "")
	id = strings.ReplaceAll(id, ".", "")
	return id
}
