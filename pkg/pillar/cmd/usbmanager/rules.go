// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type passthroughAction uint8

const (
	// this rule applies
	passthroughDo = 0
	// this rule does not apply
	passthroughNo = iota
	// this rule forbids passthrough even if other rules apply
	passthroughForbid = iota
)

type virtualmachine struct {
	qmpSocketPath string
	adapters      []string
}

func newVirtualmachine(qmpSocketPath string, adapters []string) virtualmachine {
	vm := virtualmachine{
		qmpSocketPath: qmpSocketPath,
		adapters:      adapters,
	}

	if vm.adapters == nil {
		vm.adapters = make([]string, 0)
	}

	return vm
}

func (vm *virtualmachine) addAdapter(adapter string) {
	vm.adapters = append(vm.adapters, adapter)
}

func (vm virtualmachine) String() string {
	return fmt.Sprintf("vm-qmp: %s adapters: '%s'", vm.qmpSocketPath, strings.Join(vm.adapters, ", "))
}

type passthroughRule interface {
	evaluate(ud usbdevice) passthroughAction
	priority() uint8
	virtualMachine() *virtualmachine
	setVirtualMachine(vm *virtualmachine)
	String() string
}

func (pr passthroughAction) String() string {
	if pr == passthroughDo {
		return "do passthrough"
	} else if pr == passthroughNo {
		return "no passthrough"
	} else if pr == passthroughForbid {
		return "forbid passthrough"
	}

	return ""
}

type passthroughRuleVMBase struct {
	vm *virtualmachine
}

func (pr *passthroughRuleVMBase) setVirtualMachine(vm *virtualmachine) {
	pr.vm = vm
}

func (pr *passthroughRuleVMBase) virtualMachine() *virtualmachine {
	return pr.vm
}

type pciPassthroughForbidRule struct {
	pciAddress string
	passthroughRuleVMBase
}

func (pr *pciPassthroughForbidRule) String() string {
	return fmt.Sprintf("PCI Passthrough Forbid Rule %s", pr.pciAddress)
}

func (pr *pciPassthroughForbidRule) evaluate(ud usbdevice) passthroughAction {
	if ud.usbControllerPCIAddress == pr.pciAddress {
		return passthroughForbid
	}

	return passthroughNo
}

func (pr *pciPassthroughForbidRule) priority() uint8 {
	return 0
}

type usbDevicePassthroughRule struct {
	ud usbdevice
	passthroughRuleVMBase
}

func (udpr *usbDevicePassthroughRule) String() string {
	return fmt.Sprintf("USB Device Passthrough Rule %s on pci %s", udpr.ud.vendorAndproductIDString(), udpr.ud.usbControllerPCIAddress)
}

func (udpr *usbDevicePassthroughRule) priority() uint8 {
	return 10
}

func (udpr *usbDevicePassthroughRule) evaluate(ud usbdevice) passthroughAction {
	if udpr.ud.usbControllerPCIAddress != "" && udpr.ud.usbControllerPCIAddress != ud.usbControllerPCIAddress {
		return passthroughNo
	}
	if udpr.ud.vendorID != ud.vendorID ||
		udpr.ud.productID != ud.productID {
		return passthroughNo
	}

	return passthroughDo
}

type usbPortPassthroughRule struct {
	ud usbdevice
	passthroughRuleVMBase
}

func (uppr *usbPortPassthroughRule) String() string {
	return fmt.Sprintf("USB Port Passthrough Rule %s on pci %s", uppr.ud.busnumAndPortnumString(), uppr.ud.usbControllerPCIAddress)
}

func (uppr *usbPortPassthroughRule) priority() uint8 {
	return 20
}

func (uppr *usbPortPassthroughRule) evaluate(ud usbdevice) passthroughAction {
	if uppr.ud.usbControllerPCIAddress != "" && uppr.ud.usbControllerPCIAddress != ud.usbControllerPCIAddress {
		return passthroughNo
	}
	if uppr.ud.portnum != ud.portnum ||
		uppr.ud.busnum != ud.busnum {
		return passthroughNo
	}

	return passthroughDo
}

type usbHubForbidPassthroughRule struct {
	passthroughRuleVMBase
}

func (uhfpr *usbHubForbidPassthroughRule) String() string {
	return "usbHubForbidPassthroughRule"
}

func (uhfpr *usbHubForbidPassthroughRule) priority() uint8 {
	return 0
}

func (uhfpr *usbHubForbidPassthroughRule) evaluate(ud usbdevice) passthroughAction {
	if strings.HasPrefix(ud.devicetype, "9/") {
		log.Tracef("usb hub forwarding is forbidden - %+v", ud)
		return passthroughForbid
	}

	return passthroughNo
}

func newUsbNetworkAdapterForbidPassthroughRule() usbNetworkAdapterForbidPassthroughRule {
	unafpr := usbNetworkAdapterForbidPassthroughRule{}
	unafpr.netDevPaths = unafpr.netDevPathsImpl

	return unafpr
}

type usbNetworkAdapterForbidPassthroughRule struct {
	netDevPaths func() []string
	passthroughRuleVMBase
}

func (unafpr *usbNetworkAdapterForbidPassthroughRule) String() string {
	return "usbNetworkAdapterForbidPassthroughRule"
}

func (unafpr *usbNetworkAdapterForbidPassthroughRule) priority() uint8 {
	return 0
}

func (unafpr *usbNetworkAdapterForbidPassthroughRule) evaluate(ud usbdevice) passthroughAction {
	netDevPaths := unafpr.netDevPaths()

	ueventDirname := filepath.Dir(ud.ueventFilePath) + "/"
	for _, path := range netDevPaths {
		if strings.HasPrefix(path, ueventDirname) {
			log.Tracef("usb network adapter forwarding is forbidden - %+v", ud)
			return passthroughForbid
		}
	}

	return passthroughNo
}

func (*usbNetworkAdapterForbidPassthroughRule) netDevPathsImpl() []string {
	netDir := filepath.Join(sysFSPath, "class", "net")
	netDevfiles, err := os.ReadDir(netDir)
	if err != nil {
		panic(err)
	}

	netDevPaths := make([]string, 0)

	for _, file := range netDevfiles {
		// e.g. ../../devices/pci0000:00/0000:00:14.0/usb4/4-2/4-2.1/4-2.1:1.0/net/enp0s20f0u2u1/
		relPath, err := os.Readlink(filepath.Join(netDir, file.Name()))
		if err != nil {
			panic(err)
		}

		// remove net/enp0s20f0u2u1/ and prefix with syfs dir
		absPath, err := filepath.Abs(filepath.Join(netDir, relPath, "..", ".."))
		if err != nil {
			panic(err)
		}

		netDevPaths = append(netDevPaths, absPath)
	}
	return netDevPaths
}
