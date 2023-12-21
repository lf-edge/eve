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

type pciPassthroughRule struct {
	pciAddress string
	passthroughRuleVMBase
}

func (pr *pciPassthroughRule) String() string {
	return fmt.Sprintf("PCI Passthrough Rule %s", pr.pciAddress)
}

func (pr *pciPassthroughRule) evaluate(ud usbdevice) passthroughAction {
	if ud.usbControllerPCIAddress == pr.pciAddress {
		return passthroughDo
	}

	return passthroughNo
}

func (pr *pciPassthroughRule) priority() uint8 {
	return 0
}

type usbDevicePassthroughRule struct {
	vendorID  uint32
	productID uint32
	passthroughRuleVMBase
}

func (udpr *usbDevicePassthroughRule) String() string {
	return fmt.Sprintf("USB Device Passthrough Rule %x/%x", udpr.vendorID, udpr.productID)
}

func (udpr *usbDevicePassthroughRule) priority() uint8 {
	return 10
}

func (udpr *usbDevicePassthroughRule) evaluate(ud usbdevice) passthroughAction {
	if udpr.vendorID != ud.vendorID ||
		udpr.productID != ud.productID {
		return passthroughNo
	}

	return passthroughDo
}

type compositionPassthroughRule struct {
	rules []passthroughRule
	passthroughRuleVMBase
}

func (cpr *compositionPassthroughRule) evaluate(ud usbdevice) passthroughAction {
	if len(cpr.rules) == 0 {
		return passthroughNo
	}

	var ret passthroughAction
	ret = passthroughDo

	for _, rule := range cpr.rules {
		action := rule.evaluate(ud)
		if action == passthroughForbid {
			return action
		}
		if action == passthroughNo {
			ret = passthroughNo
		}
	}
	return ret
}

func (cpr *compositionPassthroughRule) String() string {
	var ret string

	for _, rule := range cpr.rules {
		ret += fmt.Sprintf("|%s", rule.String())
	}

	ret += "|"

	return ret
}

func (cpr *compositionPassthroughRule) priority() uint8 {
	var ret uint8

	ret = 1
	for _, rule := range cpr.rules {
		oldPrio := ret
		ret += rule.priority()
		if ret < oldPrio {
			panic("overflow happened") // panic here to detect these failures in go tests
		}
	}

	return ret
}

type usbPortPassthroughRule struct {
	busnum  uint16
	portnum string
	passthroughRuleVMBase
}

func (uppr *usbPortPassthroughRule) String() string {
	return fmt.Sprintf("USB Port Passthrough Rule %x/%s", uppr.busnum, uppr.portnum)
}

func (uppr *usbPortPassthroughRule) priority() uint8 {
	return 20
}

func (uppr *usbPortPassthroughRule) evaluate(ud usbdevice) passthroughAction {
	if uppr.portnum != ud.portnum ||
		uppr.busnum != ud.busnum {
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

		// remove net/enp0s20f0u2u1/ and prefix with sysfs dir
		absPath, err := filepath.Abs(filepath.Join(netDir, relPath, "..", ".."))
		if err != nil {
			panic(err)
		}

		netDevPaths = append(netDevPaths, absPath)
	}
	return netDevPaths
}
