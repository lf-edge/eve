// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"strconv"
	"strings"
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const sysFSPath = "/sys"

type usbmanagerController struct {
	ruleEngine      *ruleEngine
	name2deviceRule map[string]passthroughRule

	usbpassthroughs usbpassthroughs

	connectUSBDeviceToQemu      func(up usbpassthrough)
	disconnectUSBDeviceFromQemu func(up usbpassthrough)

	listenUSBStopChan chan struct{}

	sync.Mutex
}

func (uc *usbmanagerController) init() {
	uc.Lock()
	uc.ruleEngine = newRuleEngine()

	usbNetworkAdapterForbidPassthroughRule := newUsbNetworkAdapterForbidPassthroughRule()
	uc.ruleEngine.addRule(&usbNetworkAdapterForbidPassthroughRule)
	uc.ruleEngine.addRule(&usbHubForbidPassthroughRule{})

	uc.name2deviceRule = make(map[string]passthroughRule)

	uc.usbpassthroughs = newUsbpassthroughs()

	uc.connectUSBDeviceToQemu = uc.connectUSBDeviceToQemuImpl
	uc.disconnectUSBDeviceFromQemu = uc.disconnectUSBDeviceFromQemuImpl

	uc.Unlock()
}

// prevents trying to connect a usb device twice
func (uc *usbmanagerController) connectUSBDeviceToQemuIdempotent(up usbpassthrough) {
	if uc.usbpassthroughs.hasUsbpassthrough(up) {
		log.Warnf("%+v is already passed through\n", up)
		return
	}
	uc.usbpassthroughs.addUsbpassthrough(&up)
	uc.connectUSBDeviceToQemu(up)
}

// prevents trying to disconnect a usb device twice
func (uc *usbmanagerController) disconnectUSBDeviceFromQemuIdempotent(up usbpassthrough) {
	if !uc.usbpassthroughs.hasUsbpassthrough(up) {
		return
	}
	uc.usbpassthroughs.delUsbpassthrough(&up)
	uc.disconnectUSBDeviceFromQemu(up)
}

func (uc *usbmanagerController) connectUSBDeviceToQemuImpl(up usbpassthrough) {
	log.Tracef("connect usb passthrough %+v to %s\n", up, up.vm.qmpSocketPath)

	err := hypervisor.QmpExecDeviceAdd(up.vm.qmpSocketPath, up.usbdevice.qemuDeviceName(), up.usbdevice.busnum, up.usbdevice.devnum)
	if err != nil {
		log.Warnf("connect qmp failed: %+v\n", err)
	}
}

func (uc *usbmanagerController) disconnectUSBDeviceFromQemuImpl(up usbpassthrough) {
	log.Tracef("disconnect usb passthrough %+v to %s\n", up, up.vm.qmpSocketPath)

	err := hypervisor.QmpExecDeviceDelete(up.vm.qmpSocketPath, up.usbdevice.qemuDeviceName())
	if err != nil {
		log.Warnf("disconnect qmp failed: %+v\n", err)
	}
}

func (uc *usbmanagerController) addUSBDevice(ud usbdevice) {
	uc.Lock()
	defer uc.Unlock()

	uc.usbpassthroughs.addUsbdevice(&ud)
	vm := uc.ruleEngine.apply(ud)
	log.Tracef("add usb device %+v vm=%v; rules: %s\n", ud, vm, uc.ruleEngine.String())
	if vm != nil {
		uc.connectUSBDeviceToQemuIdempotent(usbpassthrough{
			usbdevice: &ud,
			vm:        vm,
		})
	}
}

func (uc *usbmanagerController) removeUSBDevice(ud usbdevice) {
	uc.Lock()
	defer uc.Unlock()
	vm := uc.ruleEngine.apply(ud)
	log.Tracef("remove usb device %+v vm=%v; rules: %s\n", ud, vm, uc.ruleEngine.String())
	if vm != nil {
		uc.disconnectUSBDeviceFromQemuIdempotent(usbpassthrough{
			usbdevice: &ud,
			vm:        vm,
		})
		uc.usbpassthroughs.delUsbdevice(&ud)

	}
}

func (uc *usbmanagerController) addVirtualmachine(vm virtualmachine) {
	uc.Lock()
	defer uc.Unlock()
	log.Tracef("add vm %+v", vm)
	uc.usbpassthroughs.addVM(&vm)

	// add rules
	for _, phyLabel := range vm.adapters {
		ioBundle := uc.usbpassthroughs.ioBundles[phyLabel]
		if ioBundle == nil {
			continue
		}

		pr := ioBundle2PassthroughRule(*ioBundle)
		if pr == nil {
			continue
		}
		pr.setVirtualMachine(&vm)

		uc.ruleEngine.addRule(pr)
	}

	// find and connect usb device
	for _, ud := range uc.usbpassthroughs.listUsbdevices() {
		vm := uc.ruleEngine.apply(*ud)
		if vm == nil {
			continue
		}
		uc.connectUSBDeviceToQemuIdempotent(usbpassthrough{
			usbdevice: ud,
			vm:        vm,
		})
	}
}

func (uc *usbmanagerController) removeVirtualmachine(vm virtualmachine) {
	uc.Lock()
	defer uc.Unlock()
	ups := uc.usbpassthroughs.usbpassthroughsOfVM(vm)
	for _, up := range ups {
		uc.disconnectUSBDeviceFromQemuIdempotent(*up)
		uc.usbpassthroughs.delUsbpassthrough(up)
	}
	for _, phyLabel := range vm.adapters {
		ioBundle := uc.usbpassthroughs.ioBundles[phyLabel]
		if ioBundle == nil {
			continue
		}

		pr := ioBundle2PassthroughRule(*ioBundle)
		if pr == nil {
			continue
		}
		uc.ruleEngine.delRule(pr)
	}

	uc.usbpassthroughs.delVM(&vm)
}

func (uc *usbmanagerController) removeIOBundle(ioBundle types.IoBundle) {
	uc.Lock()
	defer uc.Unlock()

	uc.usbpassthroughs.delIoBundle(&ioBundle)

	pr := ioBundle2PassthroughRule(ioBundle)
	if pr == nil {
		return
	}
	vm := uc.usbpassthroughs.vmsByIoBundlePhyLabel[ioBundle.Phylabel]
	pr.setVirtualMachine(vm)

	uc.ruleEngine.delRule(pr)

	for _, ud := range uc.usbpassthroughs.listUsbdevices() {
		vm := uc.ruleEngine.apply(*ud)
		if vm == nil {
			continue
		}
		uc.disconnectUSBDeviceFromQemuIdempotent(usbpassthrough{
			usbdevice: ud,
			vm:        vm,
		})
	}
}

func (uc *usbmanagerController) addIOBundle(ioBundle types.IoBundle) {
	uc.Lock()
	defer uc.Unlock()
	log.Tracef("add iobundle %s: %s/%s\n", ioBundle.Phylabel, ioBundle.UsbAddr, ioBundle.PciLong)
	uc.usbpassthroughs.addIoBundle(&ioBundle)

	pr := ioBundle2PassthroughRule(ioBundle)
	if pr == nil {
		return
	}
	vm := uc.usbpassthroughs.vmsByIoBundlePhyLabel[ioBundle.Phylabel]
	pr.setVirtualMachine(vm)

	uc.ruleEngine.addRule(pr)

	for _, ud := range uc.usbpassthroughs.listUsbdevices() {
		vm := uc.ruleEngine.apply(*ud)
		if vm == nil {
			continue
		}
		uc.connectUSBDeviceToQemuIdempotent(usbpassthrough{
			usbdevice: ud,
			vm:        vm,
		})
	}
}

func (uc *usbmanagerController) cancel() {
	uc.listenUSBStopChan <- struct{}{}
}

func ioBundle2PassthroughRule(adapter types.IoBundle) passthroughRule {
	prs := make([]passthroughRule, 0)

	if adapter.PciLong != "" && adapter.UsbAddr == "" && adapter.UsbProduct == "" {
		return &pciPassthroughForbidRule{pciAddress: adapter.PciLong}
	}

	if adapter.PciLong != "" {
		pci := pciPassthroughRule{pciAddress: adapter.PciLong}

		prs = append(prs, &pci)
	}
	if adapter.UsbAddr != "" {
		usbParts := strings.SplitN(adapter.UsbAddr, ":", 2)
		if len(usbParts) != 2 {
			log.Warnf("usbaddr %s not parseable", adapter.UsbAddr)
			return nil
		}
		busnum, err := strconv.ParseUint(usbParts[0], 10, 16)
		if err != nil {
			log.Warnf("usbaddr busnum (%s) not parseable", usbParts[0])
			return nil
		}
		portnum := usbParts[1]

		usb := usbPortPassthroughRule{
			busnum:  uint16(busnum),
			portnum: portnum,
		}

		prs = append(prs, &usb)
	}
	if adapter.UsbProduct != "" {
		usbParts := strings.SplitN(adapter.UsbProduct, ":", 2)
		if len(usbParts) != 2 {
			log.Warnf("usbproduct %s not parseable", adapter.UsbProduct)
			return nil
		}

		vendorID, errVendor := strconv.ParseUint(usbParts[0], 16, 32)
		productID, errProduct := strconv.ParseUint(usbParts[1], 16, 32)
		if errVendor != nil || errProduct != nil {
			log.Warnf("extracting vendor/product id out of usbproduct %s (phylabel: %s) failed: %v/%v",
				adapter.UsbProduct, adapter.Phylabel, errVendor, errProduct)
			return nil
		}

		usb := usbDevicePassthroughRule{
			vendorID:              uint32(vendorID),
			productID:             uint32(productID),
			passthroughRuleVMBase: passthroughRuleVMBase{},
		}

		prs = append(prs, &usb)
	}
	if len(prs) == 0 {
		log.Tracef("cannot create rule out of adapter %+v\n", adapter)
		return nil
	}
	if len(prs) == 1 {
		return prs[0]
	}

	ret := compositionPassthroughRule{
		rules: prs,
	}

	return &ret
}
