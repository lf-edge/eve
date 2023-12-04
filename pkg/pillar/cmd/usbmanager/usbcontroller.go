// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/hypervisor"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

const sysFSPath = "/sys"

type usbmanagerController struct {
	ruleEngine *ruleEngine

	usbpassthroughs usbpassthroughs

	connectUSBDeviceToQemu      func(up usbpassthrough)
	disconnectUSBDeviceFromQemu func(up usbpassthrough)

	listenUSBStopChan chan struct{}

	iobt *ioBundleTree

	sync.Mutex
}

func (uc *usbmanagerController) init() {
	uc.Lock()
	uc.ruleEngine = newRuleEngine()

	usbNetworkAdapterForbidPassthroughRule := newUsbNetworkAdapterForbidPassthroughRule()
	uc.ruleEngine.addRule(&usbNetworkAdapterForbidPassthroughRule)
	uc.ruleEngine.addRule(&usbHubForbidPassthroughRule{})

	uc.usbpassthroughs = newUsbpassthroughs()

	uc.connectUSBDeviceToQemu = uc.connectUSBDeviceToQemuImpl
	uc.disconnectUSBDeviceFromQemu = uc.disconnectUSBDeviceFromQemuImpl

	uc.iobt = newIOBundleTree()

	uc.Unlock()
}

func (uc *usbmanagerController) retrievePassthroughRule(assigngrp, phylabel string) passthroughRule {
	ioBundle := uc.iobt.ioBundle(phylabel)
	if ioBundle == nil {
		return nil
	}

	prCopy := uc.iobt.ioBundle2passthroughRule(*ioBundle)
	if prCopy == nil {
		return nil
	}

	return uc.ruleEngine.rules[prCopy.String()]
}

func (uc *usbmanagerController) removeIOBundleRule(ioBundle *types.IoBundle) {
	oldIOBundle := uc.iobt.ioBundle(ioBundle.Phylabel)
	if oldIOBundle == nil {
		return
	}

	oldPr := uc.iobt.ioBundle2passthroughRule(*oldIOBundle)
	if oldPr != nil {
		uc.ruleEngine.delRule(oldPr)
	} else {
		log.Tracef("could not convert ioBundle %+v to passthrough rule; ignoring it", ioBundle)
	}

	affectedPrs := make([]passthroughRule, 0)

	for _, dependencyGroup := range uc.iobt.groupDependendents(ioBundle.AssignmentGroup) {
		ioBundleElem := uc.iobt.elementsByAssignmentGroup[dependencyGroup]
		if ioBundleElem == nil {
			continue
		}
		for _, ioBundle := range ioBundleElem.ioBundles() {
			pr := uc.iobt.ioBundle2passthroughRule(*ioBundle)
			if pr != nil {
				affectedPrs = append(affectedPrs, pr)
			}
		}
	}

	uc.iobt.removeIOBundle(oldIOBundle)

	for _, pr := range affectedPrs {
		uc.ruleEngine.delRule(pr)
	}

	for _, dependencyGroup := range uc.iobt.groupDependendents(ioBundle.AssignmentGroup) {
		ioBundleElem := uc.iobt.elementsByAssignmentGroup[dependencyGroup]
		if ioBundleElem == nil {
			continue
		}
		for _, ioBundle := range ioBundleElem.ioBundles() {
			pr := uc.iobt.ioBundle2passthroughRule(*ioBundle)
			vm := uc.usbpassthroughs.vmByIOBundlePhyLabel(ioBundle.Phylabel)
			if pr == nil || vm == nil {
				continue
			}
			pr.setVirtualMachine(vm)
			uc.ruleEngine.addRule(pr)
		}
	}

}

func (uc *usbmanagerController) addIOBundleRule(ioBundle *types.IoBundle) passthroughRule {
	oldPr := uc.iobt.ioBundle2passthroughRule(*ioBundle)
	if oldPr != nil {
		uc.ruleEngine.delRule(oldPr)
	} else {
		log.Tracef("could not convert ioBundle %+v to passthrough rule; ignoring it", ioBundle)
	}

	affectedPrs := make([]passthroughRule, 0)

	for _, dependencyGroup := range uc.iobt.groupDependendents(ioBundle.AssignmentGroup) {
		ioBundleElem := uc.iobt.elementsByAssignmentGroup[dependencyGroup]
		if ioBundleElem == nil {
			continue
		}
		for _, ioBundle := range ioBundleElem.ioBundles() {
			pr := uc.iobt.ioBundle2passthroughRule(*ioBundle)
			if pr != nil {
				affectedPrs = append(affectedPrs, pr)
			}
		}
	}

	oldIOBundle := uc.iobt.ioBundle(ioBundle.Phylabel)
	if oldIOBundle != nil {
		uc.iobt.removeIOBundle(oldIOBundle)
	}
	uc.iobt.addIOBundle(ioBundle)

	for _, pr := range affectedPrs {
		uc.ruleEngine.delRule(pr)
	}

	dependencyGroups := append(uc.iobt.groupDependendents(ioBundle.AssignmentGroup), ioBundle.AssignmentGroup)
	for _, dependencyGroup := range dependencyGroups {
		ioBundleElem := uc.iobt.elementsByAssignmentGroup[dependencyGroup]
		if ioBundleElem == nil {
			continue
		}
		for _, ioBundle := range ioBundleElem.ioBundles() {
			pr := uc.iobt.ioBundle2passthroughRule(*ioBundle)
			vm := uc.usbpassthroughs.vmByIOBundlePhyLabel(ioBundle.Phylabel)
			if pr == nil || vm == nil {
				continue
			}
			pr.setVirtualMachine(vm)
			uc.ruleEngine.addRule(pr)
		}
	}

	newPr := uc.iobt.ioBundle2passthroughRule(*ioBundle)
	if newPr != nil {
		vm := uc.usbpassthroughs.vmByIOBundlePhyLabel(ioBundle.Phylabel)
		newPr.setVirtualMachine(vm)
		uc.ruleEngine.addRule(newPr)
	}

	return newPr
}

// prevents trying to connect a usb device twice
func (uc *usbmanagerController) connectUSBDeviceToQemuIdempotent(up usbpassthrough) {
	oldUp := uc.usbpassthroughs.usbpassthroughsOfUsbdevice(*up.usbdevice)
	if oldUp != nil && oldUp.vm != nil && up.vm != nil {
		if oldUp.vm.String() != up.vm.String() {
			log.Warnf("trying to passthrough %+v while it is still connected to %+v to %+v", up.usbdevice, oldUp.vm, up.vm)
			return
		} else {
			log.Tracef("%+v is already passed through\n", up)
			return
		}
	}
	uc.usbpassthroughs.addUsbpassthrough(&up)
	uc.connectUSBDeviceToQemu(up)
}

// prevents trying to disconnect a usb device twice
func (uc *usbmanagerController) disconnectUSBDeviceFromQemuIdempotent(up usbpassthrough) {
	oldUp := uc.usbpassthroughs.usbpassthroughsOfUsbdevice(*up.usbdevice)
	if oldUp == nil || oldUp.vm == nil {
		return
	}
	if up.vm != nil && oldUp.vm.String() != up.vm.String() {
		log.Warnf("trying to disconnect usb device %+v from %+v, but according to usbmanager it is connected to %+v", up.usbdevice, up.vm, oldUp.vm)
		return
	}
	uc.usbpassthroughs.delUsbpassthrough(&up)
	uc.disconnectUSBDeviceFromQemu(up)
}

func (uc *usbmanagerController) connectUSBDeviceToQemuImpl(up usbpassthrough) {
	if up.vm == nil {
		return
	}
	log.Tracef("connect usb passthrough %+v to %s\n", up, up.vm.qmpSocketPath)

	err := hypervisor.QmpExecDeviceAdd(up.vm.qmpSocketPath, up.usbdevice.qemuDeviceName(), up.usbdevice.busnum, up.usbdevice.devnum)
	if err != nil {
		log.Warnf("connect qmp failed: %+v\n", err)
	}
}

func (uc *usbmanagerController) disconnectUSBDeviceFromQemuImpl(up usbpassthrough) {
	if up.vm == nil {
		return
	}
	log.Tracef("disconnect usb passthrough %+v to %s\n", up, up.vm.qmpSocketPath)

	err := hypervisor.QmpExecDeviceDelete(up.vm.qmpSocketPath, up.usbdevice.qemuDeviceName())
	if err != nil {
		log.Warnf("disconnect qmp failed: %+v\n", err)
	}
}

func (uc *usbmanagerController) addUSBDevice(ud usbdevice) {
	uc.Lock()
	defer uc.Unlock()

	log.Noticef("add usb device usbaddr: %s usbproduct: %s pci: %s", ud.busnumAndPortnumString(),
		ud.vendorAndproductIDString(),
		ud.usbControllerPCIAddress)
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
	log.Noticef("remove usb device usbaddr: %s usbproduct: %s pci: %s", ud.busnumAndPortnumString(),
		ud.vendorAndproductIDString(),
		ud.usbControllerPCIAddress)

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
		ioBundle := uc.iobt.ioBundle(phyLabel)
		if ioBundle == nil {
			continue
		}

		siblingsIOBundlesElem := uc.iobt.elementsByAssignmentGroup[ioBundle.AssignmentGroup]
		if siblingsIOBundlesElem == nil {
			continue
		}

		for _, siblingIOBundle := range siblingsIOBundlesElem.ioBundles() {
			pr := uc.addIOBundleRule(siblingIOBundle)
			if pr == nil {
				continue
			}
			pr.setVirtualMachine(&vm)

		}

		pr := uc.addIOBundleRule(ioBundle)
		if pr == nil {
			continue
		}
		pr.setVirtualMachine(&vm)
	}
	uc.updateAllUSBDevicePassthroughs()
}

func (uc *usbmanagerController) removeVirtualmachine(vm virtualmachine) {
	uc.Lock()
	defer uc.Unlock()
	ups := uc.usbpassthroughs.usbpassthroughsOfVM(vm)

	storedVM := uc.usbpassthroughs.vms[vm.qmpSocketPath]
	if storedVM != nil {
		vm = *storedVM
	}

	for _, up := range ups {
		uc.disconnectUSBDeviceFromQemuIdempotent(*up)
	}
	for _, phyLabel := range vm.adapters {
		ioBundle := uc.iobt.ioBundle(phyLabel)
		if ioBundle == nil {
			continue
		}

		siblingIOBundlesElem := uc.iobt.elementsByAssignmentGroup[ioBundle.AssignmentGroup]
		if siblingIOBundlesElem == nil {
			continue
		}

		for _, siblingIOBundle := range siblingIOBundlesElem.ioBundles() {
			pr := uc.addIOBundleRule(siblingIOBundle)
			if pr == nil {
				continue
			}
			pr.setVirtualMachine(nil)
		}

		pr := uc.retrievePassthroughRule(ioBundle.AssignmentGroup, ioBundle.Phylabel)
		if pr != nil {
			pr.setVirtualMachine(nil)
		}
	}

	uc.usbpassthroughs.delVM(&vm)
	uc.updateAllUSBDevicePassthroughs()
}

func (uc *usbmanagerController) removeIOBundle(ioBundle types.IoBundle) {
	uc.Lock()
	defer uc.Unlock()

	uc.removeIOBundleRule(&ioBundle)

	uc.updateAllUSBDevicePassthroughs()
}

func (uc *usbmanagerController) addIOBundle(ioBundle types.IoBundle) {
	uc.Lock()
	defer uc.Unlock()
	pr := uc.addIOBundleRule(&ioBundle)
	vm := uc.usbpassthroughs.vmByIOBundlePhyLabel(ioBundle.Phylabel)
	if pr != nil {
		pr.setVirtualMachine(vm)
	}

	uc.updateAllUSBDevicePassthroughs()
}

func (uc *usbmanagerController) updateAllUSBDevicePassthroughs() {
	usbpassthroughsAndUsbdevices := uc.usbpassthroughs.usbpassthroughsAndUsbdevices()
	uc.updateUSBDevicePassthroughs(usbpassthroughsAndUsbdevices)
}

func (uc *usbmanagerController) updateUSBDevicePassthroughs(usbpassthroughsAndUsbdevices []*usbpassthrough) {
	for _, up := range usbpassthroughsAndUsbdevices {
		ud := up.usbdevice
		vm := up.vm

		newVM := uc.ruleEngine.apply(*ud)

		if newVM == vm {
			continue
		}

		if vm != nil && newVM != nil {
			log.Warnf("Disconnecting usb device %v from %s to connect it to %s", ud, vm, newVM)
		}

		if vm != nil {
			uc.disconnectUSBDeviceFromQemuIdempotent(usbpassthrough{
				usbdevice: ud,
				vm:        vm,
			})
		}

		if newVM != nil {
			uc.connectUSBDeviceToQemuIdempotent(usbpassthrough{
				usbdevice: ud,
				vm:        newVM,
			})
		}
	}
}

func (uc *usbmanagerController) cancel() {
	uc.listenUSBStopChan <- struct{}{}
}
