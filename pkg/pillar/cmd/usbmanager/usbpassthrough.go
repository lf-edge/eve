// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"strings"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// the holy trinity
type usbpassthrough struct {
	usbdevice *usbdevice
	vm        *virtualmachine
}

func (up usbpassthrough) String() string {
	return strings.Join([]string{
		up.usbdevice.String(),
		up.vm.qmpSocketPath,
	}, "||")
}

type usbpassthroughs struct {
	ioBundles             map[string]*types.IoBundle // PhyLabel is key
	usbdevices            map[string]*usbdevice      // by ueventFilePath
	vms                   map[string]*virtualmachine // by qmp path
	vmsByIoBundlePhyLabel map[string]*virtualmachine

	usbpassthroughs     map[string]*usbpassthrough
	usbpassthroughsByVM map[string]map[string]*usbpassthrough
}

func newUsbpassthroughs() usbpassthroughs {
	var up usbpassthroughs

	up.ioBundles = make(map[string]*types.IoBundle)
	up.usbdevices = make(map[string]*usbdevice)
	up.vms = make(map[string]*virtualmachine)
	up.vmsByIoBundlePhyLabel = make(map[string]*virtualmachine)

	up.usbpassthroughs = make(map[string]*usbpassthrough)
	up.usbpassthroughsByVM = make(map[string]map[string]*usbpassthrough)

	return up
}

func (ups *usbpassthroughs) delIoBundle(ioBundle *types.IoBundle) {
	delete(ups.ioBundles, ioBundle.Phylabel)
}

func (ups *usbpassthroughs) addIoBundle(ioBundle *types.IoBundle) {
	ups.ioBundles[ioBundle.Phylabel] = ioBundle
}

func (ups *usbpassthroughs) listUsbdevices() []*usbdevice {
	usbdevices := make([]*usbdevice, 0)

	for _, ud := range ups.usbdevices {
		usbdevices = append(usbdevices, ud)
	}

	return usbdevices
}

func (ups *usbpassthroughs) addUsbdevice(ud *usbdevice) {
	ups.usbdevices[ud.ueventFilePath] = ud
}

func (ups *usbpassthroughs) delUsbdevice(ud *usbdevice) {
	delete(ups.usbdevices, ud.ueventFilePath)
}

func (ups *usbpassthroughs) addVM(vm *virtualmachine) {
	ups.vms[vm.qmpSocketPath] = vm
	for _, phyLabel := range vm.adapters {
		ups.vmsByIoBundlePhyLabel[phyLabel] = vm
	}
}

func (ups *usbpassthroughs) delVM(vm *virtualmachine) {
	vmDel := ups.vms[vm.qmpSocketPath]
	if vmDel != nil && vmDel.adapters != nil {
		for _, phyLabel := range vmDel.adapters {
			delete(ups.vmsByIoBundlePhyLabel, phyLabel)
		}
	}
	delete(ups.vms, vm.qmpSocketPath)
}

func (ups usbpassthroughs) hasUsbpassthrough(up usbpassthrough) bool {
	_, ok := ups.usbpassthroughs[up.String()]
	return ok
}

func (ups *usbpassthroughs) addUsbpassthrough(up *usbpassthrough) {
	ups.usbpassthroughs[up.String()] = up
	if ups.usbpassthroughsByVM[up.vm.qmpSocketPath] == nil {
		ups.usbpassthroughsByVM[up.vm.qmpSocketPath] = make(map[string]*usbpassthrough)
	}
	ups.usbpassthroughsByVM[up.vm.qmpSocketPath][up.usbdevice.ueventFilePath] = up
}

func (ups *usbpassthroughs) delUsbpassthrough(up *usbpassthrough) {
	delete(ups.usbpassthroughs, up.String())
	delete(ups.usbpassthroughsByVM, up.vm.qmpSocketPath)

	ups.delVM(up.vm)
}

func (ups usbpassthroughs) usbpassthroughsOfVM(vm virtualmachine) map[string]*usbpassthrough {
	return ups.usbpassthroughsByVM[vm.qmpSocketPath]
}
