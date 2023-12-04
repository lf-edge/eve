// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

// the holy trinity
type usbpassthrough struct {
	usbdevice *usbdevice
	vm        *virtualmachine
}

func (up usbpassthrough) String() string {
	return up.usbdevice.String()
}

type usbpassthroughs struct {
	vms                      map[string]*virtualmachine // by qmp path
	vmsByIOBundlePhyLabelMap map[string]*virtualmachine // by phylabel, by qmp path

	usbpassthroughs     map[string]*usbpassthrough
	usbpassthroughsByVM map[string]map[string]*usbpassthrough
}

func (ups *usbpassthroughs) addVMByIOBundlePhyLabel(phylabel string, vm *virtualmachine) {
	ups.vmsByIOBundlePhyLabelMap[phylabel] = vm
}

func (ups *usbpassthroughs) vmByIOBundlePhyLabel(phylabel string) *virtualmachine {
	return ups.vmsByIOBundlePhyLabelMap[phylabel]
}

// this includes passthroughs and usbdevices without vm
func (ups *usbpassthroughs) usbpassthroughsAndUsbdevices() []*usbpassthrough {
	ret := make([]*usbpassthrough, 0)

	for _, up := range ups.usbpassthroughs {
		ret = append(ret, up)
	}

	return ret
}

func newUsbpassthroughs() usbpassthroughs {
	var up usbpassthroughs

	up.vms = make(map[string]*virtualmachine)
	up.vmsByIOBundlePhyLabelMap = make(map[string]*virtualmachine)

	up.usbpassthroughs = make(map[string]*usbpassthrough)
	up.usbpassthroughsByVM = make(map[string]map[string]*usbpassthrough)

	return up
}

func (ups *usbpassthroughs) addUsbdevice(ud *usbdevice) {
	if ups.hasUsbpassthrough(*ud) {
		return
	}
	ups.usbpassthroughs[ud.String()] = &usbpassthrough{
		usbdevice: ud,
		vm:        nil,
	}
}

func (ups *usbpassthroughs) delUsbdevice(ud *usbdevice) {
	delete(ups.usbpassthroughs, ud.String())
}

func (ups *usbpassthroughs) addVM(vm *virtualmachine) {
	ups.vms[vm.qmpSocketPath] = vm
	for _, phyLabel := range vm.adapters {
		ups.addVMByIOBundlePhyLabel(phyLabel, vm)
	}
}

func (ups *usbpassthroughs) delVM(vm *virtualmachine) {
	vmDel := ups.vms[vm.qmpSocketPath]
	if vmDel != nil && vmDel.adapters != nil {
		for _, phyLabel := range vmDel.adapters {
			delete(ups.vmsByIOBundlePhyLabelMap, phyLabel)
		}
	}
	delete(ups.vms, vm.qmpSocketPath)
}

func (ups usbpassthroughs) hasUsbpassthrough(ud usbdevice) bool {
	_, ok := ups.usbpassthroughs[ud.String()]
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
	if up.vm != nil {
		delete(ups.usbpassthroughsByVM, up.vm.qmpSocketPath)
	}
	ups.usbpassthroughs[up.String()].vm = nil
}

func (ups usbpassthroughs) usbpassthroughsOfUsbdevice(ud usbdevice) *usbpassthrough {
	return ups.usbpassthroughs[ud.String()]
}

func (ups usbpassthroughs) usbpassthroughsOfVM(vm virtualmachine) map[string]*usbpassthrough {
	return ups.usbpassthroughsByVM[vm.qmpSocketPath]
}
