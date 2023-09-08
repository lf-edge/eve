// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

type testingEvent int

const (
	ioBundleTestEvent testingEvent = iota
	usbTestEvent
	vmTestEvent
)

type testEventTableGenerator struct {
	testEventTable [][]testingEvent
}

func (testEvent testingEvent) String() string {
	if testEvent == ioBundleTestEvent {
		return "IOBundle Event"
	} else if testEvent == usbTestEvent {
		return "USB Event"
	} else if testEvent == vmTestEvent {
		return "VM Event"
	}

	return ""
}

func (tetg *testEventTableGenerator) generate(k int, testEvents []testingEvent) {
	// Heap's algorithm
	if k == 1 {
		testEventsCopy := make([]testingEvent, len(testEvents))
		copy(testEventsCopy, testEvents)

		tetg.testEventTable = append(tetg.testEventTable, testEventsCopy)
		return
	}

	tetg.generate(k-1, testEvents)

	for i := 0; i < k-1; i++ {
		var swapIndex int
		if k%2 == 0 {
			swapIndex = i
		} else {
			swapIndex = 0
		}
		t := testEvents[swapIndex]
		testEvents[swapIndex] = testEvents[k-1]
		testEvents[k-1] = t

		tetg.generate(k-1, testEvents)
	}
}

func testEventTable() [][]testingEvent {
	testEvents := []testingEvent{ioBundleTestEvent, usbTestEvent, vmTestEvent}

	var tetg testEventTableGenerator

	tetg.generate(len(testEvents), testEvents)

	return tetg.testEventTable
}

func TestRemovingVm(t *testing.T) {
	usbEventBusnum := uint16(1)
	usbEventDevnum := uint16(2)
	usbEventPortnum := "3.1"
	ioBundleUsbAddr := fmt.Sprintf("%d:%s", usbEventBusnum, usbEventPortnum)
	ioBundlePciLong := "00:02.0"
	ioBundleLabel := "TOUCH"
	vmAdapter := ioBundleLabel
	usbEventPCIAddress := ioBundlePciLong
	qmpSocketPath := "/vm/qemu.sock"

	ioBundle, ud, vm := newTestVirtualPassthroughEnv(ioBundleLabel, ioBundleUsbAddr, ioBundlePciLong,
		usbEventBusnum, usbEventDevnum, usbEventPortnum, usbEventPCIAddress,
		qmpSocketPath, vmAdapter)

	uc := newTestUsbmanagerController()
	uc.connectUSBDeviceToQemu = func(up usbpassthrough) {
		t.Logf("connecting usbpassthrough: %+v", up.String())
	}
	uc.disconnectUSBDeviceFromQemu = func(up usbpassthrough) {
		t.Logf("disconnecting usbpassthrough: %+v", up.String())
	}

	uc.addIOBundle(ioBundle)
	uc.addUSBDevice(ud)
	uc.addVirtualmachine(vm)
	if len(uc.usbpassthroughs.usbpassthroughs) != 1 {
		t.Fatalf("invalid amount of usbpassthroughs registered")
	}
	if len(uc.usbpassthroughs.vms) != 1 || len(uc.usbpassthroughs.vmsByIoBundlePhyLabel) != 1 {
		t.Fatalf("invalid amount of vms registered")
	}
	uc.removeVirtualmachine(vm)
	if len(uc.usbpassthroughs.usbpassthroughs) != 0 {
		t.Fatalf("invalid amount of usbpassthroughs registered")
	}
	if len(uc.usbpassthroughs.vms) != 0 || len(uc.usbpassthroughs.vmsByIoBundlePhyLabel) != 0 {
		t.Fatalf("invalid amount of vms registered")
	}
}

func TestNoConnectWrongPCIUSBDevicesToQemu(t *testing.T) {
	usbEventBusnum := uint16(1)
	usbEventDevnum := uint16(2)
	usbEventPortnum := "3.1"
	ioBundleUsbAddr := fmt.Sprintf("%d:%s", usbEventBusnum, usbEventPortnum)
	ioBundlePciLong := "00:02.0"
	ioBundleLabel := "TOUCH"
	vmAdapter := ioBundleLabel
	usbEventPCIAddress := ""
	qmpSocketPath := "/vm/qemu.sock"

	ioBundle, usbdevice, vm := newTestVirtualPassthroughEnv(ioBundleLabel, ioBundleUsbAddr, ioBundlePciLong,
		usbEventBusnum, usbEventDevnum, usbEventPortnum, usbEventPCIAddress,
		qmpSocketPath, vmAdapter)

	tet := testEventTable()
	countUSBConnections := testRunConnectingUsbDevicesOrderCombinations(tet, qmpSocketPath, ioBundle, usbdevice, vm)

	if countUSBConnections != 0 {
		t.Fatalf("expected 0 connection attempts to qemu, but got %d", countUSBConnections)
	}
}

func TestNoConnectUSBDevicesToQemu(t *testing.T) {
	usbEventBusnum := uint16(1)
	usbEventDevnum := uint16(2)
	usbEventPortnum := "3.1"
	ioBundleUsbAddr := fmt.Sprintf("%d:%s-1", usbEventBusnum, usbEventPortnum) // usb port different from usb device
	ioBundlePciLong := "00:02.0"
	ioBundleLabel := "TOUCH"
	vmAdapter := ioBundleLabel
	usbEventPCIAddress := ioBundlePciLong
	qmpSocketPath := "/vm/qemu.sock"

	ioBundle, usbdevice, vm := newTestVirtualPassthroughEnv(ioBundleLabel, ioBundleUsbAddr, ioBundlePciLong,
		usbEventBusnum, usbEventDevnum, usbEventPortnum, usbEventPCIAddress,
		qmpSocketPath, vmAdapter)

	tet := testEventTable()
	countUSBConnections := testRunConnectingUsbDevicesOrderCombinations(tet, qmpSocketPath, ioBundle, usbdevice, vm)

	if countUSBConnections != 0 {
		t.Fatalf("expected 0 connection attempts to qemu, but got %d", countUSBConnections)
	}
}

func TestReconnectUSBDevicesToQemu(t *testing.T) {
	usbEventBusnum := uint16(1)
	usbEventDevnum := uint16(2)
	usbEventPortnum := "3.1"
	ioBundleUsbAddr := fmt.Sprintf("%d:%s", usbEventBusnum, usbEventPortnum)
	ioBundlePciLong := "00:02.0"
	ioBundleLabel := "TOUCH"
	vmAdapter := ioBundleLabel
	usbEventPCIAddress := ioBundlePciLong
	qmpSocketPath := "/vm/qemu.sock"

	ioBundle, ud, vm := newTestVirtualPassthroughEnv(ioBundleLabel, ioBundleUsbAddr, ioBundlePciLong,
		usbEventBusnum, usbEventDevnum, usbEventPortnum, usbEventPCIAddress,
		qmpSocketPath, vmAdapter)

	uc := newTestUsbmanagerController()
	var countCurrentUSBPassthroughs atomic.Int32
	countCurrentUSBPassthroughs.Store(0)
	uc.connectUSBDeviceToQemu = func(up usbpassthrough) {
		countCurrentUSBPassthroughs.Add(1)
	}
	uc.disconnectUSBDeviceFromQemu = func(up usbpassthrough) {
		countCurrentUSBPassthroughs.Add(-1)
	}

	uc.addIOBundle(ioBundle)
	uc.addUSBDevice(ud)
	uc.addUSBDevice(ud)
	uc.addVirtualmachine(vm)
	uc.addUSBDevice(ud)
	if countCurrentUSBPassthroughs.Load() != 1 {
		t.Fatalf("expected current usb passthrough count to be 1, but got %d", countCurrentUSBPassthroughs.Load())
	}
	uc.removeUSBDevice(ud)
	uc.removeUSBDevice(ud)
	if countCurrentUSBPassthroughs.Load() != 0 {
		t.Fatalf("expected current usb passthrough count to be 0, but got %d", countCurrentUSBPassthroughs.Load())
	}

	uc.addUSBDevice(ud)
	if countCurrentUSBPassthroughs.Load() != 1 {
		t.Fatalf("expected current usb passthrough count to be 1, but got %d", countCurrentUSBPassthroughs.Load())
	}
	uc.addUSBDevice(ud)

	if countCurrentUSBPassthroughs.Load() != 1 {
		t.Fatalf("expected current usb passthrough count to be 1, but got %d", countCurrentUSBPassthroughs.Load())
	}
}

func TestConnectUSBDevicesToQemu(t *testing.T) {
	usbEventBusnum := uint16(1)
	usbEventDevnum := uint16(2)
	usbEventPortnum := "3.1"
	ioBundleUsbAddr := fmt.Sprintf("%d:%s", usbEventBusnum, usbEventPortnum)
	ioBundlePciLong := "00:02.0"
	ioBundleLabel := "TOUCH"
	vmAdapter := ioBundleLabel
	usbEventPCIAddress := ioBundlePciLong
	qmpSocketPath := "/vm/qemu.sock"

	ioBundle, usbdevice, vm := newTestVirtualPassthroughEnv(ioBundleLabel, ioBundleUsbAddr, ioBundlePciLong,
		usbEventBusnum, usbEventDevnum, usbEventPortnum, usbEventPCIAddress,
		qmpSocketPath, vmAdapter)

	tet := testEventTable()
	countUSBConnections := testRunConnectingUsbDevicesOrderCombinations(tet, qmpSocketPath, ioBundle, usbdevice, vm)

	if len(tet) != countUSBConnections {
		t.Fatalf("expected %d connection attempts to qemu, but got %d", len(tet), countUSBConnections)
	}
}

func testRunConnectingUsbDevicesOrderCombinations(tet [][]testingEvent, expectedQmpSocketPath string, ioBundle types.IoBundle, ud usbdevice, vm virtualmachine) int {
	countUSBConnections := 0
	for _, testEvents := range tet {
		uc := newTestUsbmanagerController()

		uc.connectUSBDeviceToQemu = func(up usbpassthrough) {
			if up.vm.qmpSocketPath != expectedQmpSocketPath {
				err := fmt.Errorf("vm connecting to should have qmp path %s, but has %s", expectedQmpSocketPath, up.vm.qmpSocketPath)
				panic(err)
			}
			countUSBConnections++
		}

		for _, testEvent := range testEvents {
			if testEvent == ioBundleTestEvent {
				uc.addIOBundle(ioBundle)
			} else if testEvent == usbTestEvent {
				uc.addUSBDevice(ud)
			} else if testEvent == vmTestEvent {
				uc.addVirtualmachine(vm)
			}
		}

	}
	return countUSBConnections
}

func newTestVirtualPassthroughEnv(ioBundleLabel, ioBundleUsbAddr, ioBundlePciLong string,
	usbEventBusnum, usbEventDevnum uint16, usbEventPortnum string, usbEventPCIAddress,
	qmpSocketPath, vmAdapter string) (types.IoBundle, usbdevice, virtualmachine) {

	ioBundle := types.IoBundle{Phylabel: ioBundleLabel, UsbAddr: ioBundleUsbAddr, PciLong: ioBundlePciLong}

	ud := usbdevice{
		busnum:                  usbEventBusnum,
		devnum:                  usbEventDevnum,
		portnum:                 usbEventPortnum,
		vendorID:                05,
		productID:               06,
		usbControllerPCIAddress: usbEventPCIAddress,
	}
	vm := virtualmachine{
		qmpSocketPath: qmpSocketPath,
		adapters:      []string{vmAdapter},
	}

	return ioBundle, ud, vm
}

func newTestUsbmanagerController() *usbmanagerController {
	uc := usbmanagerController{}
	uc.init()

	return &uc
}
