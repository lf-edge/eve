// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

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

func TestAddNonRuleIOBundle(t *testing.T) {
	uc := newTestUsbmanagerController()
	ioBundle := types.IoBundle{
		Type:         0,
		Phylabel:     "Test",
		Logicallabel: "Test",
	}
	uc.addIOBundle(ioBundle)
	uc.removeIOBundle(ioBundle)

	vm := virtualmachine{
		qmpSocketPath: "",
		adapters:      []string{"Test"},
	}

	uc.addVirtualmachine(vm)
	uc.removeVirtualmachine(vm)
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
	if len(uc.usbpassthroughs.vms) != 1 || uc.usbpassthroughs.vmByIOBundlePhyLabel(ioBundleLabel) == nil {
		t.Fatalf("invalid amount of vms registered")
	}
	uc.removeVirtualmachine(vm)
	for _, up := range uc.usbpassthroughs.usbpassthroughs {
		if up.vm != nil {
			t.Fatalf("usbpassthroughs registered where there shouldn't: %+v", up)
		}
	}
	if len(uc.usbpassthroughs.vms) != 0 || uc.usbpassthroughs.vmByIOBundlePhyLabel(ioBundleLabel) != nil {
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
		t.Logf("connecting %v", up)
		countCurrentUSBPassthroughs.Add(1)
	}
	uc.disconnectUSBDeviceFromQemu = func(up usbpassthrough) {
		t.Logf("disconnecting %v", up)
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

func TestAddIOBundleWithHigherPriority(t *testing.T) {
	// add iobundle with higher priority, therefore usb device has to be removed from first vm
	ioBundleLowPrio := types.IoBundle{
		Phylabel: "lowprio",
		UsbAddr:  "1:1",
	}

	ioBundleHighPrio := types.IoBundle{
		Phylabel:   "highprio",
		UsbAddr:    "1:1",
		UsbProduct: "9:9",
	}

	vmLowPrio := virtualmachine{
		qmpSocketPath: "/lowprio.socket",
		adapters:      []string{"lowprio"},
	}

	vmHighPrio := virtualmachine{
		qmpSocketPath: "/highprio.socket",
		adapters:      []string{"highprio"},
	}

	uc := newTestUsbmanagerController()
	uc.addIOBundle(ioBundleLowPrio)
	uc.addVirtualmachine(vmLowPrio)
	uc.addVirtualmachine(vmHighPrio)

	countConnect := 0
	countDisconnect := 0
	expectedConnectQmpSocketPath := []string{
		vmLowPrio.qmpSocketPath,
		vmHighPrio.qmpSocketPath,
		vmLowPrio.qmpSocketPath,
	}
	uc.connectUSBDeviceToQemu = func(up usbpassthrough) {
		if up.vm.qmpSocketPath != expectedConnectQmpSocketPath[countConnect] {
			t.Fatalf("usb device connected to wrong vm; expected %s, got %s", expectedConnectQmpSocketPath[countConnect], up.vm.qmpSocketPath)
		}
		countConnect++
	}
	uc.disconnectUSBDeviceFromQemu = func(up usbpassthrough) {
		if up.vm.qmpSocketPath != expectedConnectQmpSocketPath[countConnect-1] {
			t.Fatalf("usb device disconnected from wrong vm; expected %s, got %s", expectedConnectQmpSocketPath[countConnect-1], up.vm.qmpSocketPath)
		}
		countDisconnect++
	}

	ud := usbdevice{
		busnum:     1,
		portnum:    "1",
		devnum:     0,
		vendorID:   9,
		productID:  9,
		devicetype: "",
	}

	uc.addUSBDevice(ud)
	if countConnect != 1 || countDisconnect != 0 {
		t.Fatal("wrong amount of connects/disconnects")
	}

	uc.addIOBundle(ioBundleHighPrio)
	if countConnect != 2 || countDisconnect != 1 {
		t.Fatal("wrong amount of connects/disconnects")
	}

	uc.removeIOBundle(ioBundleLowPrio)
	if countConnect != 2 || countDisconnect != 1 {
		t.Fatal("wrong amount of connects/disconnects")
	}
	uc.addIOBundle(ioBundleLowPrio)
	if countConnect != 2 || countDisconnect != 1 {
		t.Fatal("wrong amount of connects/disconnects")
	}

	uc.removeIOBundle(ioBundleHighPrio)
	if countConnect != 3 || countDisconnect != 2 {
		t.Fatalf("wrong amount of connects/disconnects (%d/%d)", countConnect, countDisconnect)
	}
}

func TestParentassigngrp(t *testing.T) {
	ioBundlePCI := types.IoBundle{
		Phylabel:        "usbcontroller",
		AssignmentGroup: "USB Controller",
		PciLong:         "00:0d.0",
	}
	ioBundleUSB := types.IoBundle{
		Phylabel:              "usbmouse",
		AssignmentGroup:       "USB Mouse",
		ParentAssignmentGroup: "USB Controller",
		UsbAddr:               "1:1",
	}

	vmLowPrio := virtualmachine{
		qmpSocketPath: "/lowprio.socket",
		adapters:      []string{"usbmouse"},
	}

	vmHighPrio := virtualmachine{
		qmpSocketPath: "/highprio.socket",
		adapters:      []string{"usbcontroller"},
	}

	uc := newTestUsbmanagerController()
	var connectedVM string
	uc.connectUSBDeviceToQemu = func(up usbpassthrough) {
		connectedVM = up.vm.qmpSocketPath
	}
	uc.disconnectUSBDeviceFromQemu = func(up usbpassthrough) {
		connectedVM = ""
	}

	ud := usbdevice{
		busnum:                  1,
		portnum:                 "1",
		devnum:                  0,
		vendorID:                9,
		productID:               9,
		devicetype:              "",
		usbControllerPCIAddress: ioBundlePCI.PciLong,
		ueventFilePath:          "",
	}

	uc.addUSBDevice(ud)
	uc.addIOBundle(ioBundlePCI)

	uc.addIOBundle(ioBundleUSB)
	uc.addVirtualmachine(vmLowPrio)

	// Expecting usbmouse is now connected to lowprio VM
	if connectedVM != vmLowPrio.qmpSocketPath {
		t.Fatal("device is not connected to VM")
	}

	// Expecting usbcontroller (with usbmouse) is now connected to highprio VM
	uc.addVirtualmachine(vmHighPrio)
	if connectedVM != "" {
		t.Fatalf("device is connected to VM %s", connectedVM)
	}

	uc.removeVirtualmachine(vmHighPrio)

	// Expecting usbmouse is now connected to lowprio VM again
	if connectedVM != vmLowPrio.qmpSocketPath {
		t.Fatal("device is not connected to VM")
	}
}

func TestAddIOBundleWithSeveralPCIControllers(t *testing.T) {
	ioBundles := []types.IoBundle{
		{
			Phylabel:              "3",
			AssignmentGroup:       "3",
			ParentAssignmentGroup: "2",
			UsbAddr:               "2:2",
		},
		{
			Phylabel:              "2",
			AssignmentGroup:       "2",
			ParentAssignmentGroup: "1",
			UsbAddr:               "1:1",
		},
		{
			Phylabel:              "1 - controller A",
			AssignmentGroup:       "1",
			ParentAssignmentGroup: "",
			PciLong:               "00:14",
		},
		{
			Phylabel:              "1 - controller B",
			AssignmentGroup:       "1",
			ParentAssignmentGroup: "",
			PciLong:               "00:16",
		},
		{
			Phylabel:              "0 - controller C",
			AssignmentGroup:       "0",
			ParentAssignmentGroup: "",
			PciLong:               "00:18",
		},
	}

	uc := newTestUsbmanagerController()
	uc.ruleEngine.rules = make(map[string]passthroughRule)
	uc.connectUSBDeviceToQemu = func(up usbpassthrough) {
		t.Fatal("should not passthrough any usb device")
	}
	uc.disconnectUSBDeviceFromQemu = func(up usbpassthrough) {}

	for _, ioBundle := range ioBundles {
		uc.addIOBundle(ioBundle)
	}

	vmWithControllerA := virtualmachine{
		qmpSocketPath: "/vm",
		adapters:      []string{"1 - controller A"},
	}

	uc.addVirtualmachine(vmWithControllerA)

	ud := usbdevice{
		busnum:                  1,
		portnum:                 "1",
		devnum:                  1,
		vendorID:                11,
		productID:               12,
		usbControllerPCIAddress: "00:16",
	}

	uc.addUSBDevice(ud)

	vmWithUSB1 := virtualmachine{
		qmpSocketPath: "/vmUSB",
		adapters:      []string{"2"},
	}
	uc.addVirtualmachine(vmWithUSB1)

	usbDeviceConnected := false
	uc.connectUSBDeviceToQemu = func(up usbpassthrough) {
		usbDeviceConnected = true
	}
	uc.removeVirtualmachine(vmWithControllerA)

	if !usbDeviceConnected {
		t.Fatal("usb device should have been connected, but didn't")
	}

}

func TestSetForbidRuleActive(t *testing.T) {
	bundle := types.IoBundle{PciLong: "00:14.0", Phylabel: "pci", Logicallabel: "pci"}
	vm := virtualmachine{
		qmpSocketPath: "/asdf",
		adapters:      []string{"pci"},
	}

	uc := newTestUsbmanagerController()

	uc.addVirtualmachine(vm)
	uc.addIOBundle(bundle)

	uc.removeVirtualmachine(virtualmachine{
		qmpSocketPath: "/asdf",
		adapters:      []string{"pci"},
	})

	for _, rule := range uc.ruleEngine.rules {
		if rule.virtualMachine() != nil {
			t.Fatal("rule shall not have any vm")
		}
	}
}

func FuzzUSBManagerController(f *testing.F) {
	f.Fuzz(func(t *testing.T,
		phyLabel1 string,
		pciLong1 string,
		usbaddr1 string,
		usbproduct1 string,
		assigngrp1 string,

		phyLabel2 string,
		pciLong2 string,
		usbaddr2 string,
		usbproduct2 string,
		assigngrp2 string,

		phyLabel3 string,
		pciLong3 string,
		usbaddr3 string,
		usbproduct3 string,
		assigngrp3 string,

		phyLabel4 string,
		pciLong4 string,
		usbaddr4 string,
		usbproduct4 string,
		assigngrp4 string,

		phyLabel5 string,
		pciLong5 string,
		usbaddr5 string,
		usbproduct5 string,
		assigngrp5 string,

		delBundle1 uint,
		delBundle1Pos uint,

		delBundle2 uint,
		delBundle2Pos uint,

		delBundle3 uint,
		delBundle3Pos uint,

		addVm1Name string,
		addVm1Adapter1 uint,
		addVm1Adapter2 uint,
		addVm1Adapter3 uint,
		addVm1Pos uint,

		addVm2Name string,
		addVm2Adapter1 uint,
		addVm2Adapter2 uint,
		addVm2Adapter3 uint,
		addVm2Pos uint,

		delVm1Pos uint,
		delVm2Pos uint,

		addUSB1Dev uint,
		addUSB1Pos uint,

		addUSB2Dev uint,
		addUSB2Pos uint,

	) {

		ioBundle1 := types.IoBundle{
			Phylabel:        phyLabel1,
			AssignmentGroup: assigngrp1,
			PciLong:         pciLong1,
			UsbAddr:         usbaddr1,
			UsbProduct:      usbproduct1,
		}

		ioBundle2 := types.IoBundle{
			Phylabel:        phyLabel2,
			AssignmentGroup: assigngrp2,
			PciLong:         pciLong2,
			UsbAddr:         usbaddr2,
			UsbProduct:      usbproduct2,
		}

		ioBundle3 := types.IoBundle{
			Phylabel:        phyLabel3,
			AssignmentGroup: assigngrp3,
			PciLong:         pciLong3,
			UsbAddr:         usbaddr3,
			UsbProduct:      usbproduct3,
		}

		ioBundle4 := types.IoBundle{
			Phylabel:        phyLabel4,
			AssignmentGroup: assigngrp4,
			PciLong:         pciLong4,
			UsbAddr:         usbaddr4,
			UsbProduct:      usbproduct4,
		}

		ioBundle5 := types.IoBundle{
			Phylabel:        phyLabel5,
			AssignmentGroup: assigngrp5,
			PciLong:         pciLong5,
			UsbAddr:         usbaddr5,
			UsbProduct:      usbproduct5,
		}

		ioBundlesArray := []*types.IoBundle{&ioBundle1, &ioBundle2, &ioBundle3, &ioBundle4, &ioBundle5}
		ioBundlesArrayLen := uint(len(ioBundlesArray))

		for i := range ioBundlesArray {
			_, size := utf8.DecodeLastRuneInString(ioBundlesArray[i].AssignmentGroup)
			// set the parentassigngrp to the assigngrp without the last character
			// this way it is guaranteed that ioBundles with the same assigngrp
			// have the same parentassigngrp
			parentassigngrp := ioBundlesArray[i].AssignmentGroup[:len(ioBundlesArray[i].AssignmentGroup)-size]

			ioBundlesArray[i].ParentAssignmentGroup = parentassigngrp
		}

		addUSBCmd := []struct {
			ud  usbdevice
			pos uint
		}{
			{
				ud:  createTestUSBDeviceFromIOBundle(ioBundlesArray[addUSB1Dev%ioBundlesArrayLen]),
				pos: addUSB1Pos % ioBundlesArrayLen,
			},
			{
				ud:  createTestUSBDeviceFromIOBundle(ioBundlesArray[addUSB2Dev%ioBundlesArrayLen]),
				pos: addUSB2Pos % ioBundlesArrayLen,
			},
		}

		addVMCmd := []struct {
			vm  virtualmachine
			pos uint
		}{
			{
				vm:  createTestVM(addVm1Name, ioBundlesArray, addVm1Adapter1, addVm1Adapter2, addVm1Adapter3),
				pos: addVm1Pos % ioBundlesArrayLen,
			},
			{
				vm:  createTestVM(addVm2Name, ioBundlesArray, addVm2Adapter1, addVm2Adapter2, addVm2Adapter3),
				pos: addVm2Pos % ioBundlesArrayLen,
			},
		}
		if addVm1Name == addVm2Name {
			t.Log("vm1 and vm2 have the same name")
		}

		delBundleCmd := []struct {
			index uint
			pos   uint
		}{
			{delBundle1, delBundle1Pos % ioBundlesArrayLen},
			{delBundle2, delBundle2Pos % ioBundlesArrayLen},
			{delBundle3, delBundle3Pos % ioBundlesArrayLen},
		}

		for i := range delBundleCmd {
			delBundleCmd[i].index = delBundleCmd[i].index % ioBundlesArrayLen
			delBundleCmd[i].pos = delBundleCmd[i].pos % ioBundlesArrayLen
		}

		umc := usbmanagerController{}
		umc.init()
		umc.connectUSBDeviceToQemu = func(up usbpassthrough) {
			t.Logf("connect usbdevice: %+v", up)
		}
		umc.disconnectUSBDeviceFromQemu = func(up usbpassthrough) {
			t.Logf("disconnect usbdevice: %+v", up)
		}
		for pos, ioBundle := range ioBundlesArray {
			for _, dbc := range delBundleCmd {
				if dbc.pos == uint(pos) {
					removeIOBundle := ioBundlesArray[dbc.index]
					if removeIOBundle != nil {
						t.Logf("removing ioBundle label %s usbaddr: %s usbproduct: %s pcilong: %s",
							ioBundle.Phylabel, removeIOBundle.UsbAddr, removeIOBundle.UsbProduct, removeIOBundle.PciLong)
						umc.removeIOBundle(*removeIOBundle)
					}
				}
			}

			for _, avc := range addVMCmd {
				if avc.pos == uint(pos) {
					t.Logf("adding virtualmachine with adapters %+v", avc.vm.adapters)
					umc.addVirtualmachine(avc.vm)
				}
			}

			for _, udc := range addUSBCmd {
				if int(udc.pos) == pos {
					t.Logf("adding device %+v", udc.ud)
					umc.addUSBDevice(udc.ud)
				}
			}

			if delVm1Pos == uint(pos) {
				t.Logf("removing virtualmachine with adapters %+v", addVMCmd[0].vm.adapters)
				umc.removeVirtualmachine(addVMCmd[0].vm)
			}
			if delVm2Pos == uint(pos) {
				t.Logf("removing virtualmachine with adapters %+v", addVMCmd[1].vm.adapters)
				umc.removeVirtualmachine(addVMCmd[1].vm)
			}

			t.Logf("adding ioBundle label %s usbaddr: %s usbproduct: %s pcilong: %s",
				ioBundle.Phylabel, ioBundle.UsbAddr, ioBundle.UsbProduct, ioBundle.PciLong)
			umc.addIOBundle(*ioBundle)
		}
	})
}

func createTestUSBDeviceFromIOBundle(ioBundle *types.IoBundle) usbdevice {
	var ud usbdevice

	ud.usbControllerPCIAddress = ioBundle.PciLong
	usbParts := strings.SplitN(ioBundle.UsbAddr, ":", 2)

	busnum, _ := strconv.ParseUint(usbParts[0], 10, 16)

	ud.busnum = uint16(busnum)
	if len(usbParts) == 2 {
		ud.portnum = usbParts[1]
	}

	usbParts = strings.SplitN(ioBundle.UsbProduct, ":", 2)

	vendorID, _ := strconv.ParseUint(usbParts[0], 16, 32)
	ud.vendorID = uint32(vendorID)

	if len(usbParts) == 2 {
		productID, _ := strconv.ParseUint(usbParts[1], 16, 32)
		ud.productID = uint32(productID)
	}

	return ud
}

func createTestVM(vmName string, ioBundlesArray []*types.IoBundle, vmAdapter1 uint, vmAdapter2 uint, vmAdapter3 uint) virtualmachine {
	vm := virtualmachine{
		qmpSocketPath: vmName,
		adapters:      []string{},
	}
	for _, adapterIndex := range []int{int(vmAdapter1), int(vmAdapter2), int(vmAdapter3)} {
		pos := adapterIndex % len(ioBundlesArray)

		if adapterIndex > 0 {
			vm.addAdapter(ioBundlesArray[pos].Phylabel)
		}
	}

	return vm
}
