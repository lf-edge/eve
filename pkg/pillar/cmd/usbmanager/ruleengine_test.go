// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"testing"
)

func TestOverwriteRule(t *testing.T) {
	re := newRuleEngine()

	pci1 := pciPassthroughRule{pciAddress: "00:02.0"}
	re.addRule(&pci1)

	pci2 := pciPassthroughRule{pciAddress: "00:02.0"}
	re.addRule(&pci2)

	if len(re.rules) != 1 {
		t.Fatalf("rule overwriting failed")
	}
}

func TestBlockedByPCIPassthrough(t *testing.T) {
	re := newRuleEngine()

	pci := pciPassthroughRule{pciAddress: "00:02.0"}
	re.addRule(&pci)

	ud := usbdevice{
		usbControllerPCIAddress: pci.pciAddress, // conflicts with pci rule
		busnum:                  01,
		devnum:                  02,
		portnum:                 "2",
	}
	vm := virtualmachine{}
	usb := usbPortPassthroughRule{ud: ud}
	usb.vm = &vm

	re.addRule(&usb)

	connectVM := re.apply(ud)

	if connectVM != nil {
		t.Fatalf("usb passthrough should be blocked by pci passthrough, but got connected vm")
	}
}

func TestPortOverDevPrecedence(t *testing.T) {
	re := newRuleEngine()

	ud := usbdevice{
		usbControllerPCIAddress: "00:02.0",
		busnum:                  01,
		devnum:                  3,
		portnum:                 "3.1",
		vendorID:                5,
		productID:               6,
	}

	usbPortRule := usbPortPassthroughRule{ud: ud}
	usbPortRule.vm = &virtualmachine{}

	usbDevRule := usbDevicePassthroughRule{ud: ud}

	re.addRule(&usbPortRule)
	re.addRule(&usbDevRule)

	connectVM := re.apply(ud)

	if connectVM == nil {
		t.Fatalf("usb passthrough should work, but got no connected vm")
	}
}

func TestUSBWithoutPCICard(t *testing.T) {
	re := newRuleEngine()

	ud := usbdevice{
		busnum:    01,
		devnum:    2,
		portnum:   "2",
		vendorID:  5,
		productID: 6,
	}

	usbPortRule := usbPortPassthroughRule{ud: ud}
	usbPortRule.vm = &virtualmachine{}

	re.addRule(&usbPortRule)

	connectVM := re.apply(ud)

	if connectVM == nil {
		t.Fatalf("pci-less usb passthrough fails")
	}

}

func TestPluginWrongPCICard(t *testing.T) {
	re := newRuleEngine()

	ud := usbdevice{
		usbControllerPCIAddress: "00:02.0",
		busnum:                  01,
		portnum:                 "2",
		devnum:                  2,
		vendorID:                5,
		productID:               6,
	}

	usbRule := usbPortPassthroughRule{
		ud: usbdevice{
			busnum:                  01,
			devnum:                  02,
			usbControllerPCIAddress: "00:03.0",
		},
	}
	usbRule.vm = &virtualmachine{qmpSocketPath: "/vm/with/usb/passthrough"}
	re.addRule(&usbRule)

	vm := re.apply(ud)
	if vm != nil {
		t.Fatal("ud should not be passed as parent pci addresses are different")
	}

	t.Log(re.String())
}

func TestEmptyParentPCIAddress(t *testing.T) {
	re := newRuleEngine()

	ud1 := usbdevice{
		usbControllerPCIAddress: "00:02.0",
		busnum:                  01,
		devnum:                  02,
		portnum:                 "2",
		vendorID:                5,
		productID:               6,
	}
	ud2 := usbdevice{
		usbControllerPCIAddress: "00:03.0",
		busnum:                  02,
		devnum:                  02,
		portnum:                 "3",
		vendorID:                5,
		productID:               6,
	}

	pciRule := pciPassthroughRule{
		pciAddress: "00:02.0",
	}
	pciRule.vm = &virtualmachine{qmpSocketPath: "/vm/with/pci/passthrough"}
	re.addRule(&pciRule)

	usbRule := usbPortPassthroughRule{
		ud: usbdevice{
			busnum:                  02,
			devnum:                  02,
			portnum:                 "3",
			usbControllerPCIAddress: "",
		},
	}
	usbRule.vm = &virtualmachine{qmpSocketPath: "/vm/with/usb/passthrough"}
	re.addRule(&usbRule)

	ud1VM := re.apply(ud1)
	if ud1VM != nil {
		t.Fatal("ud1 should not be passed as underlying PCI device is passed through")
	}

	ud2VM := re.apply(ud2)
	if ud2VM == nil {
		t.Fatal("ud2 should be passed through")
	}

	t.Log(re.String())
}

func FuzzRuleEngine(f *testing.F) {

	f.Fuzz(func(t *testing.T,
		// usb device passthrough rule
		parentPCIAddressRule1 string,
		busnumRule1 uint16,
		devnumRule1 uint16,
		vendorIdRule1 uint32,
		productIdRule1 uint32,
		// usb plug passthrough rule
		parentPCIAddressRule2 string,
		busnumRule2 uint16,
		devnumRule2 uint16,
		vendorIdRule2 uint32,
		productIdRule2 uint32,
		// pci passthrough rule
		parentPCIAddressRule3 string,
		// actual usb device
		parentPCIAddress string,
		busnum uint16,
		devnum uint16,
		vendorId uint32,
		productId uint32,
	) {
		re := newRuleEngine()
		udRule1 := usbdevice{
			busnum:                  busnumRule1,
			devnum:                  devnumRule1,
			vendorID:                vendorIdRule1,
			productID:               productIdRule1,
			usbControllerPCIAddress: parentPCIAddressRule1,
		}
		rule1 := usbDevicePassthroughRule{ud: udRule1}
		rule1.vm = &virtualmachine{
			qmpSocketPath: "/vm1",
		}

		udRule2 := usbdevice{
			busnum:                  busnumRule2,
			devnum:                  devnumRule2,
			vendorID:                vendorIdRule2,
			productID:               productIdRule2,
			usbControllerPCIAddress: parentPCIAddressRule2,
		}
		rule2 := usbPortPassthroughRule{ud: udRule2}
		rule2.vm = &virtualmachine{
			qmpSocketPath: "/vm2",
		}

		rule3 := pciPassthroughRule{
			pciAddress: parentPCIAddressRule3,
		}

		ud := usbdevice{
			busnum:                  busnum,
			devnum:                  devnum,
			vendorID:                vendorId,
			productID:               productId,
			usbControllerPCIAddress: parentPCIAddress,
		}
		re.addRule(&rule1)
		re.addRule(&rule2)
		re.addRule(&rule3)

		connectVM := re.apply(ud)
		if connectVM == nil {
			return
		}
		if rule3.pciAddress == ud.usbControllerPCIAddress {
			t.Fatal("passthrough should not work as it is blocked by pci passthrough")
		}
		// check that if udRule1 and udRule2 apply, we get the one with the higher priority, i.e. udRule2
		// which means, as long as udRule2 applies, we should get udRule2.vm
		reUdRule2 := newRuleEngine()
		reUdRule2.addRule(&rule2)
		connectVMUdRule := reUdRule2.apply(ud)
		if connectVMUdRule != nil {
			if connectVMUdRule.qmpSocketPath != "/vm2" {
				t.Fatal("usb plug rule applies, but rule with higher precedence has been found")
			}
		}

	})
}
