// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func isNeverPR(pr passthroughRule) bool {
	switch v := pr.(type) {
	case *neverPassthroughRule:
		return true
	case *compositionANDPassthroughRule:
		if len(v.rules) == 0 {
			panic("composition PR has to have at least one rule")
		}
		for _, childPr := range v.rules {
			if isNeverPR(childPr) {
				return true
			}
		}
	case *compositionORPassthroughRule:
		if len(v.rules) == 0 {
			panic("composition PR has to have at least one rule")
		}
		for _, childPr := range v.rules {
			if !isNeverPR(childPr) {
				return false
			}
		}
		return true

	}

	return false
}

func newUSBPortPassthroughRule(busnum uint16, portnum string, pciAddr string) compositionANDPassthroughRule {
	var ret compositionANDPassthroughRule

	usb := &usbPortPassthroughRule{
		busnum:  busnum,
		portnum: portnum,
	}

	ret.rules = []passthroughRule{usb}

	if pciAddr != "" {
		pci := &pciPassthroughRule{
			pciAddress: pciAddr,
		}
		ret.rules = append(ret.rules, pci)
	}

	return ret
}

func newUSBDevicePassthroughRule(vendorID, productID uint32, pciAddr string) compositionANDPassthroughRule {
	var ret compositionANDPassthroughRule

	usb := &usbDevicePassthroughRule{
		vendorID:  vendorID,
		productID: productID,
	}

	ret.rules = []passthroughRule{usb}

	if pciAddr != "" {
		pci := &pciPassthroughRule{
			pciAddress: pciAddr,
		}

		ret.rules = append(ret.rules, pci)
	}

	return ret
}

func TestOverwriteRule(t *testing.T) {
	re := newRuleEngine()

	pci1 := pciPassthroughForbidRule{pciAddress: "00:02.0"}
	re.addRule(&pci1)

	pci2 := pciPassthroughForbidRule{pciAddress: "00:02.0"}
	re.addRule(&pci2)

	if len(re.rules) != 1 {
		t.Fatalf("rule overwriting failed")
	}
}

func TestBlockedByPCIPassthrough(t *testing.T) {
	re := newRuleEngine()

	pci := pciPassthroughForbidRule{pciAddress: "00:02.0"}
	pci.vm = &virtualmachine{
		qmpSocketPath: "/somevm.socket",
	}
	re.addRule(&pci)

	ud := usbdevice{
		usbControllerPCIAddress: pci.pciAddress, // conflicts with pci rule
		busnum:                  01,
		devnum:                  02,
		portnum:                 "2",
	}
	vm := virtualmachine{}
	usb := newUSBPortPassthroughRule(ud.busnum, ud.portnum, pci.pciAddress)
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

	usbPortRule := newUSBPortPassthroughRule(ud.busnum, ud.portnum, ud.usbControllerPCIAddress)
	usbPortRule.vm = &virtualmachine{}

	usbDevRule := newUSBDevicePassthroughRule(ud.vendorID, ud.productID, ud.usbControllerPCIAddress)

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

	usbPortRule := newUSBPortPassthroughRule(ud.busnum, ud.portnum, ud.usbControllerPCIAddress)
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

	usbRule := newUSBPortPassthroughRule(01, "02", "00:03.0")
	usbRule.vm = &virtualmachine{qmpSocketPath: "/vm/with/usb/passthrough"}
	re.addRule(&usbRule)

	vm := re.apply(ud)
	if vm != nil {
		t.Fatal("ud should not be passed as parent pci addresses are different")
	}

}

func TestAddIOBundle(t *testing.T) {
	re := usbmanagerController{}
	re.init()

	re.ruleEngine.rules = make(map[string]passthroughRule)

	re.addIOBundleRule(&types.IoBundle{
		Phylabel:              "phy2",
		AssignmentGroup:       "2",
		ParentAssignmentGroup: "1",
		PciLong:               "0d:02",
	})

	for _, pr := range re.ruleEngine.rules {
		eval, _ := pr.evaluate(usbdevice{
			usbControllerPCIAddress: "0d:02",
		})
		if eval == passthroughDo {
			t.Fatal("rule should never do a passthrough")
		}
	}

	re.addIOBundleRule(&types.IoBundle{
		Phylabel:              "phy1",
		AssignmentGroup:       "1",
		ParentAssignmentGroup: "",
		PciLong:               "0d:01",
	})

	for _, pr := range re.ruleEngine.rules {
		eval, _ := pr.evaluate(usbdevice{
			usbControllerPCIAddress: "0d:01",
		})
		if pr.String() == "PCI Passthrough Rule 0d:01" && eval != passthroughDo {
			t.Fatal("rule should do a passthrough")
		}
	}

	re.addIOBundleRule(&types.IoBundle{
		Phylabel:              "phy3",
		AssignmentGroup:       "3",
		ParentAssignmentGroup: "2",
		PciLong:               "0d:03",
	})

	for _, pr := range re.ruleEngine.rules {
		if isNeverPR(pr) {
			t.Fatalf("rule %v should be satisfiable, but isn't", pr)
		}
	}

	re.removeIOBundleRule(&types.IoBundle{
		Phylabel:              "phy1",
		AssignmentGroup:       "1",
		ParentAssignmentGroup: "",
	})

	for _, pr := range re.ruleEngine.rules {
		if !isNeverPR(pr) {
			t.Fatalf("there should not be any working passthrough rule, but found %v", pr)
		}
	}
}

func TestEmptyParentPCIAddress(t *testing.T) {
	re := newRuleEngine()

	ud1 := usbdevice{
		usbControllerPCIAddress: "00:02.0",
		busnum:                  01,
		portnum:                 "3",
		vendorID:                5,
		productID:               6,
	}
	ud2 := usbdevice{
		usbControllerPCIAddress: "00:03.0",
		busnum:                  02,
		portnum:                 "3",
		vendorID:                5,
		productID:               6,
	}

	pciRule := pciPassthroughForbidRule{
		pciAddress: "00:02.0",
	}
	pciRule.vm = &virtualmachine{qmpSocketPath: "/vm/with/pci/passthrough"}
	re.addRule(&pciRule)

	usbRule := newUSBPortPassthroughRule(02, "3", "")

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
		portnumRule1 string,
		vendorIdRule1 uint32,
		productIdRule1 uint32,
		// usb plug passthrough rule
		parentPCIAddressRule2 string,
		busnumRule2 uint16,
		portnumRule2 string,
		vendorIdRule2 uint32,
		productIdRule2 uint32,
		// pci passthrough rule
		parentPCIAddressRule3 string,
		// actual usb device
		parentPCIAddress string,
		busnum uint16,
		devnum uint16,
		portnum string,
		vendorId uint32,
		productId uint32,
	) {
		re := newRuleEngine()

		rule1 := newUSBDevicePassthroughRule(vendorIdRule1, productIdRule1, parentPCIAddressRule1)
		rule1.vm = &virtualmachine{
			qmpSocketPath: "/vm1",
		}

		rule2 := newUSBPortPassthroughRule(busnumRule2, portnumRule2, parentPCIAddressRule2)
		rule2.vm = &virtualmachine{
			qmpSocketPath: "/vm2",
		}

		rule3 := pciPassthroughForbidRule{
			pciAddress: parentPCIAddressRule3,
		}
		rule3.vm = &virtualmachine{
			qmpSocketPath: "/vm3",
		}

		ud := usbdevice{
			busnum:                  busnum,
			devnum:                  devnum,
			portnum:                 portnum,
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
