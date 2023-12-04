// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"fmt"
	"io"
	"testing"
	"unicode/utf8"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

func (iobt ioBundleTree) toDotFile(w io.Writer) {
	iobt.consistencyCheck()
	fmt.Fprintf(w, "digraph G {\n")
	fmt.Fprintf(w, "\tcompound=true;\n")
	for _, ioBundleElem := range iobt.elementsByAssignmentGroup {
		fmt.Fprintf(w, "\tsubgraph \"cluster_%s\" {\n", ioBundleElem.assignmentGroup)
		subgraphName := ioBundleElem.assignmentGroup
		if subgraphName == "" {
			subgraphName = "root"
		}
		fmt.Fprintf(w, "\t\tlabel = \"%s\"\n", subgraphName)
		fmt.Fprintf(w, "\t\t\"cluster_%s_invisible_node\"[style=invis];\n", ioBundleElem.assignmentGroup)
		for _, ioBundle := range ioBundleElem.ioBundles() {
			fmt.Fprintf(w, "\t\t\"%s\";\n", ioBundle.Phylabel)
		}
		fmt.Fprintf(w, "\t}\n")
	}
	fmt.Fprintln(w)
	for _, ioBundleElem := range iobt.elementsByAssignmentGroup {
		if ioBundleElem.parent != nil {
			fmt.Fprintf(w, "\t\"cluster_%s_invisible_node\" -> \"cluster_%s_invisible_node\"[lhead=cluster_%s];\n",
				ioBundleElem.assignmentGroup,
				ioBundleElem.parent.assignmentGroup,
				ioBundleElem.parent.assignmentGroup)
		}
	}
	fmt.Fprintf(w, "}\n")
}

func (iobt *ioBundleTree) consistencyCheck() {
	for assigngrp, ioBundleElem := range iobt.elementsByAssignmentGroup {
		iobt.groupDependendents(assigngrp)
		iobt.groupParents(assigngrp)
		if assigngrp != ioBundleElem.assignmentGroup {
			panic("assigngrp in elementsByAssignmentGroup map is wrong")
		}

		for childAssigngrp, childIOBundleElem := range ioBundleElem.children {
			if childAssigngrp != childIOBundleElem.assignmentGroup {
				panic("key of children ioBundlesElem map is wrong")
			}

			childIOBundleElemInMap := iobt.elementsByAssignmentGroup[childAssigngrp]
			if childIOBundleElemInMap != childIOBundleElem {
				panic("childIOBundleElem not found in elementsByAssignmentGroup map")
			}
		}

		for _, ioBundle := range ioBundleElem.ioBundles() {
			if ioBundle.AssignmentGroup != ioBundleElem.assignmentGroup {
				panic("assigngrp is wrong; ioBundleElem vs ioBundle")
			}

			if ioBundleElem.parent == nil && ioBundle.ParentAssignmentGroup != "" {
				panic("ioBundle parent assignment group is nonempty, but ioBundleElem has no parent")
			} else if ioBundleElem.parent != nil && ioBundle.ParentAssignmentGroup != ioBundleElem.parent.assignmentGroup {
				panic("ioBundle parent assignment group is different from ioBundleElem.parent assignment group")
			}

		}
	}

}

func TestIOBundle2PassthroughRule_AppearingParent(t *testing.T) {
	var pr passthroughRule
	var pa passthroughAction

	iobt := newIOBundleTree()

	iobt.addIOBundle(&types.IoBundle{
		Phylabel:        "phy2",
		AssignmentGroup: "2",
	})

	usbDeviceBundle := &types.IoBundle{
		Phylabel:              "phy4.1",
		AssignmentGroup:       "4",
		ParentAssignmentGroup: "3",
		UsbAddr:               "4:1",
		UsbProduct:            "4:1",
	}
	iobt.addIOBundle(usbDeviceBundle)

	pr = iobt.ioBundle2passthroughRule(*usbDeviceBundle)

	ud := usbdevice{
		busnum:                  4,
		portnum:                 "1",
		vendorID:                4,
		productID:               1,
		usbControllerPCIAddress: "4:1",
		ueventFilePath:          "/uevent.file",
	}

	pa, _ = pr.evaluate(ud)

	if pa != passthroughNo {
		t.Fatalf("expected no passthrough, but got %v", pa)
	}

	iobt.addIOBundle(&types.IoBundle{
		Phylabel:              "phy3",
		AssignmentGroup:       "3",
		ParentAssignmentGroup: "2",
	})

	pr = iobt.ioBundle2passthroughRule(*usbDeviceBundle)

	pa, _ = pr.evaluate(ud)

	if pa != passthroughDo {
		t.Fatalf("expected passthrough, but got %v", pa)
	}

}

func TestIOBundle2PassthroughRule(t *testing.T) {
	iobt := newIOBundleTree()

	iobt.addIOBundle(&types.IoBundle{
		Phylabel:        "phy2",
		AssignmentGroup: "2",
	})

	iobt.addIOBundle(&types.IoBundle{
		Phylabel:              "phy3.1",
		AssignmentGroup:       "3",
		PciLong:               "3:1",
		ParentAssignmentGroup: "2",
	})
	iobt.addIOBundle(&types.IoBundle{
		Phylabel:              "phy3.2",
		AssignmentGroup:       "3",
		PciLong:               "3:2",
		ParentAssignmentGroup: "2",
	})

	usbDeviceBundle := &types.IoBundle{
		Phylabel:              "phy4.1",
		AssignmentGroup:       "4",
		ParentAssignmentGroup: "3",
		UsbAddr:               "4:1",
		UsbProduct:            "4:1",
	}
	iobt.addIOBundle(usbDeviceBundle)

	pr := iobt.ioBundle2passthroughRule(*usbDeviceBundle)

	ud := usbdevice{
		busnum:                  4,
		portnum:                 "1",
		vendorID:                4,
		productID:               1,
		usbControllerPCIAddress: "3:1",
		ueventFilePath:          "/uevent.file",
	}

	passthrough, _ := pr.evaluate(ud)
	if passthrough != passthroughDo {
		t.Fatalf("expected passthroughDo, but got %v", passthrough)
	}

	ud.usbControllerPCIAddress = ""
	passthrough, _ = pr.evaluate(ud)
	if passthrough != passthroughNo {
		t.Fatalf("expected passthroughNo, but got %v", passthrough)
	}

	ud.usbControllerPCIAddress = "3:2"
	passthrough, _ = pr.evaluate(ud)
	if passthrough != passthroughDo {
		t.Fatalf("expected passthroughDo, but got %v", passthrough)
	}

	ud.portnum = ""
	passthrough, _ = pr.evaluate(ud)
	if passthrough != passthroughNo {
		t.Fatalf("expected passthroughNo, but got %v", passthrough)
	}

}

func TestIOBundleTree(t *testing.T) {
	iobt := newIOBundleTree()

	iobt.addIOBundle(&types.IoBundle{
		Phylabel:              "phy3",
		AssignmentGroup:       "3",
		ParentAssignmentGroup: "2",
	})

	iobt.addIOBundle(&types.IoBundle{
		Phylabel:              "phy3.1",
		AssignmentGroup:       "3",
		ParentAssignmentGroup: "2",
	})

	iobt.addIOBundle(&types.IoBundle{
		Phylabel:        "phy2",
		AssignmentGroup: "2",
	})

	iobt.consistencyCheck()
}

func TestOrphanedIOBundleElem(t *testing.T) {
	iobt := newIOBundleTree()

	iobt.addIOBundle(&types.IoBundle{
		Phylabel:              "phy3",
		AssignmentGroup:       "3",
		ParentAssignmentGroup: "2",
	})

	iobt.addIOBundle(&types.IoBundle{
		Phylabel:              "phy2",
		AssignmentGroup:       "2",
		ParentAssignmentGroup: "",
	})

	iobt.consistencyCheck()

}

func TestGroupDependencies(t *testing.T) {
	iobt := newIOBundleTree()

	iobt.addIOBundle(&types.IoBundle{
		Phylabel:              "phy3",
		AssignmentGroup:       "group3",
		ParentAssignmentGroup: "group2.1",
	})

	iobt.addIOBundle(&types.IoBundle{
		Phylabel:              "phy2.1",
		AssignmentGroup:       "group2.1",
		ParentAssignmentGroup: "group1",
	})

	iobt.addIOBundle(&types.IoBundle{
		Phylabel:              "phy2.2",
		AssignmentGroup:       "group2.2",
		ParentAssignmentGroup: "group1",
	})

	iobt.addIOBundle(&types.IoBundle{
		Phylabel:              "phy1",
		AssignmentGroup:       "group1",
		ParentAssignmentGroup: "",
	})

	dependents := iobt.groupDependendents("group2.1")
	if dependents[0] != "group3" {
		t.Fatalf("group2.1 should have dependee group3")
	}
	found := 0
	dependents = iobt.groupDependendents("group1")
	for _, group := range []string{"group2.1", "group2.2", "group3"} {
		for _, dependeeGroup := range dependents {
			if group == dependeeGroup {
				found++
			}
		}
	}
	if found != 3 {
		t.Fatalf("did not find expected groups; groups are: %+v", dependents)
	}

	dependers := iobt.groupParents("group3")
	found = 0
	for _, group := range []string{"group2.1", "group1"} {
		for _, dependerGroup := range dependers {
			if group == dependerGroup {
				found++
			}
		}
	}
	if found != 2 {
		t.Fatalf("did not find expected groups; groups are: %+v", dependers)
	}
}

func FuzzIOBundleTree(f *testing.F) {
	f.Fuzz(func(t *testing.T,
		phyLabel1 string,
		assigngrp1 string,

		phyLabel2 string,
		assigngrp2 string,

		phyLabel3 string,
		assigngrp3 string,

		phyLabel4 string,
		assigngrp4 string,

		phyLabel5 string,
		assigngrp5 string,

		delBundle1 int,
		delBundle1Pos int,

		delBundle2 int,
		delBundle2Pos int,

		delBundle3 int,
		delBundle3Pos int,

	) {

		iobt := newIOBundleTree()

		ioBundle1 := types.IoBundle{
			Phylabel:        phyLabel1,
			AssignmentGroup: assigngrp1,
		}

		ioBundle2 := types.IoBundle{
			Phylabel:        phyLabel2,
			AssignmentGroup: assigngrp2,
		}

		ioBundle3 := types.IoBundle{
			Phylabel:        phyLabel3,
			AssignmentGroup: assigngrp3,
		}

		ioBundle4 := types.IoBundle{
			Phylabel:        phyLabel4,
			AssignmentGroup: assigngrp4,
		}

		ioBundle5 := types.IoBundle{
			Phylabel:        phyLabel5,
			AssignmentGroup: assigngrp5,
		}

		ioBundlesArray := []*types.IoBundle{&ioBundle1, &ioBundle2, &ioBundle3, &ioBundle4, &ioBundle5}

		delBundleCmd := []struct {
			index int
			pos   int
		}{
			{delBundle1, delBundle1Pos},
			{delBundle2, delBundle2Pos},
			{delBundle3, delBundle3Pos},
		}

		for i := range delBundleCmd {
			if delBundleCmd[i].index < 0 {
				delBundleCmd[i].index = -1 * delBundleCmd[i].index
			}
			if delBundleCmd[i].pos < 0 {
				delBundleCmd[i].pos = -1 * delBundleCmd[i].pos
			}
			delBundleCmd[i].index = delBundleCmd[i].index % len(ioBundlesArray)
			delBundleCmd[i].pos = delBundleCmd[i].pos % len(ioBundlesArray)
		}

		for pos, ioBundle := range ioBundlesArray {

			for _, dbc := range delBundleCmd {
				if dbc.pos == pos {
					iobt.removeIOBundle(ioBundlesArray[dbc.index])
					iobt.consistencyCheck()
				}
			}

			var parentassigngrp string
			if len(ioBundle.AssignmentGroup) > 0 {
				_, size := utf8.DecodeLastRuneInString(ioBundle.AssignmentGroup)
				// set the parentassigngrp to the assigngrp without the last character
				// this way it is guaranteed that ioBundles with the same assigngrp
				// have the same parentassigngrp
				parentassigngrp = ioBundle.AssignmentGroup[:len(ioBundle.AssignmentGroup)-size]
			}

			ioBundle.ParentAssignmentGroup = parentassigngrp

			iobt.addIOBundle(ioBundle)
			iobt.consistencyCheck()
		}

	})
}

func FuzzIOBundle2PassthroughRule(f *testing.F) {
	f.Fuzz(func(t *testing.T,
		usbaddr string,
		usbproduct string,
		pcilong string,
	) {
		ioBundle := types.IoBundle{
			UsbAddr:    usbaddr,
			UsbProduct: usbproduct,
			PciLong:    pcilong,
		}

		iobt := newIOBundleTree()
		iobt.ioBundle2passthroughRule(ioBundle)
	})
}

func TestIOBundleEmpty(t *testing.T) {
	bundle := types.IoBundle{}

	iobt := newIOBundleTree()
	pr := iobt.ioBundle2passthroughRule(bundle)

	if pr != nil {
		t.Fatalf("expected nil rule but got %+v (%T)", pr, pr)
	}
}

func TestIOBundlePCIForbidRule(t *testing.T) {
	bundle := types.IoBundle{PciLong: "00:14.0"}

	iobt := newIOBundleTree()
	pr := iobt.ioBundle2passthroughRule(bundle)

	_, ok := pr.(*pciPassthroughForbidRule)
	if !ok {
		t.Fatalf("expected pciPassthroughForbidRule type but got %T %+v", pr, pr)
	}
}

func TestIOBundleUSBProductAndUSBAddress(t *testing.T) {
	bundle := types.IoBundle{
		UsbAddr:    "1:1",
		UsbProduct: "2:2",
	}

	iobt := newIOBundleTree()
	pr := iobt.ioBundle2passthroughRule(bundle)

	ud := usbdevice{}

	action, _ := pr.evaluate(ud)
	if action != passthroughNo {
		t.Fatalf("passthrough action should be passthroughNo, but got %v", action)
	}

	for _, test := range []struct {
		beforeFunc     func()
		expectedAction passthroughAction
	}{
		{
			beforeFunc:     func() { ud.busnum = 1 },
			expectedAction: passthroughNo,
		},
		{
			beforeFunc:     func() { ud.portnum = "1" },
			expectedAction: passthroughNo,
		},
		{
			beforeFunc:     func() { ud.vendorID = 2 },
			expectedAction: passthroughNo,
		},
		{
			beforeFunc:     func() { ud.productID = 2 },
			expectedAction: passthroughDo,
		},
		{
			beforeFunc: func() {
				bundle.PciLong = "3:3" // passthrough is now tied to this pci controller
				pr = iobt.ioBundle2passthroughRule(bundle)

				ud.usbControllerPCIAddress = "4:4"
			},
			expectedAction: passthroughNo,
		},
		{
			beforeFunc:     func() { ud.usbControllerPCIAddress = "3:3" },
			expectedAction: passthroughDo,
		},
	} {
		test.beforeFunc()
		action, _ := pr.evaluate(ud)
		if action != test.expectedAction {
			t.Fatalf("passthrough action should be %v, but got %v; ud: %+v", test.expectedAction, action, ud)
		}
	}
}

func TestIOBundlePCIAndUSBProduct(t *testing.T) {
	bundle := types.IoBundle{
		PciLong:    "0:0",
		UsbProduct: "1:1",
	}

	iobt := newIOBundleTree()
	pr := iobt.ioBundle2passthroughRule(bundle)

	hasPCIRule := false
	hasUSBProductRule := false
	cpr := pr.(*compositionANDPassthroughRule)
	for _, rule := range cpr.rules {
		switch rule.(type) {
		case *pciPassthroughRule:
			hasPCIRule = true
		case *usbDevicePassthroughRule:
			hasUSBProductRule = true
		}
	}

	if !hasPCIRule {
		t.Fatal("not pciPassthroughRule")
	}
	if !hasUSBProductRule {
		t.Fatal("not usbDevicePassthroughRule")
	}

	ud := usbdevice{
		usbControllerPCIAddress: "2:2",
	}

	action, _ := pr.evaluate(ud)
	if action != passthroughNo {
		t.Fatalf("passthrough action should be passthroughNo, but got %v", action)
	}

	ud.vendorID = 1
	ud.productID = 1
	action, _ = pr.evaluate(ud)
	if action != passthroughNo {
		t.Fatalf("passthrough action should be passthroughNo, but got %v", action)
	}
	ud.usbControllerPCIAddress = "0:0"
	action, _ = pr.evaluate(ud)
	if action != passthroughDo {
		t.Fatalf("passthrough action should be passthroughDo, but got %v", action)
	}
}

func TestIOBundlePCIAndUSBAddress(t *testing.T) {
	bundle := types.IoBundle{
		PciLong: "0:0",
		UsbAddr: "1:1",
	}

	iobt := newIOBundleTree()
	pr := iobt.ioBundle2passthroughRule(bundle)

	ud := usbdevice{
		usbControllerPCIAddress: "2:2",
	}

	action, _ := pr.evaluate(ud)
	if action != passthroughNo {
		t.Fatalf("passthrough action should be passthroughNo, but got %v", action)
	}

	ud.busnum = 1
	ud.portnum = "1"
	action, _ = pr.evaluate(ud)
	if action != passthroughNo {
		t.Fatalf("passthrough action should be passthroughNo, but got %v", action)
	}
	ud.usbControllerPCIAddress = "0:0"
	action, _ = pr.evaluate(ud)
	if action != passthroughDo {
		t.Fatalf("passthrough action should be passthroughDo, but got %v", action)
	}
}

func TestAddIOBundleDeadlock(t *testing.T) {
	ioBundles := []types.IoBundle{
		{
			Phylabel:              "1",
			Logicallabel:          "1",
			AssignmentGroup:       "1",
			ParentAssignmentGroup: "2",
			UsbAddr:               "1:1",
		},
		{
			Phylabel:              "2",
			Logicallabel:          "2",
			AssignmentGroup:       "2",
			ParentAssignmentGroup: "1",
			UsbAddr:               "0:0",
		},
	}

	iobt := newIOBundleTree()
	iobt.addIOBundle(&ioBundles[0])
	iobt.addIOBundle(&ioBundles[1])

}
