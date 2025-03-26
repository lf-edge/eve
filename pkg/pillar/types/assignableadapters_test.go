// Copyright (c) 2019,2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	zcommon "github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var aa = AssignableAdapters{
	Initialized: true,
	IoBundleList: []IoBundle{
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth0-1",
			Phylabel:        "eth0",
			Ifname:          "eth0",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth0-1",
			Phylabel:        "eth1",
			Ifname:          "eth1",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth2",
			Phylabel:        "eth2",
			Ifname:          "eth2",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth4-7",
			Phylabel:        "eth4",
			Ifname:          "eth4",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth4-7",
			Phylabel:        "eth5",
			Ifname:          "eth5",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth4-7",
			Phylabel:        "eth6",
			Ifname:          "eth6",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth4-7",
			Phylabel:        "eth7",
			Ifname:          "eth7",
		},
	},
}

func TestLookupIoBundleGroup(t *testing.T) {
	testMatrix := map[string]struct {
		ioType             IoType
		lookupName         string
		expectedBundleName string
	}{
		"IoType: IoNetEth, LookupName: eth0-1": {
			ioType:             IoNetEth,
			lookupName:         "eth0-1",
			expectedBundleName: "eth0-1",
		},
		"IoType: IoNetEth LookupName: eth1": {
			ioType:             IoNetEth,
			lookupName:         "eth1",
			expectedBundleName: "",
		},
		"IoType: IoNetEth LookupName: eth2": {
			ioType:             IoNetEth,
			lookupName:         "eth2",
			expectedBundleName: "eth2",
		},
		"IoType: IoNetEth LookupName: eth4-7": {
			ioType:             IoNetEth,
			lookupName:         "eth4-7",
			expectedBundleName: "eth4-7",
		},
	}

	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		list := aa.LookupIoBundleGroup(test.lookupName)
		if len(list) == 0 {
			assert.Equal(t, test.expectedBundleName, "")
		} else {
			assert.Equal(t, test.expectedBundleName,
				list[0].AssignmentGroup)
		}
	}
}

func TestLookupIoBundlePhylabel(t *testing.T) {
	testMatrix := map[string]struct {
		ioType             IoType
		lookupName         string
		expectedBundleName string
	}{
		"ioType: IoNetEth, lookupName: eth1": {
			ioType:             IoNetEth,
			lookupName:         "eth1",
			expectedBundleName: "eth1",
		},
		"ioType: IoNetEth, lookupName: eth3": {
			ioType:             IoNetEth,
			lookupName:         "eth3",
			expectedBundleName: "",
		}, // No such member
		"ioType: IoNetEth, lookupName: eth7": {
			ioType:             IoNetEth,
			lookupName:         "eth7",
			expectedBundleName: "eth7",
		},
		// Test Ignore case
		"ioType: IoNetEth, lookupName: ETH7": {
			ioType:             IoNetEth,
			lookupName:         "ETH7",
			expectedBundleName: "eth7",
		},
	}

	// Basic test
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		ioBundle := aa.LookupIoBundlePhylabel(test.lookupName)
		if ioBundle == nil {
			assert.Equal(t, test.expectedBundleName, "")
		} else {
			assert.Equal(t, test.expectedBundleName, ioBundle.Phylabel)
		}
	}
}

func TestIoBundleFromPhyAdapter(t *testing.T) {
	phyAdapter := PhysicalIOAdapter{
		Ptype:        zcommon.PhyIoType_PhyIoNetEth,
		Phylabel:     "ethernet0",
		Logicallabel: "shopfloor",
		Assigngrp:    "eth-grp-1",
		Phyaddr: PhysicalAddress{
			Ifname:  "eth0",
			PciLong: "0000:f4:00.0",
			Irq:     "5",
			Ioports: "3f8-3ff",
			Serial:  "/dev/ttyS0",
		},
		Usage: zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		UsagePolicy: PhyIOUsagePolicy{
			FreeUplink: true,
		},
	}
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)
	ibPtr := IoBundleFromPhyAdapter(log, phyAdapter)
	assert.NotEqual(t, ibPtr, nil)
	assert.Equal(t, IoType(phyAdapter.Ptype), ibPtr.Type)
	assert.Equal(t, phyAdapter.Phylabel, ibPtr.Phylabel)
	assert.Equal(t, phyAdapter.Logicallabel, ibPtr.Logicallabel)
	assert.Equal(t, phyAdapter.Assigngrp, ibPtr.AssignmentGroup)
	assert.Equal(t, phyAdapter.Phyaddr.Ifname, ibPtr.Ifname)
	assert.Equal(t, phyAdapter.Phyaddr.PciLong, ibPtr.PciLong)
	assert.Equal(t, phyAdapter.Phyaddr.Irq, ibPtr.Irq)
	assert.Equal(t, phyAdapter.Phyaddr.Ioports, ibPtr.Ioports)
	assert.Equal(t, phyAdapter.Phyaddr.Serial, ibPtr.Serial)
	assert.Equal(t, phyAdapter.Usage, ibPtr.Usage)
}

var aa2 = AssignableAdapters{
	Initialized: true,
	IoBundleList: []IoBundle{
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth0-1",
			Phylabel:        "eth0",
			Ifname:          "eth0",
			PciLong:         "0000:f2:00.0",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth0-1",
			Phylabel:        "eth1",
			Ifname:          "eth1",
			PciLong:         "0000:f2:00.0",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth2",
			Phylabel:        "eth2",
			Ifname:          "eth2",
			PciLong:         "0000:f2:00.0",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth3",
			Phylabel:        "eth3",
			Ifname:          "eth3",
			PciLong:         "0000:f2:00.1",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth4-7",
			Phylabel:        "eth4",
			Ifname:          "eth4",
			PciLong:         "0000:f4:00.0",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth4-7",
			Phylabel:        "eth5",
			Ifname:          "eth5",
			PciLong:         "0000:f4:00.1",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth4-7",
			Phylabel:        "eth6",
			Ifname:          "eth6",
			PciLong:         "0000:f4:00.2",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth4-7",
			Phylabel:        "eth7",
			Ifname:          "eth7",
			PciLong:         "0000:f4:00.3",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth8",
			Phylabel:        "eth8",
			Ifname:          "eth8",
			PciLong:         "0000:f8:00.0",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth9",
			Phylabel:        "eth9",
			Ifname:          "eth9",
			PciLong:         "0000:f8:00.1",
		},
		{
			Type:            IoUSBController,
			Phylabel:        "USB0",
			Logicallabel:    "USB0",
			AssignmentGroup: "USB-A",
			Ifname:          "",
			PciLong:         "0000:f0:15.0",
		},
		{
			Type:            IoUSBController,
			Phylabel:        "USB1",
			Logicallabel:    "USB1",
			AssignmentGroup: "USB-A",
			Ifname:          "",
			PciLong:         "0000:f0:15.0",
		},
		{
			Type:            IoUSBController,
			Phylabel:        "USB2",
			Logicallabel:    "USB2",
			AssignmentGroup: "USB-A",
			Ifname:          "",
			PciLong:         "0000:f0:15.0",
		},
		{
			Type:            IoUSBController,
			Phylabel:        "USB3",
			Logicallabel:    "USB3",
			AssignmentGroup: "USB-A",
			Ifname:          "",
			PciLong:         "0000:f0:15.0",
		},
		{
			Type:            IoUSBController,
			Phylabel:        "USB4",
			Logicallabel:    "USB4",
			AssignmentGroup: "USB-A",
			Ifname:          "",
			PciLong:         "0000:f0:15.0",
		},
		{
			Type:            IoUSBController,
			Phylabel:        "USB5",
			Logicallabel:    "USB5",
			AssignmentGroup: "USB-A",
			Ifname:          "",
			PciLong:         "0000:f0:15.0",
		},
		{
			Type:            IoUSBController,
			Phylabel:        "USB-C",
			Logicallabel:    "USB6",
			AssignmentGroup: "USB-C",
			Ifname:          "",
			PciLong:         "0000:f5:00.0",
		},
		{
			Type:            IoCom,
			Phylabel:        "COM1",
			Logicallabel:    "COM1",
			AssignmentGroup: "COM1",
			Ifname:          "",
			PciLong:         "",
			Serial:          "/dev/ttyS0",
		},
		{
			Type:            IoCom,
			Phylabel:        "COM2",
			Logicallabel:    "COM2",
			AssignmentGroup: "COM2",
			Ifname:          "",
			PciLong:         "",
			Serial:          "/dev/ttyS1",
		},
		{
			Type:            IoCom,
			Phylabel:        "COM3",
			Logicallabel:    "COM3",
			AssignmentGroup: "COM34",
			Ifname:          "",
			PciLong:         "",
			Serial:          "/dev/ttyS2",
		},
		{
			Type:            IoCom,
			Phylabel:        "COM4",
			Logicallabel:    "COM4",
			AssignmentGroup: "COM34",
			Ifname:          "",
			PciLong:         "",
			Serial:          "/dev/ttyS3",
		},
		{
			Type:            IoAudio,
			Phylabel:        "Audio",
			Logicallabel:    "Audio",
			AssignmentGroup: "",
			Ifname:          "None",
			PciLong:         "0000:f5:01.f",
		},
	},
}

// Same indices as above
var aa2Errors = []string{
	"CheckBadAssignmentGroup: eth2 same PCI controller as eth0; pci long 0000:f2:00.0 vs 0000:f2:00.0; CheckBadAssignmentGroup: eth3 same PCI controller as eth0; pci long 0000:f2:00.1 vs 0000:f2:00.0",
	"CheckBadAssignmentGroup: eth2 same PCI controller as eth1; pci long 0000:f2:00.0 vs 0000:f2:00.0; CheckBadAssignmentGroup: eth3 same PCI controller as eth1; pci long 0000:f2:00.1 vs 0000:f2:00.0",
	"CheckBadAssignmentGroup: eth0 same PCI controller as eth2; pci long 0000:f2:00.0 vs 0000:f2:00.0; CheckBadAssignmentGroup: eth1 same PCI controller as eth2; pci long 0000:f2:00.0 vs 0000:f2:00.0; CheckBadAssignmentGroup: eth3 same PCI controller as eth2; pci long 0000:f2:00.1 vs 0000:f2:00.0",
	"CheckBadAssignmentGroup: eth0 same PCI controller as eth3; pci long 0000:f2:00.0 vs 0000:f2:00.1; CheckBadAssignmentGroup: eth1 same PCI controller as eth3; pci long 0000:f2:00.0 vs 0000:f2:00.1; CheckBadAssignmentGroup: eth2 same PCI controller as eth3; pci long 0000:f2:00.0 vs 0000:f2:00.1",
	"",
	"",
	"",
	"",
	"CheckBadAssignmentGroup: eth9 same PCI controller as eth8; pci long 0000:f8:00.1 vs 0000:f8:00.0",
	"CheckBadAssignmentGroup: eth8 same PCI controller as eth9; pci long 0000:f8:00.0 vs 0000:f8:00.1",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
	"",
}

func TestCheckBadAssignmentGroups(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)
	changed := aa2.CheckBadAssignmentGroups(log, PCISameController)
	assert.True(t, changed)
	assert.Equal(t, len(aa2.IoBundleList), len(aa2Errors))
	for i, ib := range aa2.IoBundleList {
		t.Logf("Running test case TestCheckBadAssignmentGroups[%d]", i)
		assert.Equal(t, aa2Errors[i], ib.Error.String())
	}
}

type expandControllersTestEntry struct {
	assignmentGroup string
	preLen          int
	postLen         int
	postMembers     []string
}

func TestExpandControllers(t *testing.T) {
	var testMatrix = map[string]expandControllersTestEntry{
		"eth0-3": {
			assignmentGroup: "eth0-1",
			preLen:          2,
			postLen:         4,
			postMembers:     []string{"eth0", "eth1", "eth2", "eth3"},
		},
		"eth0-3 from eth2": {
			assignmentGroup: "eth2",
			preLen:          1,
			postLen:         4,
			postMembers:     []string{"eth0", "eth1", "eth2", "eth3"},
		},
		"eth8-9 from eth8": {
			assignmentGroup: "eth8",
			preLen:          1,
			postLen:         2,
			postMembers:     []string{"eth8", "eth9"},
		},
		"com1": {
			assignmentGroup: "COM1",
			preLen:          1,
			postLen:         1,
			postMembers:     []string{"COM1"},
		},
		"com34": {
			assignmentGroup: "COM34",
			preLen:          2,
			postLen:         2,
			postMembers:     []string{"COM3", "COM4"},
		},
		"USB-A": {
			assignmentGroup: "USB-A",
			preLen:          6,
			postLen:         6,
			postMembers:     []string{"USB0", "USB1", "USB2", "USB3", "USB4", "USB5"},
		},
		"USB-C": {
			assignmentGroup: "USB-C",
			preLen:          1,
			postLen:         1,
			postMembers:     []string{"USB-C"},
		},
	}

	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)
	for testname, test := range testMatrix {
		t.Logf("TESTCASE: %s - Running", testname)
		preList := aa2.LookupIoBundleGroup(test.assignmentGroup)
		preLen := len(preList)
		postList := aa2.ExpandControllers(log, preList, PCISameController)
		postLen := len(postList)
		assert.Equal(t, test.preLen, preLen)
		assert.Equal(t, test.postLen, postLen)
		for _, m := range test.postMembers {
			found := false
			for _, ib := range postList {
				if ib.Phylabel == m {
					found = true
				}
			}
			assert.True(t, found, fmt.Sprintf("Expected %s in postList", m))
		}
	}
}

func alternativeCheckBadUSBBundlesImpl(bundles []IoBundle) {
	for i := range bundles {
		for j := range bundles {
			errStr := ""
			if i == j {
				continue
			}

			if bundles[i].UsbAddr != "" || bundles[j].UsbAddr != "" {
				if bundles[i].UsbAddr != bundles[j].UsbAddr {
					continue
				} else {
					errStr = "usbaddr same"
				}
			}

			if bundles[i].UsbProduct != "" || bundles[j].UsbProduct != "" {
				if bundles[i].UsbProduct != bundles[j].UsbProduct {
					continue
				} else {
					errStr = fmt.Sprintf("%s usbproduct same", errStr)
				}
			}

			if bundles[i].PciLong != "" || bundles[j].PciLong != "" {
				if bundles[i].PciLong != bundles[j].PciLong {
					continue
				} else {
					errStr = fmt.Sprintf("%s pci address same", errStr)
				}
			}

			if errStr != "" {
				bundles[i].Error.Append(errors.New(errStr))
				bundles[j].Error.Append(errors.New(errStr))
			}
		}
	}
}

func TestClearingCycleErrors(t *testing.T) {
	t.Parallel()

	aa := AssignableAdapters{}
	bundles := make([]IoBundle, 2)

	bundles[0].Phylabel = "usb1"
	bundles[1].Phylabel = "usb2"

	bundles[0].UsbAddr = "1:1"
	bundles[1].UsbAddr = "1:2"

	bundles[0].AssignmentGroup = "a1"
	bundles[1].AssignmentGroup = "a2"

	bundles[0].ParentAssignmentGroup = "a2"
	bundles[1].ParentAssignmentGroup = "a1"

	aa.IoBundleList = bundles

	aa.CheckParentAssigngrp()

	errFound := func() bool {
		found := false
		for _, ioBundle := range aa.IoBundleList {
			if ioBundle.Error.String() != "" {
				found = true
			}
		}
		return found
	}

	if !errFound() {
		t.Fatalf("no error found although there is a cycle: %+v", aa.IoBundleList)
	}

	aa.IoBundleList[1].ParentAssignmentGroup = "p2"
	aa.CheckParentAssigngrp()
	if errFound() {
		t.Fatalf("error found although there is no cycle anymore: %+v", aa.IoBundleList)
	}
}

func TestClearingUSBCollision(t *testing.T) {
	t.Parallel()
	aa := AssignableAdapters{}
	bundles := make([]IoBundle, 2)

	bundles[0].Phylabel = "usb1"
	bundles[1].Phylabel = "usb2"

	bundles[0].UsbAddr = "1:1"
	bundles[1].UsbAddr = bundles[0].UsbAddr
	aa.IoBundleList = bundles

	aa.CheckBadUSBBundles()

	for _, ioBundle := range aa.IoBundleList {
		t.Logf("%s / %s", ioBundle.Phylabel, ioBundle.Error.String())
		if ioBundle.Error.String() == "" {
			t.Fatalf("expected collision for ioBundle %s", ioBundle.Phylabel)
		}
	}

	aa.IoBundleList[0].UsbAddr = "1:2"
	aa.IoBundleList[0].Error.Clear()

	aa.CheckBadUSBBundles()
	for _, ioBundle := range aa.IoBundleList {
		t.Logf("%s / %s", ioBundle.Phylabel, ioBundle.Error.String())
		if ioBundle.Error.String() != "" {
			t.Fatalf("expected no collision for ioBundle %s", ioBundle.Phylabel)
		}
	}
}

func FuzzCheckBadUSBBundles(f *testing.F) {
	f.Fuzz(func(t *testing.T,
		// ioBundle 1
		pciLong1 string,
		usbAddr1 string,
		usbProduct1 string,
		// ioBundle 2
		pciLong2 string,
		usbAddr2 string,
		usbProduct2 string,
		// ioBundle 3
		pciLong3 string,
		usbAddr3 string,
		usbProduct3 string,
	) {
		alternativeCheckBundles := make([]IoBundle, 3)

		alternativeCheckBundles[0].PciLong = pciLong1
		alternativeCheckBundles[0].UsbAddr = usbAddr1
		alternativeCheckBundles[0].UsbProduct = usbProduct1

		alternativeCheckBundles[1].PciLong = pciLong2
		alternativeCheckBundles[1].UsbAddr = usbAddr2
		alternativeCheckBundles[1].UsbProduct = usbProduct2

		alternativeCheckBundles[2].PciLong = pciLong3
		alternativeCheckBundles[2].UsbAddr = usbAddr3
		alternativeCheckBundles[2].UsbProduct = usbProduct3

		alternativeCheckBadUSBBundlesImpl(alternativeCheckBundles)

		aa := AssignableAdapters{}
		bundles := make([]IoBundle, 3)
		bundles[0].PciLong = pciLong1
		bundles[0].UsbAddr = usbAddr1
		bundles[0].UsbProduct = usbProduct1

		bundles[1].PciLong = pciLong2
		bundles[1].UsbAddr = usbAddr2
		bundles[1].UsbProduct = usbProduct2

		bundles[2].PciLong = pciLong3
		bundles[2].UsbAddr = usbAddr3
		bundles[2].UsbProduct = usbProduct3

		aa.IoBundleList = bundles

		aa.CheckBadUSBBundles()

		failed := false
		for i := 0; i < len(bundles); i++ {
			if bundles[i].Error.String() != "" && alternativeCheckBundles[i].Error.String() != "" {
				continue
			}
			if bundles[i].Error.String() == "" && alternativeCheckBundles[i].Error.String() == "" {
				continue
			}

			failed = true
		}

		if failed {
			for i := 0; i < len(bundles); i++ {
				t.Logf("'%s' '%s' '%s' : '%s' <-> '%s'", bundles[i].PciLong, bundles[i].UsbAddr, bundles[i].UsbProduct,
					bundles[i].Error.String(), alternativeCheckBundles[i].Error.String())
			}
			t.Fatal("fail - check log")
		}
	})
}

func TestCheckBadParentAssigngrp(t *testing.T) {
	t.Parallel()
	aa := AssignableAdapters{}

	aa.IoBundleList = []IoBundle{
		{
			Phylabel:              "1",
			AssignmentGroup:       "BBB",
			ParentAssignmentGroup: "AAA",
		},
		{
			Phylabel:              "2",
			AssignmentGroup:       "BBB",
			ParentAssignmentGroup: "ZZZ",
		},
	}

	aa.CheckParentAssigngrp()

	errorSet := false
	for _, ioBundle := range aa.IoBundleList {
		if ioBundle.Error.String() == "IOBundle with parentassigngrp mismatch found" {
			errorSet = true
			break
		}
	}

	if !errorSet {
		t.Fatal("wrong error message")
	}
}

func TestCheckBadParentAssigngrpLoop(t *testing.T) {
	t.Parallel()
	aa := AssignableAdapters{}

	aa.IoBundleList = []IoBundle{
		{
			Phylabel:              "1",
			AssignmentGroup:       "BBB",
			ParentAssignmentGroup: "AAA",
		},
		{
			Phylabel:              "2",
			AssignmentGroup:       "AAA",
			ParentAssignmentGroup: "AAA",
		},
	}

	aa.CheckParentAssigngrp()

	for _, ioBundle := range aa.IoBundleList {
		if ioBundle.Phylabel == "2" {
			if ioBundle.Error.String() != "IOBundle cannot be it's own parent" {
				t.Fatal("wrong error message")
			}
		}
	}

	aa.IoBundleList = []IoBundle{
		{
			Phylabel:              "1",
			AssignmentGroup:       "BBB",
			ParentAssignmentGroup: "AAA",
		},
		{
			Phylabel:              "2",
			AssignmentGroup:       "AAA",
			ParentAssignmentGroup: "BBB",
		},
	}

	aa.CheckParentAssigngrp()

	errorSet := false
	for _, ioBundle := range aa.IoBundleList {
		if ioBundle.Error.String() == "Cycle detected, please check provided parentassigngrp/assigngrp" {
			errorSet = true
			break
		}

	}
	if !errorSet {
		t.Fatal("wrong error message")
	}

}

func TestCheckBadUSBBundles(t *testing.T) {
	t.Parallel()
	aa := AssignableAdapters{}

	type bundleWithError struct {
		bundle        IoBundle
		expectedError string
	}
	bundleTestCases := []struct {
		bundleWithError []bundleWithError
	}{
		{
			bundleWithError: []bundleWithError{
				{
					bundle:        IoBundle{Phylabel: "1", UsbAddr: "1:1", UsbProduct: "a:a", PciLong: "1:1"},
					expectedError: "ioBundle collision:||phylabel 1 - usbaddr: 1:1 usbproduct: a:a pcilong: 1:1 assigngrp: ||phylabel 2 - usbaddr: 1:1 usbproduct: a:a pcilong: 1:1 assigngrp: ||",
				},
				{
					bundle:        IoBundle{Phylabel: "2", UsbAddr: "1:1", UsbProduct: "a:a", PciLong: "1:1"},
					expectedError: "ioBundle collision:||phylabel 1 - usbaddr: 1:1 usbproduct: a:a pcilong: 1:1 assigngrp: ||phylabel 2 - usbaddr: 1:1 usbproduct: a:a pcilong: 1:1 assigngrp: ||",
				},
			},
		},
		{
			bundleWithError: []bundleWithError{
				{
					bundle:        IoBundle{Phylabel: "3", UsbAddr: "1:1", UsbProduct: "a:a"},
					expectedError: "ioBundle collision:||phylabel 3 - usbaddr: 1:1 usbproduct: a:a pcilong:  assigngrp: ||phylabel 4 - usbaddr: 1:1 usbproduct: a:a pcilong:  assigngrp: ||",
				},
				{
					bundle:        IoBundle{Phylabel: "4", UsbAddr: "1:1", UsbProduct: "a:a"},
					expectedError: "ioBundle collision:||phylabel 3 - usbaddr: 1:1 usbproduct: a:a pcilong:  assigngrp: ||phylabel 4 - usbaddr: 1:1 usbproduct: a:a pcilong:  assigngrp: ||",
				},
				{
					bundle:        IoBundle{Phylabel: "5", UsbAddr: "1:1", UsbProduct: ""},
					expectedError: "",
				},
			},
		},
		{
			bundleWithError: []bundleWithError{
				{
					bundle:        IoBundle{Phylabel: "6", UsbAddr: "1:1", UsbProduct: ""},
					expectedError: "ioBundle collision:||phylabel 6 - usbaddr: 1:1 usbproduct:  pcilong:  assigngrp: ||phylabel 7 - usbaddr: 1:1 usbproduct:  pcilong:  assigngrp: ||",
				},
				{
					bundle:        IoBundle{Phylabel: "7", UsbAddr: "1:1", UsbProduct: ""},
					expectedError: "ioBundle collision:||phylabel 6 - usbaddr: 1:1 usbproduct:  pcilong:  assigngrp: ||phylabel 7 - usbaddr: 1:1 usbproduct:  pcilong:  assigngrp: ||",
				},
			},
		},
		{
			bundleWithError: []bundleWithError{
				{
					bundle:        IoBundle{Phylabel: "8", UsbAddr: "", UsbProduct: "a:a"},
					expectedError: "ioBundle collision:||phylabel 8 - usbaddr:  usbproduct: a:a pcilong:  assigngrp: ||phylabel 9 - usbaddr:  usbproduct: a:a pcilong:  assigngrp: ||",
				},
				{
					bundle:        IoBundle{Phylabel: "9", UsbAddr: "", UsbProduct: "a:a"},
					expectedError: "ioBundle collision:||phylabel 8 - usbaddr:  usbproduct: a:a pcilong:  assigngrp: ||phylabel 9 - usbaddr:  usbproduct: a:a pcilong:  assigngrp: ||",
				},
			},
		},
		{
			bundleWithError: []bundleWithError{
				{
					bundle: IoBundle{Phylabel: "10", UsbAddr: "", UsbProduct: ""},
				},
				{
					bundle: IoBundle{Phylabel: "11", UsbAddr: "", UsbProduct: ""},
				},
			},
		},
	}

	for _, testCase := range bundleTestCases {
		bundles := make([]IoBundle, 0)

		for _, bundle := range testCase.bundleWithError {
			bundles = append(bundles, bundle.bundle)
		}
		aa.IoBundleList = bundles

		aa.CheckBadUSBBundles()

		for i, bundleWithErr := range testCase.bundleWithError {
			if bundles[i].Error.String() != bundleWithErr.expectedError {
				t.Fatalf("bundle %s expected error \n'%s', got error \n'%s'",
					bundleWithErr.bundle.Phylabel, bundleWithErr.expectedError, bundles[i].Error.String())
			}
		}
	}
}

type (
	testErr1 struct{}
	testErr2 struct{}
	testErr3 struct {
		error
	}
	testErr4 struct {
		error
	}
)

func (testErr1) Error() string {
	return "err1"
}

func (testErr2) Error() string {
	return "err2"
}

func TestIoBundleError(t *testing.T) {
	iobe := IOBundleError{}

	iobe.Append(testErr1{})

	if !iobe.HasErrorByType(testErr1{}) {
		t.Fatal("has not error testErr1")
	}
	if iobe.HasErrorByType(testErr2{}) {
		t.Fatal("has error testErr2, but shouldn't")
	}

	if iobe.String() != "err1" {
		t.Fatalf("expected error string to be 'err1', but got '%s'", iobe.String())
	}

	iobe.Append(testErr2{})

	if iobe.String() != "err1; err2" {
		t.Fatalf("expected error string to be 'err1; err2', but got '%s'", iobe.String())
	}

	iobe.Append(testErr1{})

	iobe.removeByType(testErr1{})

	if iobe.String() != "err2" {
		t.Fatalf("expected error string to be 'err2', but got '%s'", iobe.String())
	}
	if !iobe.HasErrorByType(testErr2{}) {
		t.Fatal("has not error testErr2")
	}

	err3 := testErr3{fmt.Errorf("err3")}
	err4 := testErr4{fmt.Errorf("err4")}
	iobe.Append(err3)
	iobe.Append(err4)

	if iobe.String() != "err2; err3; err4" {
		t.Fatalf("expected error string to be 'err2; err3; err4', but got '%s'", iobe.String())
	}

	iobe.removeByType(testErr3{})
	if iobe.String() != "err2; err4" {
		t.Fatalf("expected error string to be 'err2; err4', but got '%s'", iobe.String())
	}
}

func TestIoBundleCmpable(t *testing.T) {
	io1 := IoBundle{}
	io2 := IoBundle{}

	cmp.Diff(io1, io2)
}

func TestIoBundleErrorRemove(t *testing.T) {
	errs := []error{
		fmt.Errorf("some error"),
		ErrOwnParent{},
		ErrParentAssigngrpMismatch{},
		ErrEmptyAssigngrpWithParent{},
		ErrCycleDetected{},
		newIoBundleCollisionErr(),
	}
	iob := IoBundle{
		Error: IOBundleError{
			TimeOfError: time.Time{},
		},
	}

	for _, err := range errs {
		iob.Error.Append(err)
	}

	iob.Error.removeByType(ErrOwnParent{})

	if len(iob.Error.Errors) != 5 {
		for _, err := range iob.Error.Errors {
			t.Logf("\t- %s -- %v", err.TypeStr, err)
		}

		t.Fatalf("expected only 5 errors, but got %d", len(iob.Error.Errors))
	}
}
