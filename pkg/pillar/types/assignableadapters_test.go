// Copyright (c) 2019,2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"testing"

	zcommon "github.com/lf-edge/eve/api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var aa AssignableAdapters = AssignableAdapters{
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
			PciLong: "0000:04:00.0",
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

var aa2 AssignableAdapters = AssignableAdapters{
	Initialized: true,
	IoBundleList: []IoBundle{
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth0-1",
			Phylabel:        "eth0",
			Ifname:          "eth0",
			PciLong:         "0000:02:00.0",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth0-1",
			Phylabel:        "eth1",
			Ifname:          "eth1",
			PciLong:         "0000:02:00.0",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth2",
			Phylabel:        "eth2",
			Ifname:          "eth2",
			PciLong:         "0000:02:00.0",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth3",
			Phylabel:        "eth3",
			Ifname:          "eth3",
			PciLong:         "0000:02:00.1",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth4-7",
			Phylabel:        "eth4",
			Ifname:          "eth4",
			PciLong:         "0000:04:00.0",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth4-7",
			Phylabel:        "eth5",
			Ifname:          "eth5",
			PciLong:         "0000:04:00.1",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth4-7",
			Phylabel:        "eth6",
			Ifname:          "eth6",
			PciLong:         "0000:04:00.2",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth4-7",
			Phylabel:        "eth7",
			Ifname:          "eth7",
			PciLong:         "0000:04:00.3",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth8",
			Phylabel:        "eth8",
			Ifname:          "eth8",
			PciLong:         "0000:08:00.0",
		},
		{
			Type:            IoNetEth,
			AssignmentGroup: "eth9",
			Phylabel:        "eth9",
			Ifname:          "eth9",
			PciLong:         "0000:08:00.1",
		},
		{
			Type:            IoUSB,
			Phylabel:        "USB0",
			Logicallabel:    "USB0",
			AssignmentGroup: "USB-A",
			Ifname:          "",
			PciLong:         "0000:00:15.0",
		},
		{
			Type:            IoUSB,
			Phylabel:        "USB1",
			Logicallabel:    "USB1",
			AssignmentGroup: "USB-A",
			Ifname:          "",
			PciLong:         "0000:00:15.0",
		},
		{
			Type:            IoUSB,
			Phylabel:        "USB2",
			Logicallabel:    "USB2",
			AssignmentGroup: "USB-A",
			Ifname:          "",
			PciLong:         "0000:00:15.0",
		},
		{
			Type:            IoUSB,
			Phylabel:        "USB3",
			Logicallabel:    "USB3",
			AssignmentGroup: "USB-A",
			Ifname:          "",
			PciLong:         "0000:00:15.0",
		},
		{
			Type:            IoUSB,
			Phylabel:        "USB4",
			Logicallabel:    "USB4",
			AssignmentGroup: "USB-A",
			Ifname:          "",
			PciLong:         "0000:00:15.0",
		},
		{
			Type:            IoUSB,
			Phylabel:        "USB5",
			Logicallabel:    "USB5",
			AssignmentGroup: "USB-A",
			Ifname:          "",
			PciLong:         "0000:00:15.0",
		},
		{
			Type:            IoUSB,
			Phylabel:        "USB-C",
			Logicallabel:    "USB6",
			AssignmentGroup: "USB-C",
			Ifname:          "",
			PciLong:         "0000:05:00.0",
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
			PciLong:         "0000:05:01.f",
		},
	},
}

// Same indices as above
var aa2Errors = []string{
	"CheckBadAssignmentGroup: eth3 same PCI controller as eth0; pci long 0000:02:00.1 vs 0000:02:00.0",
	"CheckBadAssignmentGroup: eth3 same PCI controller as eth1; pci long 0000:02:00.1 vs 0000:02:00.0",
	"CheckBadAssignmentGroup: eth3 same PCI controller as eth2; pci long 0000:02:00.1 vs 0000:02:00.0",
	"CheckBadAssignmentGroup: eth2 same PCI controller as eth3; pci long 0000:02:00.0 vs 0000:02:00.1",
	"",
	"",
	"",
	"",
	"CheckBadAssignmentGroup: eth9 same PCI controller as eth8; pci long 0000:08:00.1 vs 0000:08:00.0",
	"CheckBadAssignmentGroup: eth8 same PCI controller as eth9; pci long 0000:08:00.0 vs 0000:08:00.1",
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
		assert.Equal(t, aa2Errors[i], ib.Error)
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
