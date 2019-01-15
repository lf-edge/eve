// Copyright (c) 2019 Zededa, Inc.
// All rights reserved.

package types

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

var aa AssignableAdapters = AssignableAdapters{
	Initialized: true,
	IoBundleList: []IoBundle{
		IoBundle{
			Type:    IoEth,
			Name:    "eth0-1",
			Members: []string{"eth0", "eth1"},
			Lookup:  true,
		},
		IoBundle{
			Type:    IoEth,
			Name:    "eth2",
			Members: []string{"eth2"},
			Lookup:  true,
		},
		IoBundle{
			Type:    IoEth,
			Name:    "eTH4-7",
			Members: []string{"eth4", "eth5", "eth6", "eth7"},
			Lookup:  true,
		},
	},
}

type TestLookupIoBundleForMemberMatrix struct {
	ioType             IoType
	lookupName         string
	expectedBundleName string
}

func TestLookupIoBundle(t *testing.T) {
	log.Infof("TestLookupIoBundle: START\n")

	testMatrix := []TestLookupIoBundleForMemberMatrix{
		{ioType: IoEth, lookupName: "eth0-1", expectedBundleName: "eth0-1"},
		// Type should also be considered.
		{ioType: IoUSB, lookupName: "eth1", expectedBundleName: ""},
		{ioType: IoEth, lookupName: "eth4-7", expectedBundleName: ""}, // No such member
	}

	// Basic test
	for index := range testMatrix {
		entry := &testMatrix[index]
		ioBundle := LookupIoBundle(&aa, entry.ioType, entry.lookupName)
		if ioBundle == nil {
			if entry.expectedBundleName != "" {
				t.Errorf("Test Entry Index %d Failed: Null bundle. Expected %s\n",
					index, entry.expectedBundleName)
			}
		} else {
			if ioBundle.Name != entry.expectedBundleName {
				t.Errorf("Test Entry Index %d Failed: Expected %s, Actual: %s\n",
					index, entry.expectedBundleName, ioBundle.Name)
			}
		}
	}
	log.Infof("TestLookupIoBundleForMember: DONE\n")
}

func TestLookupIoBundleForMember(t *testing.T) {
	log.Infof("TestLookupIoBundleForMember: START\n")

	testMatrix := []TestLookupIoBundleForMemberMatrix{
		{ioType: IoEth, lookupName: "eth1", expectedBundleName: "eth0-1"},
		// Type should also be considered.
		{ioType: IoUSB, lookupName: "eth1", expectedBundleName: ""},
		{ioType: IoEth, lookupName: "eth3", expectedBundleName: ""}, // No such member
		{ioType: IoEth, lookupName: "eth7", expectedBundleName: "eth4-7"},
		// Test Ignore case
		{ioType: IoEth, lookupName: "ETH7", expectedBundleName: "eth4-7"},
	}

	// Basic test
	for index := range testMatrix {
		entry := &testMatrix[index]
		ioBundle := aa.LookupIoBundleForMember(entry.ioType,
			entry.lookupName)
		if ioBundle == nil {
			if entry.expectedBundleName != "" {
				t.Errorf("Test Entry Index %d Failed: Null bundle. Expected %s\n",
					index, entry.expectedBundleName)
			}
		} else {
			if ioBundle.Name != entry.expectedBundleName {
				t.Errorf("Test Entry Index %d Failed: Expected %s, Actual: %s\n",
					index, entry.expectedBundleName, ioBundle.Name)
			}
		}
	}
	log.Infof("TestLookupIoBundleForMember: DONE\n")
}
