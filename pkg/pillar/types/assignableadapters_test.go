// Copyright (c) 2019 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var aa AssignableAdapters = AssignableAdapters{
	Initialized: true,
	IoBundleList: []IoBundle{
		{
			Type:    IoEth,
			Name:    "eth0-1",
			Members: []string{"eth0", "eth1"},
			Lookup:  true,
		},
		{
			Type:    IoEth,
			Name:    "eth2",
			Members: []string{"eth2"},
			Lookup:  true,
		},
		{
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
	testMatrix := map[string]struct {
		ioType             IoType
		lookupName         string
		expectedBundleName string
	}{
		"IoType: IoEth, LookupName: eth0-1": {
			ioType:             IoEth,
			lookupName:         "eth0-1",
			expectedBundleName: "eth0-1",
		},
		"IoType: IoUSB LookupName: eth2": {
			ioType:             IoUSB,
			lookupName:         "eth2",
			expectedBundleName: "",
		},
		"IoType: IoEth LookupName: eth1": {
			ioType:             IoEth,
			lookupName:         "eth1",
			expectedBundleName: "",
		},
		"IoType: IoEth LookupName: eth2": {
			ioType:             IoEth,
			lookupName:         "eth2",
			expectedBundleName: "eth2",
		},
		"IoType: IoEth LookupName: eth4-7": {
			ioType:             IoEth,
			lookupName:         "eth4-7",
			expectedBundleName: "eTH4-7",
		},
	}

	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		ioBundle := LookupIoBundle(&aa, test.ioType, test.lookupName)
		if ioBundle == nil {
			assert.Equal(t, test.expectedBundleName, "")
		} else {
			assert.Equal(t, test.expectedBundleName, ioBundle.Name)
		}
	}
}

func TestLookupIoBundleForMember(t *testing.T) {
	testMatrix := map[string]struct {
		ioType             IoType
		lookupName         string
		expectedBundleName string
	}{
		"ioType: IoEth, lookupName: eth1": {
			ioType: IoEth,
			lookupName: "eth1",
			expectedBundleName: "eth0-1",
		},
		// Type should also be considered.
		"ioType: IoUSB, lookupName: eth1": {
			ioType: IoUSB,
			lookupName: "eth1",
			expectedBundleName: "",
		},
		"ioType: IoEth, lookupName: eth3": {
			ioType: IoEth,
			lookupName: "eth3",
			expectedBundleName: "",
			}, // No such member
		"ioType: IoEth, lookupName: eth7": {
			ioType: IoEth,
			lookupName: "eth7",
			expectedBundleName: "eTH4-7",
		},
		// Test Ignore case
		"ioType: IoEth, lookupName: ETH7": {
			ioType: IoEth,
			lookupName: "ETH7",
			 expectedBundleName: "eTH4-7",
		 },
	}

	// Basic test
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		ioBundle := aa.LookupIoBundleForMember(test.ioType, test.lookupName)
		if ioBundle == nil {
			assert.Equal(t, test.expectedBundleName, "")
		} else {
			assert.Equal(t, test.expectedBundleName, ioBundle.Name)
		}
	}
}
