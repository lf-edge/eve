// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage Xen guest domains based on the subscribed collection of DomainConfig
// and publish the result in a collection of DomainStatus structs.
// We run a separate go routine for each domU to be able to boot and halt
// them concurrently and also pick up their state periodically.

package devicenetwork

import (
	"reflect"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	log "github.com/sirupsen/logrus"
)

type compressDPCLTestEntry struct {
	dpcl                 types.DevicePortConfigList
	pendingInProgress    bool
	expectedEntries      []int
	expectedCurrentIndex int
}

func (testEntry compressDPCLTestEntry) checkDpclEqual(
	t *testing.T, testname string,
	dpcl types.DevicePortConfigList) bool {
	expectedDpcl := types.DevicePortConfigList{}
	expectedDpcl.CurrentIndex = testEntry.expectedCurrentIndex
	expectedDpcl.PortConfigList = make([]types.DevicePortConfig, 0)
	for _, num := range testEntry.expectedEntries {
		expectedDpcl.PortConfigList = append(expectedDpcl.PortConfigList,
			testEntry.dpcl.PortConfigList[num])
	}
	if testEntry.expectedCurrentIndex != dpcl.CurrentIndex {
		t.Errorf("TEST CASE %s FAILED - "+
			"testEntry.expectedCurrentIndex(%d) != dpcl.CurrentIndex(%d)\n"+
			"dpcl: %+v\nexpectedDpcl: %+v",
			testname, testEntry.expectedCurrentIndex, dpcl.CurrentIndex,
			dpcl, expectedDpcl)
		return false
	}
	if len(dpcl.PortConfigList) != len(expectedDpcl.PortConfigList) {
		t.Errorf("TEST CASE %s FAILED - Unequal PortConfigList lengths\n"+
			"len(dpcl) (%d) != len(expectedDpcl) (%d)\n"+
			"dpcl: %+v\nexpectedDpcl: %+v",
			testname, len(dpcl.PortConfigList),
			len(expectedDpcl.PortConfigList), dpcl, expectedDpcl)
		return false
	}

	// Check each entry
	for indx, dpc := range dpcl.PortConfigList {
		expectedDpc := expectedDpcl.PortConfigList[indx]
		if !reflect.DeepEqual(dpc, expectedDpc) {
			t.Errorf("TEST CASE %s FAILED - Index: %d, "+
				"dpc != expectedDpc\n"+
				"dpc: %+v\nexpectedDpc: %+v",
				testname, indx, dpc, expectedDpc)
			return false
		}
	}
	if !reflect.DeepEqual(dpcl, expectedDpcl) {
		t.Errorf("TEST CASE %s FAILED - dpcl != expectedDpcl\n"+
			"dpcl: %+v\nexpectedDpcl: %+v",
			testname, dpcl, expectedDpcl)
		return false
	}
	return true
}

var testMatrix = map[string]compressDPCLTestEntry{
	"Pending in progress": {
		// DPCL is not compressed
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 0,
			PortConfigList: []types.DevicePortConfig{
				{ // Successful Zedagent Entry
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // Successful ZedAgent Entry
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 2, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // lastresort - NOT DELETED
					Version:      1,
					Key:          "lastresort",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // Unknown Key
					Version:      1,
					Key:          "hardware",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		pendingInProgress:    true,
		expectedEntries:      []int{0, 1, 2, 3},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry

	// CurrentIndex != 0 - None of the entries are deleted.
	"Current Index Not Zero": {
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 1,
			PortConfigList: []types.DevicePortConfig{
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "hardware",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0, 1, 2, 3},
		expectedCurrentIndex: 1,
	}, // compressDPCLTestEntry

	// Empty DPCL
	"Empty DPCL": {
		dpcl: types.DevicePortConfigList{
			CurrentIndex:   0,
			PortConfigList: []types.DevicePortConfig{},
		}, // dpcl
		expectedEntries:      []int{},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry

	// First Key Not Zedagent - No compression
	"First Key Not Zedagent": {
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 0,
			PortConfigList: []types.DevicePortConfig{
				{
					Version:      1,
					Key:          "lastresort",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "hardware",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0, 1, 2, 3},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry

	// First Entry Not working
	"First Entry Not working": {
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 0,
			PortConfigList: []types.DevicePortConfig{
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "hardware",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0, 1, 2, 3},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry

	// With Last resort
	"ValidZedEntry with last resort - Last resort is retained": {
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 0,
			PortConfigList: []types.DevicePortConfig{
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      2,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      3,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      4,
					Key:          "hardware",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // Retained
					Version:      5,
					Key:          "lastresort",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0, 4},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry

	// Without Last resort
	"ValidZedEntry without last resort": {
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 0,
			PortConfigList: []types.DevicePortConfig{
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      2,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      3,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      4,
					Key:          "hardware",
					TimePriority: time.Date(2000, 3, 0, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry
}

func TestCompressDPCL(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	for testname, test := range testMatrix {
		t.Logf("TESTCASE: %s - Running", testname)
		log.Debugf("======================TESTCASE: %s - Running============",
			testname)
		ctx := DeviceNetworkContext{
			DevicePortConfigList: &test.dpcl,
			Pending: DPCPending{
				Inprogress: test.pendingInProgress,
			},
		}
		dpcl := compressDPCL(&ctx)
		passed := test.checkDpclEqual(t, testname, dpcl)
		log.Debugf("======================TESTCASE: %s - DONE - Passed: %t "+
			"===============", testname, passed)
		t.Logf("TESTCASE: %s - Done", testname)
		if !passed {
			log.Debugf("Test Failed.. Stopping")
			break
		}
	}
}
