// Copyright (c) 2022,2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package dpcmanager

import (
	"reflect"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

type compressDPCLTestEntry struct {
	dpcl                 types.DevicePortConfigList
	enableLastResort     bool
	testingInProgress    bool
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
	return true
}

var testMatrix = map[string]compressDPCLTestEntry{
	// DPCL is not compressed when testing is in progress.
	"Testing in progress": {
		enableLastResort: true,
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
					TimePriority: time.Date(2000, 3, 1, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		testingInProgress:    true,
		expectedEntries:      []int{0, 1, 2},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry

	// CurrentIndex != 0
	// We used to not run compression in this case, but it can lead to an oversized DPCL.
	// We now compress the DPCL in this case as well.
	// The older failed "zedagent" DPC should be removed and CurrentIndex updated.
	"Current Index Not Zero": {
		enableLastResort: true,
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 2,
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
					TimePriority: time.Date(2000, 3, 2, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 1, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0, 2},
		expectedCurrentIndex: 1,
	}, // compressDPCLTestEntry

	// Empty DPCL, nothing to compress.
	"Empty DPCL": {
		enableLastResort: true,
		dpcl: types.DevicePortConfigList{
			CurrentIndex:   -1, // -1 is used by DPCManager in this case.
			PortConfigList: []types.DevicePortConfig{},
		}, // dpcl
		expectedEntries:      []int{},
		expectedCurrentIndex: -1,
	}, // compressDPCLTestEntry

	// First key is not Zedagent
	// Previously, we skipped compression in this case.
	// Now, we compress the DPCL regardless, to for example prevent a "manual" DPC (from TUI)
	// from blocking compression.
	// However, we always keep the latest DPC from the controller, even if it
	// does not currently provide working connectivity or has been manually overridden.
	"First Key Not Zedagent": {
		enableLastResort: true,
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 0,
			PortConfigList: []types.DevicePortConfig{
				{
					Version:      1,
					Key:          "manual",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 2, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed:    time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
						LastSucceeded: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 1, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0, 1},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry

	// First Entry Not working.
	// The latest DPC should never get compressed, even if it is not working.
	"First Entry Not working": {
		enableLastResort: true,
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
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0, 1},
		expectedCurrentIndex: 1,
	}, // compressDPCLTestEntry

	// With Last resort enabled
	"ValidZedEntry with last resort - Last resort is retained": {
		enableLastResort: true,
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 0,
			PortConfigList: []types.DevicePortConfig{
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      2,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      3,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 2, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // Retained
					Version:      5,
					Key:          "lastresort",
					TimePriority: time.Date(2000, 3, 1, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0, 3},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry

	// With Last resort disabled
	"ValidZedEntry with last resort but disabled - Last resort is removed": {
		enableLastResort: false,
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 0,
			PortConfigList: []types.DevicePortConfig{
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      2,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      3,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 2, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      5,
					Key:          "lastresort",
					TimePriority: time.Date(2000, 3, 1, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry

	// Without Last resort
	"ValidZedEntry without last resort": {
		enableLastResort: true,
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
					TimePriority: time.Date(2000, 3, 2, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      3,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 1, 0, 0, 0, 0, time.UTC),
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

	// The currently used DPC should never be removed, regardless of its state or position.
	// The latest DPC should never be removed, regardless of its state.
	// We should also preserve the newest working DPC, even if it's not currently used.
	// In this test, only the failed, non-latest, non-current "zedagent" DPC should be removed,
	// along with the "override" DPC since we have a working "zedagent" and do not need this
	// fallback option anymore.
	// It's also important to ensure that CurrentIndex is updated correctly.
	"Current, latest, and newest successful DPCs are preserved": {
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 2,
			PortConfigList: []types.DevicePortConfig{
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 5, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 5, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "manual",
					TimePriority: time.Date(2000, 3, 2, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      1,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 1, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0, 2, 3},
		expectedCurrentIndex: 1,
	}, // compressDPCLTestEntry

	// The latest network configuration received from the controller
	// should never be removed,
	// even if it does not currently provide working connectivity or
	// has been manually overridden.
	"Latest DPC from the controller is retained": {
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 0,
			PortConfigList: []types.DevicePortConfig{
				{
					Version:      1,
					Key:          "manual",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 2, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed:    time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
						LastSucceeded: time.Date(2000, 3, 2, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED
					Version:      1,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 1, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0, 1},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry

	// If no controller-provided DPC has ever succeeded in a connectivity test,
	// retain fallback options by keeping the most recent DPC from each source.
	"Keep DPC from every source": {
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 0,
			PortConfigList: []types.DevicePortConfig{
				{
					Version:      1,
					Key:          "manual",
					TimePriority: time.Date(2000, 3, 5, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // Delete this obsolete zedagent DPC
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
					Key:          "override",
					TimePriority: time.Date(2000, 3, 2, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{
					Version:      1,
					Key:          "lastresort",
					TimePriority: time.Date(2000, 3, 1, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0, 1, 3, 4},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry
}

func TestCompressDPCL(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)
	logrus.SetLevel(logrus.TraceLevel)

	for testname, test := range testMatrix {
		t.Logf("TESTCASE: %s - Running", testname)
		log.Tracef("======================TESTCASE: %s - Running============",
			testname)
		m := &DpcManager{
			dpcList:          test.dpcl,
			enableLastResort: test.enableLastResort,
			dpcVerify: dpcVerify{
				inProgress: test.testingInProgress,
			},
			Log: log,
		}
		m.compressDPCL()
		passed := test.checkDpclEqual(t, testname, m.dpcList)
		log.Tracef("======================TESTCASE: %s - DONE - Passed: %t "+
			"===============", testname, passed)
		t.Logf("TESTCASE: %s - Done", testname)
		if !passed {
			log.Tracef("Test Failed.. Stopping")
			break
		}
	}
}
