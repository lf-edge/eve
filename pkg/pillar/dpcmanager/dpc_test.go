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
	// In this test, the failed, non-latest, non-current "zedagent" DPC is removed,
	// along with the "override" DPC since we have a working "zedagent" and do not need this
	// fallback option anymore. The "manual" DPC is also removed even though it itself
	// succeeded, because a higher-priority "zedagent" DPC already worked.
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
				{ // DELETED
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
		expectedEntries:      []int{0, 2},
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

	// Once a higher-priority (more recent) DPC has provided working
	// connectivity, the "manual" DPC is no longer unconditionally retained,
	// even if the manual DPC itself also worked at some point.
	"Manual DPC dropped once a higher-priority DPC has worked": {
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 0,
			PortConfigList: []types.DevicePortConfig{
				{ // Retained: latest DPC and the one providing working connectivity.
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 5, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 5, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED: manual DPC, even though it itself succeeded once,
					// is no longer needed since a higher-priority DPC already works.
					Version:      1,
					Key:          "manual",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 2, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry

	// A "manual" DPC that is itself the highest-priority DPC that has ever
	// worked is preserved - not because of the manual-specific rule, but
	// because it is the most recent DPC with working connectivity.
	"Self-working manual DPC retained when it is the highest-priority DPC that ever worked": {
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 0,
			PortConfigList: []types.DevicePortConfig{
				{ // Retained: latest DPC. Currently failing, but succeeded in the
					// past, so it is not itself "the DPC with working connectivity".
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 5, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed:    time.Date(2000, 3, 5, 0, 0, 0, 0, time.UTC),
						LastSucceeded: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // Retained: manual DPC never failed, so it is the highest-priority
					// DPC with working connectivity.
					Version:      1,
					Key:          "manual",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 2, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // DELETED: never worked and controller DPC has succeeded, so no
					// need to retain a fallback option from every source.
					Version:      1,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 1, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 1, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0, 1},
		expectedCurrentIndex: 0,
	}, // compressDPCLTestEntry

	// The manual-specific retention rule is not redundant with the generic
	// "keep one DPC per source while the controller has never worked" rule.
	// That generic rule is keyed off controllerDPCWorked, which is true as
	// soon as *any* "zedagent" entry anywhere in the list has ever
	// succeeded, regardless of how old or low-priority it now is. Here an
	// old, lower-priority "zedagent" DPC once worked, so controllerDPCWorked
	// is true and the generic rule no longer protects "manual". But nothing
	// *higher-priority* than "manual" has ever worked, so the manual-specific
	// rule (based on retainedWorkingDPC, not controllerDPCWorked) must be the
	// one keeping it - without it, "manual" would be dropped immediately even
	// though it hasn't been superseded by anything more recent.
	"Manual DPC retained despite an old lower-priority DPC having worked": {
		dpcl: types.DevicePortConfigList{
			CurrentIndex: 2, // manager fell back to the working "zedagent" DPC
			PortConfigList: []types.DevicePortConfig{
				{ // Retained: latest DPC, never worked.
					Version:      1,
					Key:          "override",
					TimePriority: time.Date(2000, 3, 5, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 5, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // Retained: manual DPC, currently failing and never worked itself,
					// but nothing higher-priority than it has worked either.
					Version:      1,
					Key:          "manual",
					TimePriority: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastFailed: time.Date(2000, 3, 4, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
				{ // Retained: currently used DPC, and the only one that has ever
					// worked, even though it is the lowest priority (oldest) entry.
					Version:      1,
					Key:          "zedagent",
					TimePriority: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					TestResults: types.TestResults{
						LastSucceeded: time.Date(2000, 3, 3, 0, 0, 0, 0, time.UTC),
					},
					Ports: []types.NetworkPortConfig{},
				},
			}, // PortConfigList
		}, // dpcl
		expectedEntries:      []int{0, 1, 2},
		expectedCurrentIndex: 2,
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

func TestHigherPriority(t *testing.T) {
	older := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC)

	zedagentOlder := types.DevicePortConfig{Key: types.ControllerDPCKey, TimePriority: older}
	zedagentNewer := types.DevicePortConfig{Key: types.ControllerDPCKey, TimePriority: newer}
	manualOlder := types.DevicePortConfig{Key: types.ManualDPCKey, TimePriority: older}
	overrideOlder := types.DevicePortConfig{Key: "override", TimePriority: older}
	overrideNewer := types.DevicePortConfig{Key: "override", TimePriority: newer}

	// An incoming "manual" DPC always takes effect immediately, even with
	// an older timestamp than what is already in the list.
	if !higherPriority(manualOlder, zedagentNewer) {
		t.Error("expected incoming manual to always outrank an existing zedagent")
	}
	if !higherPriority(manualOlder, overrideNewer) {
		t.Error("expected incoming manual to always outrank an existing override")
	}

	// An incoming "zedagent" DPC always outranks an existing non-"zedagent"
	// one, regardless of timestamp - even an older zedagent outranks a
	// newer override.
	if !higherPriority(zedagentOlder, overrideNewer) {
		t.Error("expected older zedagent to structurally outrank newer override")
	}

	// Among multiple "zedagent" DPCs, timestamp still decides.
	if !higherPriority(zedagentNewer, zedagentOlder) {
		t.Error("expected newer zedagent to outrank older zedagent")
	}
	if higherPriority(zedagentOlder, zedagentNewer) {
		t.Error("expected older zedagent to not outrank newer zedagent")
	}

	// Two "override" DPCs (neither manual nor controller) still fall back
	// to plain timestamp comparison.
	if !higherPriority(overrideNewer, overrideOlder) {
		t.Error("expected newer override to outrank older override")
	}
	if higherPriority(overrideOlder, overrideNewer) {
		t.Error("expected older override to not outrank newer override")
	}
}

// usableDPC returns a DPC with a single usable management port, so
// IsDPCTestable's IsDPCUsable() check passes and only the DPC's own
// TestResults determine testability.
func usableDPC(key string, timePriority time.Time, testResults types.TestResults) types.DevicePortConfig {
	return types.DevicePortConfig{
		Key:          key,
		TimePriority: timePriority,
		TestResults:  testResults,
		Ports: []types.NetworkPortConfig{
			{
				IfName:     "eth0",
				IsMgmt:     true,
				DhcpConfig: types.DhcpConfig{Dhcp: types.DhcpTypeClient},
			},
		},
	}
}

func TestGetNextTestableDPCIndexCapsAtManual(t *testing.T) {
	log := base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)
	now := time.Now()

	// No manual DPC present: behavior is unchanged - the search can reach an
	// index that would be "past" a manual DPC if one existed.
	m := &DpcManager{
		Log:                    log,
		DpcMinTimeSinceFailure: time.Minute,
		dpcList: types.DevicePortConfigList{
			PortConfigList: []types.DevicePortConfig{
				usableDPC("zedagent", now, types.TestResults{LastFailed: now}),
				usableDPC("override", now.Add(-time.Hour), types.TestResults{}), // untested
			},
		},
	}
	if idx := m.getNextTestableDPCIndex(1); idx != 1 {
		t.Errorf("expected index 1 to be testable without a manual DPC present, got %d", idx)
	}

	// Manual DPC present at index 1, itself not testable (recent failure);
	// nothing else within [0, 1] is testable either (index 0 also recently
	// failed) - must never fall through to index 2 (below manual), even
	// though it would otherwise be testable (untested).
	m = &DpcManager{
		Log:                    log,
		DpcMinTimeSinceFailure: time.Minute,
		dpcList: types.DevicePortConfigList{
			PortConfigList: []types.DevicePortConfig{
				usableDPC("zedagent", now, types.TestResults{LastFailed: now}),
				usableDPC(types.ManualDPCKey, now.Add(-time.Hour), types.TestResults{LastFailed: now}),
				usableDPC("override", now.Add(-2*time.Hour), types.TestResults{}), // untested
			},
		},
	}
	if idx := m.getNextTestableDPCIndex(1); idx != -1 {
		t.Errorf("expected no testable index within manual's bound, got %d", idx)
	}

	// Manual DPC present and itself testable (untested): a search starting
	// at or before it should find it, but never advance past it.
	m = &DpcManager{
		Log:                    log,
		DpcMinTimeSinceFailure: time.Minute,
		dpcList: types.DevicePortConfigList{
			PortConfigList: []types.DevicePortConfig{
				usableDPC("zedagent", now, types.TestResults{LastFailed: now}),
				usableDPC(types.ManualDPCKey, now.Add(-time.Hour), types.TestResults{}), // untested
				usableDPC("override", now.Add(-2*time.Hour), types.TestResults{}),       // untested
			},
		},
	}
	if idx := m.getNextTestableDPCIndex(1); idx != 1 {
		t.Errorf("expected search to find manual itself (index 1), got %d", idx)
	}
}
