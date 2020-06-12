// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"
)

type appVolumeNameEntry struct {
	filename          string
	dir               string
	volumeID          string
	generationCounter uint32
}

func TestParseAppRwVolumeName(t *testing.T) {
	testMatrix := map[string]appVolumeNameEntry{
		"Test VM volume with generation counter": {
			filename:          "/persist/img/dfde839b-61f8-4df9-a840-d49cc0940d5c#0",
			dir:               "/persist/img",
			volumeID:          "dfde839b-61f8-4df9-a840-d49cc0940d5c",
			generationCounter: 0,
		},
		"Test VM volume with incremented generation counter": {
			filename:          "/persist/img/dfde839b-61f8-4df9-a840-d49cc0940d5c#1",
			dir:               "/persist/img",
			volumeID:          "dfde839b-61f8-4df9-a840-d49cc0940d5c",
			generationCounter: 1,
		},
		"Test VM volume without generation counter": {
			filename:          "/persist/img/dfde839b-61f8-4df9-a840-d49cc0940d5c",
			dir:               "",
			volumeID:          "",
			generationCounter: 0,
		},
		"Test Container volume with generation counter": {
			filename:          "/persist/runx/pods/prepared/dfde839b-61f8-4df9-a840-d49cc0940d5c#0",
			dir:               "/persist/runx/pods/prepared",
			volumeID:          "dfde839b-61f8-4df9-a840-d49cc0940d5c",
			generationCounter: 0,
		},
		"Test Container volume with incremented generation counter": {
			filename:          "/persist/runx/pods/prepared/dfde839b-61f8-4df9-a840-d49cc0940d5c#1",
			dir:               "/persist/runx/pods/prepared",
			volumeID:          "dfde839b-61f8-4df9-a840-d49cc0940d5c",
			generationCounter: 1,
		},
		"Test Container volume without generation counter": {
			filename:          "/persist/runx/pods/prepared/dfde839b-61f8-4df9-a840-d49cc0940d5c",
			dir:               "",
			volumeID:          "",
			generationCounter: 0,
		},
		"Test No Dir": {
			filename: "dfde839b-61f8-4df9-a840-d49cc0940d5c#0",
			// We get return values of ""
			dir:               "",
			volumeID:          "",
			generationCounter: 0,
		},
		"Test Invalid UUID": {
			filename: "/persist/img/#0",
			// We get return values of ""
			dir:               "",
			volumeID:          "",
			generationCounter: 0,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		dir, uuid, generationCounter := parseAppRwVolumeName(test.filename)
		if dir != test.dir {
			t.Errorf("dir ( %s ) != Expected value ( %s )", dir, test.dir)
		}
		if uuid != test.volumeID {
			t.Errorf("uuid ( %s ) != Expected value ( %s )", uuid, test.volumeID)
		}
		if generationCounter != test.generationCounter {
			t.Errorf("generationCounter ( %d ) != Expected value ( %d )", generationCounter, test.generationCounter)
		}
	}
}
