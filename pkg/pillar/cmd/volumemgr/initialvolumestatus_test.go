// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"testing"
)

type appVolumeNameEntry struct {
	filename     string
	dir          string
	sha          string
	appUUID      string
	purgeCounter uint32
	imageFormat  string
}

func TestParseAppRwVolumeName(t *testing.T) {
	testMatrix := map[string]appVolumeNameEntry{
		"Test lowercase SHA": {
			filename:     "/persist/img/EFA50C64CAACF8D43F334A05F8048F39A27FEA26FC1D155F2543D38D13176C17-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			dir:          "/persist/img",
			sha:          "EFA50C64CAACF8D43F334A05F8048F39A27FEA26FC1D155F2543D38D13176C17",
			appUUID:      "dfde839b-61f8-4df9-a840-d49cc0940d5c",
			purgeCounter: 0,
		},
		"Test uppercase SHA": {
			filename:     "/persist/img/01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			dir:          "/persist/img",
			sha:          "01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848",
			appUUID:      "dfde839b-61f8-4df9-a840-d49cc0940d5c",
			purgeCounter: 0,
		},
		"Test purgeCounter": {
			filename:     "/persist/img/01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848-dfde839b-61f8-4df9-a840-d49cc0940d5c#3.qcow2",
			dir:          "/persist/img",
			sha:          "01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848",
			appUUID:      "dfde839b-61f8-4df9-a840-d49cc0940d5c",
			purgeCounter: 3,
		},
		"Test No Dir": {
			filename: "01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			// We get return values of ""
			dir:          "",
			sha:          "",
			appUUID:      "",
			purgeCounter: 0,
		},
		"Test Invalid Hash": {
			filename: "/persist/img/01434c4dK-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			// We get return values of ""
			dir:          "",
			sha:          "",
			appUUID:      "",
			purgeCounter: 0,
		},
		"Test Invalid UUID": {
			filename: "/persist/img/01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848.qcow2",
			// We get return values of ""
			dir:          "",
			sha:          "",
			appUUID:      "",
			purgeCounter: 0,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		dir, sha, uuid, purgeCounter := parseAppRwVolumeName(test.filename)
		if dir != test.dir {
			t.Errorf("dir ( %s ) != Expected value ( %s )", dir, test.dir)
		}
		if sha != test.sha {
			t.Errorf("sha ( %s ) != Expected value ( %s )", sha, test.sha)
		}
		if uuid != test.appUUID {
			t.Errorf("uuid ( %s ) != Expected value ( %s )", uuid, test.appUUID)
		}
		if purgeCounter != test.purgeCounter {
			t.Errorf("purgeCounter ( %d ) != Expected value ( %d )", purgeCounter, test.purgeCounter)
		}
	}
}
