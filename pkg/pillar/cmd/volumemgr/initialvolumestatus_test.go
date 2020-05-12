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
	isContainer  bool
}

func TestParseAppRwVolumeName(t *testing.T) {
	testMatrix := map[string]appVolumeNameEntry{
		"Test lowercase SHA": {
			filename:     "/persist/img/EFA50C64CAACF8D43F334A05F8048F39A27FEA26FC1D155F2543D38D13176C17-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			dir:          "/persist/img",
			sha:          "EFA50C64CAACF8D43F334A05F8048F39A27FEA26FC1D155F2543D38D13176C17",
			appUUID:      "dfde839b-61f8-4df9-a840-d49cc0940d5c",
			purgeCounter: 0,
			isContainer:  false,
		},
		"Test lowercase SHA cont": {
			filename:     "/persist/img/EFA50C64CAACF8D43F334A05F8048F39A27FEA26FC1D155F2543D38D13176C17-dfde839b-61f8-4df9-a840-d49cc0940d5c",
			dir:          "/persist/img",
			sha:          "EFA50C64CAACF8D43F334A05F8048F39A27FEA26FC1D155F2543D38D13176C17",
			appUUID:      "dfde839b-61f8-4df9-a840-d49cc0940d5c",
			purgeCounter: 0,
			isContainer:  true,
		},
		"Test uppercase SHA": {
			filename:     "/persist/img/01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			dir:          "/persist/img",
			sha:          "01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848",
			appUUID:      "dfde839b-61f8-4df9-a840-d49cc0940d5c",
			purgeCounter: 0,
			isContainer:  false,
		},
		"Test uppercase SHA cont": {
			filename:     "/persist/img/01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848-dfde839b-61f8-4df9-a840-d49cc0940d5c",
			dir:          "/persist/img",
			sha:          "01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848",
			appUUID:      "dfde839b-61f8-4df9-a840-d49cc0940d5c",
			purgeCounter: 0,
			isContainer:  true,
		},
		"Test purgeCounter": {
			filename:     "/persist/img/01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848-dfde839b-61f8-4df9-a840-d49cc0940d5c#3.qcow2",
			dir:          "/persist/img",
			sha:          "01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848",
			appUUID:      "dfde839b-61f8-4df9-a840-d49cc0940d5c",
			purgeCounter: 3,
			isContainer:  false,
		},
		"Test purgeCounter cont": {
			filename:     "/persist/img/01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848-dfde839b-61f8-4df9-a840-d49cc0940d5c#3",
			dir:          "/persist/img",
			sha:          "01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848",
			appUUID:      "dfde839b-61f8-4df9-a840-d49cc0940d5c",
			purgeCounter: 3,
			isContainer:  true,
		},
		"Test No Dir": {
			filename: "01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			// We get return values of ""
			dir:          "",
			sha:          "",
			appUUID:      "",
			purgeCounter: 0,
			isContainer:  false,
		},
		"Test No Dir cont": {
			filename: "01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848-dfde839b-61f8-4df9-a840-d49cc0940d5c",
			// We get return values of ""
			dir:          "",
			sha:          "",
			appUUID:      "",
			purgeCounter: 0,
			isContainer:  true,
		},
		"Test Invalid Hash": {
			filename: "/persist/img/01434c4dK-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			// We get return values of ""
			dir:          "",
			sha:          "",
			appUUID:      "",
			purgeCounter: 0,
			isContainer:  false,
		},
		"Test Invalid Hash cont": {
			filename: "/persist/img/01434c4dK-dfde839b-61f8-4df9-a840-d49cc0940d5c",
			// We get return values of ""
			dir:          "",
			sha:          "",
			appUUID:      "",
			purgeCounter: 0,
			isContainer:  true,
		},
		"Test Invalid UUID": {
			filename: "/persist/img/01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848.qcow2",
			// We get return values of ""
			dir:          "",
			sha:          "",
			appUUID:      "",
			purgeCounter: 0,
			isContainer:  false,
		},
		"Test Invalid UUID cont": {
			filename: "/persist/img/01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848",
			// We get return values of ""
			dir:          "",
			sha:          "",
			appUUID:      "",
			purgeCounter: 0,
			isContainer:  true,
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		dir, sha, uuid, purgeCounter := parseAppRwVolumeName(test.filename, test.isContainer)
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
