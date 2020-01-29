// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Manage Xen guest domains based on the subscribed collection of DomainConfig
// and publish the result in a collection of DomainStatus structs.
// We run a separate go routine for each domU to be able to boot and halt
// them concurrently and also pick up their state periodically.

package domainmgr

import (
	"testing"
)

type appImageNameEntry struct {
	filename    string
	dir         string
	sha         string
	appUUID     string
	imageFormat string
}

func TestParseAppRwImageName(t *testing.T) {
	testMatrix := map[string]appImageNameEntry{
		"Test owercase SHA": {
			filename: "/persist/img/EFA50C64CAACF8D43F334A05F8048F39A27FEA26FC1D155F2543D38D13176C17-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			dir:      "/persist/img",
			sha:      "EFA50C64CAACF8D43F334A05F8048F39A27FEA26FC1D155F2543D38D13176C17",
			appUUID:  "dfde839b-61f8-4df9-a840-d49cc0940d5c",
		},
		"Test uppercase SHA": {
			filename: "/persist/img/01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			dir:      "/persist/img",
			sha:      "01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848",
			appUUID:  "dfde839b-61f8-4df9-a840-d49cc0940d5c",
		},
		"Test No Dir": {
			filename: "01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			// We get return values of ""
			dir:     "",
			sha:     "",
			appUUID: "",
		},
		"Test Invalid Hash": {
			filename: "/persist/img/01434c4dK-dfde839b-61f8-4df9-a840-d49cc0940d5c.qcow2",
			// We get return values of ""
			dir:     "",
			sha:     "",
			appUUID: "",
		},
		"Test Invalid UUID": {
			filename: "/persist/img/01434c4de5e7646dbaf026fe8c522e637a298daa2af71bd1dade03826d442848.qcow2",
			// We get return values of ""
			dir:     "",
			sha:     "",
			appUUID: "",
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		dir, sha, uuid := parseAppRwImageName(test.filename)
		if dir != test.dir {
			t.Errorf("dir ( %s ) != Expected value ( %s )", dir, test.dir)
		}
		if sha != test.sha {
			t.Errorf("sha ( %s ) != Expected value ( %s )", sha, test.sha)
		}
		if uuid != test.appUUID {
			t.Errorf("uuid ( %s ) != Expected value ( %s )", uuid, test.appUUID)
		}
	}
}
