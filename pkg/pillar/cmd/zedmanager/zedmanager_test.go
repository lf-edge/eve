// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Get AppInstanceConfig from zedagent, drive config to VolumeMgr,
// IdentityMgr, and Zedrouter. Collect status from those services and make
// the combined AppInstanceStatus available to zedagent.

package zedmanager

import (
	"testing"
)

func TestMaybeInsertSha(t *testing.T) {
	type insertSHA struct {
		imageName         string
		imageSHA          string
		expectedImageName string
	}
	testInsertSHA := map[string]insertSHA{
		"No tag in image name": {
			imageName:         "docker.io/library/alpine",
			imageSHA:          "de78803598bc4c940fc4591d412bffe488205d5d953f94751c6308deeaaa7eb8",
			expectedImageName: "docker.io/library/alpine@sha256:de78803598bc4c940fc4591d412bffe488205d5d953f94751c6308deeaaa7eb8",
		},
		"Latest tag in image name": {
			imageName:         "alpine:latest",
			imageSHA:          "de78803598bc4c940fc4591d412bffe488205d5d953f94751c6308deeaaa7eb8",
			expectedImageName: "alpine@sha256:de78803598bc4c940fc4591d412bffe488205d5d953f94751c6308deeaaa7eb8",
		},
		"Specific tag in image name": {
			imageName:         "alpine:3.10",
			imageSHA:          "de78803598bc4c940fc4591d412bffe488205d5d953f94751c6308deeaaa7eb8",
			expectedImageName: "alpine@sha256:de78803598bc4c940fc4591d412bffe488205d5d953f94751c6308deeaaa7eb8",
		},
	}
	for testname, test := range testInsertSHA {
		t.Logf("Running test case %s", testname)
		output := maybeInsertSha(test.imageName, test.imageSHA)
		if output != test.expectedImageName {
			t.Errorf("Image name ( %v ) != Expected name ( %v )", output, test.expectedImageName)
		}
	}
}
