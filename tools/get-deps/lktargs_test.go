// Copyright(c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// Test_lktBuildArgs checks that pkglib's build args for a package are
// harvested. PKG_IMAGE is asserted exactly, since it is composed from
// build.yml's org and image keys and so pins that the right file was read;
// PKG_HASH is content-derived and only checked for presence.
func Test_lktBuildArgs(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		ymlPath   string
		wantImage string
	}{
		{
			name:      "pillar",
			ymlPath:   "../../pkg/pillar/build.yml",
			wantImage: "lfedge/eve-pillar",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buildArgs := lktBuildArgs(tt.ymlPath)
			if got := buildArgs["PKG_IMAGE"]; got != tt.wantImage {
				t.Errorf("lktBuildArgs() PKG_IMAGE = %q, want %q", got, tt.wantImage)
			}
			if buildArgs["PKG_HASH"] == "" {
				t.Errorf("lktBuildArgs() returned no PKG_HASH: %v", buildArgs)
			}
		})
	}
}
