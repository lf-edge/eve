// Copyright(c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func Test_lktBuildArgs(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		ymlPath string
		want    map[string]struct{}
	}{
		{
			name:    "pillar",
			ymlPath: "../../pkg/pillar/build.yml",
			want: map[string]struct{}{
				"REL_HASH_LFEDGE_EVE_GRUB":                {},
				"REL_HASH_LFEDGE_EVE_EXTERNAL_BOOT_IMAGE": {},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buildArgs := lktBuildArgs(tt.ymlPath)
			for buildArg := range tt.want {
				_, found := buildArgs[buildArg]
				if !found {
					t.Errorf("lktBuildArgs() = %v, want %v", buildArgs, tt.want)
				}
			}
		})
	}
}
