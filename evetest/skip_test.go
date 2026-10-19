// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"testing"

	"github.com/lf-edge/eve/evetest/constants"
	"github.com/spf13/viper"
)

func TestMatchedSkipName(t *testing.T) {
	defer viper.Set(constants.SkipEnv, "")

	cases := []struct {
		descr       string
		skipEnv     string
		names       []string
		wantMatched string
		wantSkip    bool
	}{
		{
			descr:    "unset",
			skipEnv:  "",
			names:    []string{"TestBootstrapWithProxy"},
			wantSkip: false,
		},
		{
			descr:       "own name listed",
			skipEnv:     "TestBootstrapWithAutoDiscoveredProxy,TestControllerFaultsSuite",
			names:       []string{"TestBootstrapWithAutoDiscoveredProxy", "TestBootstrapWithProxy"},
			wantMatched: "TestBootstrapWithAutoDiscoveredProxy",
			wantSkip:    true,
		},
		{
			descr:       "parent name listed",
			skipEnv:     "TestBootstrapWithProxy",
			names:       []string{"TestBootstrapWithAutoDiscoveredProxy", "TestBootstrapWithProxy"},
			wantMatched: "TestBootstrapWithProxy",
			wantSkip:    true,
		},
		{
			descr:    "unrelated variant of the same parent stays unaffected",
			skipEnv:  "TestBootstrapWithManualProxyConfig",
			names:    []string{"TestBootstrapWithAutoDiscoveredProxy", "TestBootstrapWithProxy"},
			wantSkip: false,
		},
		{
			descr:       "whitespace and empty entries are tolerated",
			skipEnv:     " TestFoo ,, TestBar",
			names:       []string{"TestBar"},
			wantMatched: "TestBar",
			wantSkip:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.descr, func(t *testing.T) {
			viper.Set(constants.SkipEnv, tc.skipEnv)
			matched, skip := matchedSkipName(tc.names...)
			if skip != tc.wantSkip || (skip && matched != tc.wantMatched) {
				t.Fatalf("matchedSkipName(%v) with %s=%q = (%q, %v), want (%q, %v)",
					tc.names, constants.SkipEnv, tc.skipEnv, matched, skip, tc.wantMatched, tc.wantSkip)
			}
		})
	}
}
