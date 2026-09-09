// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"strings"

	"github.com/lf-edge/eve/evetest/constants"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/spf13/viper"
)

// skippedTestNames returns the list of test/suite names listed in
// EVETEST_SKIP, or nil if the variable is unset or empty.
func skippedTestNames() []string {
	raw := viper.GetString(constants.SkipEnv)
	if raw == "" {
		return nil
	}
	var names []string
	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// matchedSkipName reports whether any of the given names is listed in
// EVETEST_SKIP, and if so, which one. A suite variant's own name and its
// parent test function's name (see testState.parentName) are both valid
// matches; matching on the parent skips every variant at once.
func matchedSkipName(names ...string) (matched string, skip bool) {
	skipped := skippedTestNames()
	for _, name := range names {
		if name != "" && generics.ContainsItem(skipped, name) {
			return name, true
		}
	}
	return "", false
}
