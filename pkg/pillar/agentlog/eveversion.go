// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package agentlog

import (
	"fmt"
	"io/ioutil"
	"strings"
)

const versionFile = "/etc/eve-release"

var version = "" // Cached value since it doesn't change on a running device

// EveVersion returns the version of the current image
func EveVersion() string {
	if version == "" {
		version = readEveVersion(versionFile)
	}
	return version
}

func readEveVersion(fileName string) string {
	version, err := ioutil.ReadFile(fileName)
	if err != nil {
		// Note: can be called from log hook hence no log calls.
		fmt.Printf("readEveVersion: Error reading EVE version from file %s", fileName)
		return "Unknown"
	}
	versionStr := string(version)
	versionStr = strings.TrimSpace(versionStr)
	if versionStr == "" {
		return "Unknown"
	}
	return versionStr
}
