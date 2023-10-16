// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package agentlog

import (
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"os"
	"strings"
)

const (
	partitionFile = "/run/eve.id"
)

var (
	version   = "" // Cached value since it doesn't change on a running device
	partition = "" // Does not change on a running device
)

// EveVersion returns the version of the current image
func EveVersion() string {
	if version == "" {
		version = readEveVersion(types.EveVersionFile)
	}
	return version
}

func readEveVersion(fileName string) string {
	version, err := os.ReadFile(fileName)
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

// EveCurrentPartition returns the current EVE image partition
func EveCurrentPartition() string {
	if partition == "" {
		partition = readCurrentPartition(partitionFile)
	}
	return partition
}

func readCurrentPartition(fileName string) string {
	curpart, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Printf("readCurrentPartition: Error reading current partition from file %s",
			fileName)
		return "Unknown"
	}
	curpartStr := string(curpart)
	curpartStr = strings.TrimSpace(curpartStr)
	if curpartStr == "" {
		return "Unknown"
	}
	return curpartStr
}
