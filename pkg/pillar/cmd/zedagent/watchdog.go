// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Extract Watchdog information from files

package zedagent

import (
	"os"
)

const (
	//WatchdogDevicePath is the Watchdog device file path
	WatchdogDevicePath = "/dev/watchdog"
)

func getHardwareWatchdogPresent(ctx *zedagentContext) bool {
	_, err := os.Stat(WatchdogDevicePath)
	if err != nil {
		//No Watchdog found on this system
		return false
	}
	return true
}
