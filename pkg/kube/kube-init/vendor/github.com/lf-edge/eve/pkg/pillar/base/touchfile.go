// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"os"
	"time"
)

const (
	// WatchdogFileDir is the dir to add .touch files for watchdog to monitor
	WatchdogFileDir = "/run/watchdog/file"
	// WatchdogPidDir is the dir to add .pid files for watchdog to monitor
	WatchdogPidDir = "/run/watchdog/pid"
)

// TouchFile touches the given file
func TouchFile(log *LogObject, filename string) {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_SYNC, 0755)
		if err != nil {
			log.Fatalf("TouchFile: Failed touching file %s with err: %s", filename, err)
		}
		defer file.Close()
	} else {
		currentTime := time.Now()
		err = os.Chtimes(filename, currentTime, currentTime)
		if err != nil {
			log.Fatalf("TouchFile: Failed touching file %s with err: %s", filename, err)
		}
	}
}
