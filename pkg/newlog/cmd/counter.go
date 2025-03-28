// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/lf-edge/eve-api/go/logs"
)

var (
	// logsToCount is a list of Filename fields (src file + line number) of log entries that should be counted.
	logsToCount atomic.Value

	counterSuppressedLogs = 0
)

func countLogsInFile(file *os.File) map[string]int {
	logCounter := make(map[string]int)
	for _, logSrcLine := range logsToCount.Load().([]string) {
		logCounter[logSrcLine] = 0
	}
	preScanner := bufio.NewScanner(file)
	for preScanner.Scan() {
		var logEntry logs.LogEntry
		// we ignore the errors here, they might be coming from non-json lines like the metadata line
		_ = json.Unmarshal(preScanner.Bytes(), &logEntry)

		if currentCount, ok := logCounter[logEntry.Filename]; ok {
			logCounter[logEntry.Filename] = currentCount + 1
		}
	}
	if err := preScanner.Err(); err != nil {
		log.Errorf("Error scanning file for log occurrence count: %v", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		log.Errorf("Failed to reset file pointer: %v", err)
	}
	return logCounter
}

// addLogCount updates the log entry with a count tag based on the occurrence count
// provided in the filterMap, and manages suppression of duplicate log entries.
// It returns true if the log entry should be included in the output and false if it should be suppressed.
func addLogCount(logEntry *logs.LogEntry, filterMap map[string]int) bool {
	count, ok := filterMap[logEntry.Filename]
	if !ok {
		return true
	}

	if count == 0 {
		// the count was already included in another entry
		counterSuppressedLogs++
		return false
	}

	if count == 1 {
		// no need to add additional count field if there is only one occurrence
		return true
	}

	if logEntry.Tags == nil {
		logEntry.Tags = make(map[string]string)
	}
	logEntry.Tags["count"] = fmt.Sprint(count)

	// mark the log entry as counted
	filterMap[logEntry.Filename] = 0

	return true
}
