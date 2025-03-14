package main

import (
	"encoding/json"
	"fmt"

	"github.com/lf-edge/eve-api/go/logs"
)

// logsToCount is a list of Filename fields (src file + line number) of log entries that should be counted.
var logsToCount []string

// countLogOccurances checks if the log entries should be merged into a single entry with a counter of occurances.
// If so it increments the counter for that log entry. It returns true if the log entry
// should be kept in the logs file (log's first occurance) and false otherwise.
func countLogOccurances(line []byte, filterMap map[string]int) error {
	var logEntry logs.LogEntry
	if err := json.Unmarshal(line, &logEntry); err != nil {
		return err
	}

	if currentCount, ok := filterMap[logEntry.Filename]; ok {
		filterMap[logEntry.Filename] = currentCount + 1
	}

	return nil
}

// addLogCount adds the count of the log entry to the log entry and returns the log entry as a byte array.
// If the log entry is not supposed to be counted, it's returned without any changes.
// If the log entry count was already included in another entry, the function returns nil, meaning the log entry should be skipped (not written to the logs file).
func addLogCount(logEntry *logs.LogEntry, filterMap map[string]int) bool {
	if count, ok := filterMap[logEntry.Filename]; !ok {
		return true
	} else {
		if count == 0 {
			// the count was already included in another entry
			return false
		}

		if count == 1 {
			// no need to add additional count field if there is only one occurance
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
}
