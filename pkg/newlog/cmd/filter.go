package main

import (
	"slices"

	"github.com/lf-edge/eve-api/go/logs"
)

var (
	// those structures need to support concurrency since they will be set in a different goroutine
	filenameFilter            = make(map[string]any)      // map[filename+line]nothing
	severityAndFunctionFilter = make(map[string][]string) // map[function]severities
)

// filterOut checks if the log entry should be filtered out
// based on the filename or severity + function name
func filterOut(l *logs.LogEntry) bool {
	if _, ok := filenameFilter[l.Filename]; ok {
		return false
	}

	if severityList, ok := severityAndFunctionFilter[l.Function]; ok {
		if slices.Contains(severityList, l.Severity) {
			return false
		}
	}

	return true
}
