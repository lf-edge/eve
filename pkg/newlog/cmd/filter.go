package main

import (
	"sync/atomic"

	"github.com/lf-edge/eve-api/go/logs"
)

var (
	// those structures need to support concurrency since they will be set in a different goroutine
	filenameFilter            atomic.Value                // map[filename+line]nothing
	severityAndFunctionFilter = make(map[string][]string) // map[function]severities
)

// filterOut checks if the log entry should be filtered out
// based on the filename or severity + function name
func filterOut(l *logs.LogEntry) bool {
	if _, ok := filenameFilter.Load().(map[string]any)[l.Filename]; ok {
		return true
	}

	if severityList, ok := severityAndFunctionFilter[l.Function]; ok {
		for _, severity := range severityList {
			if severity == l.Severity {
				return true
			}
		}
	}

	return false
}
