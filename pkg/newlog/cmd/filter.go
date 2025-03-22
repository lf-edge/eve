// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"sync/atomic"

	"github.com/lf-edge/eve-api/go/logs"
)

var (
	filenameFilter atomic.Value // map[filename+line]nothing

	filterSuppressedLogs = 0
)

// filterOut checks if the log entry should be filtered out
// based on the filename or severity + function name
func filterOut(l *logs.LogEntry) bool {
	if _, ok := filenameFilter.Load().(map[string]any)[l.Filename]; ok {
		filterSuppressedLogs++
		return true
	}

	return false
}
