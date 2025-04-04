// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"container/ring"
	"encoding/json"
	"sync/atomic"

	"github.com/lf-edge/eve-api/go/logs"
)

var dedupWindowSize atomic.Uint32

func init() {
	dedupWindowSize.Store(0)
}

type containsMsg struct {
	Msg string `json:"msg"`
}

var numDedupedLogs = 0

// dedupLogEntry returns a boolean indicating whether the log entry should be used and the updated queue.
// It can be used to deduplicate logs based on the content of a file
func dedupLogEntry(logEntry *logs.LogEntry, seen map[string]uint64, queue *ring.Ring) (bool, *ring.Ring) {
	useEntry := true

	// No queue means no deduplication.
	if queue == nil {
		return useEntry, queue
	}

	dedupField := ""
	// If logEntry.content is a valid JSON, extract the field "msg" from it.
	if logEntry.Content != "" {
		var content containsMsg
		err := json.Unmarshal([]byte(logEntry.Content), &content)
		if err == nil && content.Msg != "" {
			dedupField = content.Msg
		} else {
			dedupField = logEntry.Content
		}
	}

	// If the file hasn't appeared in the last bufferSize logs, forward it.
	if _, ok := seen[dedupField]; ok && logEntry.Severity == "error" {
		useEntry = false
		log.Tracef("Deduped log id %d because of the log id %d\n", logEntry.Msgid, seen[dedupField])
		numDedupedLogs++
	} else {
		useEntry = true
	}

	// Remove the oldest log from the window.
	if oldest := queue.Value; oldest != nil {
		delete(seen, oldest.(string))
	}

	// Add the current log to the window.
	queue.Value = dedupField
	seen[dedupField] = logEntry.Msgid

	return useEntry, queue.Next()
}
