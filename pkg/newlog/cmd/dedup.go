package main

import (
	"container/ring"
	"encoding/json"
	"fmt"
)

const bufferSize = 100

type ContainsMsg struct {
	Msg string `json:"msg"`
}

var numDedupedLogs = 0

func deduplicateLogs(in <-chan inputEntry, out chan<- inputEntry) {
	// 'seen' counts occurrences of each file in the current window.
	seen := make(map[string]string)
	// 'queue' holds the file fields of the last bufferSize logs.
	queue := ring.New(bufferSize)

	for logEntry := range in {
		dedupField := ""
		// If logEntry.content is a valid JSON, extract the field "msg" from it.
		if logEntry.content != "" {
			var content ContainsMsg
			err := json.Unmarshal([]byte(logEntry.content), &content)
			if err == nil && content.Msg != "" {
				dedupField = content.Msg
			} else {
				dedupField = logEntry.content
			}
		}

		// If the file hasn't appeared in the last bufferSize logs, forward it.
		if _, ok := seen[dedupField]; !ok || logEntry.severity != "error" {
			out <- logEntry
		} else {
			fmt.Printf("Deduped log at %s because of the log at %s\n", logEntry.timestamp, seen[dedupField])
			numDedupedLogs++
			if numDedupedLogs%10 == 0 {
				fmt.Printf("Deduped %d logs\n", numDedupedLogs)
			}
		}

		// Remove the oldest log from the window.
		if oldest := queue.Value; oldest != nil {
			delete(seen, oldest.(string))
		}

		// Add the current log to the window.
		queue.Value = dedupField
		seen[dedupField] = logEntry.timestamp

		// Move the window.
		queue = queue.Next()
	}

	close(out)
}
