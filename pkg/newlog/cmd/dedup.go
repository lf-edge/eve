package main

import (
	"encoding/json"
	"fmt"
)

const bufferSize = 100

type ContainsMsg struct {
	Msg string `json:"msg"`
}

func deduplicateLogs(in <-chan inputEntry, out chan<- inputEntry) {
	// 'seen' counts occurrences of each file in the current window.
	seen := make(map[string]string)
	// 'queue' holds the file fields of the last bufferSize logs.
	queue := make([]string, bufferSize)

	newElementIdx := 0
	bufferFull := false

	for logEntry := range in {
		dedupField := ""
		msgid := logEntry.appUUID // the field is set artificially for testing - CHANGE AFTER TESTING!!!
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

		if bufferFull {
			oldest := queue[newElementIdx]
			delete(seen, oldest)
		}

		// If the file hasn't appeared in the last bufferSize logs, forward it.
		if _, ok := seen[dedupField]; !ok || logEntry.severity != "error" {
			out <- logEntry
		} else {
			fmt.Printf("Deduped %s because of %s\n", msgid, seen[dedupField])
		}

		// Add the current log to the window.
		queue[newElementIdx] = dedupField
		seen[dedupField] = msgid

		// increment the index
		newElementIdx++
		// Maintain the window size: if it exceeds bufferSize, remove the oldest log.
		if newElementIdx == bufferSize {
			newElementIdx = 0
			bufferFull = true
		}
	}

	close(out)
}
