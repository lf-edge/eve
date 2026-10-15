// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	evelogs "github.com/lf-edge/eve-api/go/logs"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

// LogEntryMatcher defines a predicate used to determine whether
// a LogEntry should be delivered to a subscriber.
type LogEntryMatcher func(entry *evelogs.LogEntry) bool

// DeviceLogIterator defines an interface for iterating over EVE device logs.
// Implementations may write to a file, stream over gRPC, or perform
// arbitrary log processing.
// Returning stop=true signals that no further entries are needed and iteration
// should stop cleanly. Returning a non-nil error aborts iteration and
// propagates the error to the caller.
type DeviceLogIterator interface {
	Iterate(*evelogs.LogEntry) (stop bool, err error)
}

// PlainDeviceLogFile writes EVE LogEntry instances in a human-readable
// "plain text" format (not JSON) to the provided output writer.
// Each log line is written as:
//
//	<timestamp>|<severity>|<source>|<function>| <content>\n
//
// Example:
//
//	2025-08-05 02:42:41.267|info|domainmgr|/pillar/cmd/domainmgr/domainmgr.go:421| waiting for GCComplete
type PlainDeviceLogFile struct {
	OutFile io.Writer
}

// Iterate formats the given LogEntry as a human-readable line
// and writes it to the underlying OutFile.
func (w *PlainDeviceLogFile) Iterate(entry *evelogs.LogEntry) (bool, error) {
	var ts string
	if entry.Timestamp != nil {
		ts = entry.Timestamp.AsTime().
			UTC().
			Format("2006-01-02 15:04:05.000")
	}
	line := fmt.Sprintf("%s|%s|%s|%s| %s\n",
		ts,
		strings.ToLower(entry.Severity),
		entry.Source,
		entry.Function,
		getDeviceLogMsg(entry),
	)
	_, err := io.WriteString(w.OutFile, line)
	return false, err
}

// GrpcDeviceLogStreamer wraps a gRPC streaming interface and implements
// the DeviceLogIterator interface. Each log entry iterated via Iterate() is
// sent to the connected gRPC client as an api.LogMessage.
type GrpcDeviceLogStreamer struct {
	Stream GrpcLogStream
}

// Iterate formats the given LogEntry as an api.LogMessage and sends
// it over the gRPC stream. Severity is converted from EVE's string format
// to the corresponding api.LogSeverity.
func (w *GrpcDeviceLogStreamer) Iterate(entry *evelogs.LogEntry) (bool, error) {
	return false, w.Stream.Send(&api.LogMessage{
		Message:   getDeviceLogMsg(entry),
		Severity:  eveSeverityToAPILogSeverity(entry.Severity),
		Source:    entry.Source,
		Timestamp: entry.Timestamp,
	})
}

// eveSeverityToAPILogSeverity converts a log severity string as produced
// by an EVE device into the corresponding api.LogSeverity enumeration
// used by the gRPC API. Unknown severities are mapped to LOG_UNKNOWN.
func eveSeverityToAPILogSeverity(severity string) api.LogSeverity {
	switch severity {
	case "fatal":
		return api.LogSeverity_LOG_FATAL
	case "error":
		return api.LogSeverity_LOG_ERROR
	case "warning":
		return api.LogSeverity_LOG_WARN
	case "info", "notice":
		return api.LogSeverity_LOG_INFO
	case "debug":
		return api.LogSeverity_LOG_DEBUG
	default:
		return api.LogSeverity_LOG_UNKNOWN
	}
}

// getDeviceLogMsg extracts a human-readable message from a device log entry.
//
// The entry.Content field may contain either:
//  1. A plain text log message
//  2. A JSON-encoded log record, for example:
//     {"level":"debug","msg":"Read 284 bytes","time":"2026-02-15T19:19:55.962102829Z"}
//
// If Content contains valid JSON with a "msg" field of type string,
// that field is returned. Otherwise, the original Content is returned
// unchanged.
//
// Any trailing newline characters ('\n' or '\r\n') are stripped from
// the returned string.
//
// The function never returns an error and is safe for malformed JSON.
func getDeviceLogMsg(entry *evelogs.LogEntry) string {
	if entry == nil || entry.Content == "" {
		return ""
	}

	// Remove trailing newlines first.
	content := strings.TrimRight(entry.Content, "\r\n")

	// Fast-path: JSON logs typically start with '{'
	if len(content) == 0 || content[0] != '{' {
		return content
	}

	// Attempt to extract only the "msg" field.
	var tmp struct {
		Msg string `json:"msg"`
	}

	if err := json.Unmarshal([]byte(content), &tmp); err != nil {
		return content
	}
	if tmp.Msg == "" {
		return content
	}

	return tmp.Msg
}
