// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GrpcLogStream defines the interface for streaming log messages over gRPC.
type GrpcLogStream interface {
	Send(logs *api.LogMessage) error
}

// LogrusGrpcHook is a logrus Hook that streams log entries over a gRPC stream.
// It can be attached to a logrus.Logger to automatically send logs to a remote
// gRPC client.
type LogrusGrpcHook struct {
	mu     sync.RWMutex
	stream GrpcLogStream
}

// SetStream sets the gRPC stream used for log forwarding. Pass nil to detach.
// Returns an error if called with a non-nil stream while one is already active.
func (h *LogrusGrpcHook) SetStream(s GrpcLogStream) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s != nil && h.stream != nil {
		return fmt.Errorf("a log stream is already active; " +
			"only one concurrent stream is allowed")
	}
	h.stream = s
	return nil
}

// LogrusJSON represents the JSON structure produced by logrus.JSONFormatter.
type LogrusJSON struct {
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
	Time  time.Time `json:"time"`
}

// LoadAndStreamFromFile reads previously saved logrus JSON log entries from a file
// and streams them over the configured gRPC stream. Lines not in logrus JSON format
// are sent as raw messages with INFO severity.
// Returns an error if the file cannot be read or if sending fails.
func (h *LogrusGrpcHook) LoadAndStreamFromFile(path string) error {
	h.mu.RLock()
	stream := h.stream
	h.mu.RUnlock()
	if stream == nil {
		return fmt.Errorf("no GrpcLogStream configured")
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		var entry LogrusJSON
		if err = json.Unmarshal(line, &entry); err != nil {
			// Line not produced by logrus.
			logMsg := &api.LogMessage{
				Message:  string(line),
				Severity: LogrusLevelToAPILogSeverity(logrus.InfoLevel),
			}
			if err = stream.Send(logMsg); err != nil {
				return fmt.Errorf("failed to send loaded log: %w", err)
			}
			continue
		}

		level, err := logrus.ParseLevel(entry.Level)
		if err != nil {
			level = logrus.InfoLevel // default if unknown
		}

		logMsg := &api.LogMessage{
			Message:   entry.Msg,
			Severity:  LogrusLevelToAPILogSeverity(level),
			Timestamp: timestamppb.New(entry.Time),
		}
		if err = stream.Send(logMsg); err != nil {
			return fmt.Errorf("failed to send loaded log: %w", err)
		}
	}
	if err = scanner.Err(); err != nil {
		return fmt.Errorf("error reading log file: %w", err)
	}
	return nil
}

// Levels returns all log levels that trigger this hook. All logrus levels are supported.
func (h *LogrusGrpcHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire sends a single logrus.Entry over the gRPC stream as an api.LogMessage.
// Implements the logrus.Hook interface.
func (h *LogrusGrpcHook) Fire(entry *logrus.Entry) error {
	h.mu.RLock()
	stream := h.stream
	h.mu.RUnlock()
	if stream == nil {
		return nil
	}
	logMessage := &api.LogMessage{
		Message:   entry.Message,
		Severity:  LogrusLevelToAPILogSeverity(entry.Level),
		Timestamp: timestamppb.New(entry.Time),
	}
	return stream.Send(logMessage)
}

// LogrusLevelToAPILogSeverity converts a logrus.Level into the corresponding
// api.LogSeverity enum for gRPC transport.
func LogrusLevelToAPILogSeverity(level logrus.Level) api.LogSeverity {
	switch level {
	case logrus.PanicLevel, logrus.FatalLevel:
		return api.LogSeverity_LOG_FATAL
	case logrus.ErrorLevel:
		return api.LogSeverity_LOG_ERROR
	case logrus.WarnLevel:
		return api.LogSeverity_LOG_WARN
	case logrus.InfoLevel:
		return api.LogSeverity_LOG_INFO
	case logrus.DebugLevel, logrus.TraceLevel:
		return api.LogSeverity_LOG_DEBUG
	default:
		return api.LogSeverity_LOG_UNKNOWN
	}
}

// APILogSeverityToLogrusLevel converts an api.LogSeverity enum back to
// a logrus.Level. Unknown severities are mapped to InfoLevel.
func APILogSeverityToLogrusLevel(severity api.LogSeverity) logrus.Level {
	switch severity {
	case api.LogSeverity_LOG_FATAL:
		return logrus.FatalLevel
	case api.LogSeverity_LOG_ERROR:
		return logrus.ErrorLevel
	case api.LogSeverity_LOG_WARN:
		return logrus.WarnLevel
	case api.LogSeverity_LOG_INFO:
		return logrus.InfoLevel
	case api.LogSeverity_LOG_DEBUG:
		return logrus.DebugLevel
	default:
		return logrus.InfoLevel // default fallback if unknown
	}
}
