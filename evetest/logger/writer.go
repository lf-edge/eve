// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"strings"

	"github.com/sirupsen/logrus"
)

// LogWriter adapts a logrus.Logger to the io.Writer interface.
//
// It is intended for capturing stdout or stderr from external commands
// (e.g. exec.Cmd) and forwarding the output into logrus at a specified
// log level, optionally prefixed for context.
type LogWriter struct {
	Log    *logrus.Logger
	Level  logrus.Level
	Prefix string
}

// Write logs the provided byte slice as a single log entry.
//
// Empty or whitespace-only messages are ignored. The message is logged
// at the configured log level and prefixed with Prefix.
func (w LogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if msg == "" {
		return len(p), nil
	}
	w.Log.Log(w.Level, w.Prefix+msg)
	return len(p), nil
}
