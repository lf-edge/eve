// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"bytes"
	"sync"
)

// processLogger implements io.Writer and is used to capture stdout/stderr
// of a non-daemonized child process started via exec.Command.
// It buffers output until a newline is encountered and then logs
// complete lines using the provided log callback.
type processLogger struct {
	logCb func(fmt string, args ...interface{})
	cmd   string

	mu  sync.Mutex
	buf bytes.Buffer
}

func newProcessLogger(
	logCb func(fmt string, args ...interface{}), cmd string) *processLogger {
	return &processLogger{
		logCb: logCb,
		cmd:   cmd,
	}
}

// Write accumulates data until a newline is seen and then emits
// the complete line through the configured logger. It is safe for
// concurrent use by multiple goroutines.
func (l *processLogger) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, b := range p {
		if b == '\n' {
			line := l.buf.String()
			l.buf.Reset()
			if line != "" {
				l.logCb("%s: %s", l.cmd, line)
			}
			continue
		}
		_ = l.buf.WriteByte(b)
	}
	return len(p), nil
}

// Flush logs any buffered data that was not terminated by a newline.
// This should be called after the process exits to avoid losing
// a trailing partial line.
func (l *processLogger) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buf.Len() > 0 {
		l.logCb("%s: %s", l.cmd, l.buf.String())
		l.buf.Reset()
	}
}
