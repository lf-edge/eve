// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"context"

	"github.com/sirupsen/logrus"
)

// loggerKeyType is an unexported type to avoid key collisions in context.
type loggerKeyType struct{}

// loggerKey is the unique key for storing loggers in context.
var loggerKey = loggerKeyType{}

// WithLogger returns a new context that carries the provided logger.
func WithLogger(ctx context.Context, log *logrus.Entry) context.Context {
	if log == nil {
		return ctx
	}
	return context.WithValue(ctx, loggerKey, log)
}

// FromContext extracts the *logrus.Entry from the context.
// If no logger is present, it returns a default logger.
func FromContext(ctx context.Context) *logrus.Entry {
	if ctx != nil {
		if log, ok := ctx.Value(loggerKey).(*logrus.Entry); ok && log != nil {
			return log
		}
	}
	// Return a default logger if none is set
	return logrus.NewEntry(logrus.StandardLogger())
}
