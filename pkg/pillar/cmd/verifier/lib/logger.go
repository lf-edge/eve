// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

// Logger is an interface for logging, combines the best of logrus.Logger and base.LogObject
type Logger interface {
	Functionf(format string, args ...interface{})
	Tracef(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Function(args ...interface{})
	Trace(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
	Fatal(args ...interface{})
}
