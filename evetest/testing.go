// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"fmt"
	"runtime/debug"
	"testing"
)

// T wraps testing.T and adds evetest-specific failure handling.
//
// The wrapper augments test failures with:
//   - automatic stacktrace logging
//   - optional pause-on-failure support (controlled by EVETEST_PAUSE_ON_FAILURE)
//
// T is returned by evetest.Init(*testing.T) and MUST be used instead of the
// original *testing.T. Calling failure methods on the original *testing.T
// bypasses this additional behavior.
type T struct {
	*testing.T
	th *TestHarness
}

const (
	redColor   = "\033[31m"
	resetColor = "\033[0m"
)

// fail is the common failure path for all T failure methods.
//
// It performs evetest-specific failure handling, including:
//   - logging a highlighted failure message
//   - capturing and logging the current goroutine stacktrace
//   - optionally pausing test execution if pause-on-failure is enabled
//   - signaling the test harness about the failure (used when running
//     from within evetest.RunParallel)
//
// After the custom handling, it marks the test as failed using the underlying
// testing.T. If now is true, it also stops execution immediately in the current
// test goroutine (equivalent to FailNow semantics).
func (t *T) fail(msg string, now bool) {
	t.Helper()

	// Log the error message with the red color.
	t.Log(redColor + "TEST FAILURE: " + msg + resetColor)

	// Log stacktrace at the point of failure for easier debugging.
	t.Logf("STACKTRACE:\n%s", debug.Stack())

	// Check whether pause-on-failure is enabled and record failure state.
	t.th.checkpointM.Lock()
	shouldPause := t.th.pauseOnFailure
	if shouldPause {
		t.th.pausedOnFailure = msg
	}
	t.th.checkpointM.Unlock()

	// If enabled, pause test execution until resumed by TestHarness.Continue
	if shouldPause {
		t.th.log.Info("Paused on failure")
		select {
		case <-t.th.resume:
			t.th.log.Info("Resumed after failure")
		case sig := <-t.th.sigCh:
			t.th.log.Infof("Received signal %v while paused on failure, terminating", sig)
		case <-t.th.exitCh:
			t.th.log.Info("Exit requested while paused on failure")
		}
	}

	// Signal that the test has failed.
	// Used when the failure is triggered from a different goroutine
	// than the one running the test (see evetest.RunParallel).
	t.th.testM.Lock()
	if t.th.test.failedCh != nil {
		close(t.th.test.failedCh)
	}
	t.th.testM.Unlock()

	// Mark the test as failed
	t.T.Fail()

	if now {
		t.T.FailNow()
	}
}

// Fail marks the test as failed but allows execution to continue.
//
// This mirrors testing.T.Fail, with the addition of stacktrace logging and
// optional pause-on-failure behavior.
func (t *T) Fail() {
	t.Helper()
	t.fail("test failed", false)
}

// FailNow marks the test as failed and stops execution immediately.
//
// Like testing.T.FailNow, this only stops the test in the goroutine from which
// it is called.
func (t *T) FailNow() {
	t.Helper()
	t.fail("test failed", true)
}

// Error logs the provided arguments, marks the test as failed, and continues
// execution.
//
// This is equivalent to Log + Fail, with additional stacktrace logging and
// optional pause-on-failure behavior.
func (t *T) Error(args ...interface{}) {
	t.Helper()
	t.fail(fmt.Sprint(args...), false)
}

// Errorf formats the message, marks the test as failed, and continues execution.
//
// This is equivalent to Logf + Fail, with additional stacktrace logging and
// optional pause-on-failure behavior.
func (t *T) Errorf(format string, args ...interface{}) {
	t.Helper()
	t.fail(fmt.Sprintf(format, args...), false)
}

// Fatal logs the provided arguments, marks the test as failed, and stops
// execution immediately.
//
// Like testing.T.Fatal, this only stops the test in the goroutine from which
// it is called.
func (t *T) Fatal(args ...interface{}) {
	t.Helper()
	t.fail(fmt.Sprint(args...), true)
}

// Fatalf formats the message, marks the test as failed, and stops execution
// immediately.
//
// In addition to testing.T.Fatalf behavior, this logs the current stacktrace
// and optionally pauses test execution if EVETEST_PAUSE_ON_FAILURE is enabled.
func (t *T) Fatalf(format string, args ...interface{}) {
	t.Helper()
	t.fail(fmt.Sprintf(format, args...), true)
}
