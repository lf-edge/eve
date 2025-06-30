// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"math"
	"testing"
	"time"
)

// This is a test function to ensure that the ReportDroppedMsgs limits the rate of error reporting correctly.
func TestReportDroppedMsgs(t *testing.T) {
	bufSize := 5       // Size of the buffer for BufferedSockWriter
	extra := 10        // Extra messages to write beyond the buffer size
	printedErrors := 0 // Counter for printed errors

	sw := NewBufferedSockWriter("/tmp/test.sock", bufSize, 10*time.Second)
	for i := 0; i < bufSize+extra; i++ {
		// Simulate writing messages to the buffer
		_, err := sw.Write([]byte("test message"))
		if err != nil {
			if numLogs := sw.ReportDroppedMsgs(); numLogs > 0 {
				t.Logf("TestReportDroppedMsgs: BufferedSockWriter dropped %d logs due to a write error: %s", numLogs, err)
				printedErrors++
			}
		}
	}

	expectedErrors := math.Log2(float64(extra)) + 1
	if printedErrors != int(expectedErrors) {
		t.Errorf("TestReportDroppedMsgs: expected %d printed errors, got %d", int(expectedErrors), printedErrors)
	} else {
		t.Logf("TestReportDroppedMsgs: successfully printed %d errors as expected", printedErrors)
	}
}
