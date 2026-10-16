// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// This is a test function to ensure that the ReportDroppedMsgs limits the rate of error reporting correctly.
func TestReportDroppedMsgs(t *testing.T) {
	bufSize := 5       // Size of the buffer for BufferedSockWriter
	extra := 10        // Extra messages to write beyond the buffer size
	printedErrors := 0 // Counter for printed errors

	sw := newBufferedSockWriter("/tmp/test.sock", bufSize, 10*time.Second, 0)
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

// TestWriteWaitsForFirstConnection checks that messages written while the
// socket does not exist yet are held back, not dropped, until it appears.
func TestWriteWaitsForFirstConnection(t *testing.T) {
	bufSize := 5
	total := 50
	sockPath := filepath.Join(t.TempDir(), "source.sock")
	sw := newBufferedSockWriter(sockPath, bufSize, 50*time.Millisecond, 10*time.Second)

	writeErr := make(chan error, 1)
	go func() {
		for i := 0; i < total; i++ {
			if _, err := fmt.Fprintf(sw, "msg %d\n", i); err != nil {
				writeErr <- fmt.Errorf("write %d: %w", i, err)
				return
			}
		}
		writeErr <- nil
	}()

	time.Sleep(300 * time.Millisecond)
	select {
	case err := <-writeErr:
		t.Fatalf("all writes returned before the socket existed: %v", err)
	default:
	}

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	scanner := bufio.NewScanner(conn)
	for i := 0; i < total; i++ {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if !scanner.Scan() {
			t.Fatalf("got %d of %d messages: %v", i, total, scanner.Err())
		}
		if want := fmt.Sprintf("msg %d", i); scanner.Text() != want {
			t.Fatalf("message %d is %q, want %q", i, scanner.Text(), want)
		}
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	if sw.msgsDropped != 0 {
		t.Errorf("dropped %d messages", sw.msgsDropped)
	}
}

// TestWriteDropsAfterStartupWait checks that a full buffer drops once the
// startup window has ended, and from then on without waiting.
func TestWriteDropsAfterStartupWait(t *testing.T) {
	bufSize := 3
	waitFor := 200 * time.Millisecond
	sw := newBufferedSockWriter(filepath.Join(t.TempDir(), "none.sock"), bufSize, time.Hour, waitFor)
	for i := 0; i < bufSize; i++ {
		if _, err := sw.Write([]byte("x")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	start := time.Now()
	if _, err := sw.Write([]byte("x")); err == nil {
		t.Fatal("write to a full buffer succeeded")
	}
	if waited := time.Since(start); waited < waitFor/2 {
		t.Errorf("dropped after %v, within the startup window of %v", waited, waitFor)
	}
	start = time.Now()
	if _, err := sw.Write([]byte("x")); err == nil {
		t.Fatal("write to a full buffer succeeded")
	}
	if waited := time.Since(start); waited > waitFor/2 {
		t.Errorf("waited %v to drop after the startup window", waited)
	}
}
