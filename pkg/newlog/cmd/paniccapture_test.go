// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"
)

// feedPanicRecords runs a sequence of memlogd records through
// checkWatchdogRestart and returns whatever was sent to the panic file
// channel, plus the buffer still being accumulated.
func feedPanicRecords(t *testing.T, records []inputEntry) (sent []byte, pending string) {
	t.Helper()

	panicWriteTimer = time.NewTimer(time.Hour)
	panicWriteTimer.Stop()
	panicBuf = nil
	t.Cleanup(func() { panicBuf = nil })

	panicFileChan := make(chan []byte, 1)
	var count int
	for i := range records {
		checkWatchdogRestart(&records[i], &count, panicFileChan)
	}

	select {
	case sent = <-panicFileChan:
	default:
	}
	panicBufLock.Lock()
	defer panicBufLock.Unlock()
	return sent, string(panicBuf)
}

// A C assertion failing under cgo, in the order the dying process prints it:
// no "panic:" appears anywhere and Go's traceback only starts several lines in.
var cgoAbortRecords = []string{
	"ASSERT at lib/cgolib/tree.c:190:tree_reload()",
	"avl_find(hdl->tree, node, &where) == NULL",
	"  PID: 4280      COMM: zedbox",
	"SIGABRT: abort",
	"signal arrived during cgo execution",
	"goroutine 4490 gp=0xc002b81500 m=13 mp=0xc0005f4808 [syscall]:",
	"github.com/example/cgolib.OpenAll()",
}

func pillarRecords(lines []string) []inputEntry {
	entries := make([]inputEntry, 0, len(lines))
	for _, l := range lines {
		entries = append(entries, inputEntry{source: "pillar", content: l})
	}
	return entries
}

func TestPanicCaptureStart(t *testing.T) {
	t.Run("cgo abort is captured from its first line", func(t *testing.T) {
		_, pending := feedPanicRecords(t, pillarRecords(cgoAbortRecords))
		if !strings.HasPrefix(pending, "ASSERT at lib/cgolib/tree.c:190") {
			t.Fatalf("capture must start at the C assert line, not at the Go traceback; got %q", pending)
		}
		if !strings.Contains(pending, "cgolib.OpenAll()") {
			t.Errorf("traceback frames missing from capture: %q", pending)
		}
		if !strings.Contains(pending, "signal arrived during cgo execution") {
			t.Errorf("signal banner missing from capture: %q", pending)
		}
	})

	t.Run("go panic and runtime throw are captured", func(t *testing.T) {
		for _, first := range []string{
			"panic: runtime error: invalid memory address or nil pointer dereference",
			"fatal error: concurrent map writes",
			"[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x123]",
		} {
			_, pending := feedPanicRecords(t, pillarRecords([]string{first, "goroutine 1 [running]:"}))
			if !strings.HasPrefix(pending, first) {
				t.Errorf("should trigger on %q, got %q", first, pending)
			}
		}
	})

	t.Run("ordinary pillar logs do not trigger a capture", func(t *testing.T) {
		_, pending := feedPanicRecords(t, pillarRecords([]string{
			`{"level":"info","msg":"periodic metrics published","pid":4280}`,
			`{"level":"error","msg":"handling panic: recovered"}`,
		}))
		if pending != "" {
			t.Errorf("ordinary logs must not start a capture, got %q", pending)
		}
	})

	t.Run("a reported rebootReason does not re-trigger", func(t *testing.T) {
		_, pending := feedPanicRecords(t, pillarRecords([]string{
			`panic: some old crash rebootReason from the previous boot`,
		}))
		if pending != "" {
			t.Errorf("a reported rebootReason must not start a capture, got %q", pending)
		}
	})
}

func TestPanicCaptureSpansOtherSources(t *testing.T) {
	// A traceback is a burst of thousands of records; other services keep
	// logging in between, and those interleaved records must not end it.
	records := pillarRecords(cgoAbortRecords[:4])
	records = append(records, inputEntry{source: "zedbox", content: "some other service logged"})
	records = append(records, inputEntry{source: "kube", content: "and another"})
	records = append(records, pillarRecords(cgoAbortRecords[4:])...)

	_, pending := feedPanicRecords(t, records)
	if !strings.Contains(pending, "cgolib.OpenAll()") {
		t.Errorf("records after an interleaved non-pillar record must still be captured, got %q", pending)
	}
	if strings.Contains(pending, "some other service logged") {
		t.Errorf("non-pillar records must not be captured, got %q", pending)
	}
}

func TestPanicCaptureBudget(t *testing.T) {
	origRecords, origSize := maxPanicRecords, maxPanicBufSize
	maxPanicRecords = 5
	t.Cleanup(func() { maxPanicRecords, maxPanicBufSize = origRecords, origSize })

	sent, _ := feedPanicRecords(t, pillarRecords(cgoAbortRecords))
	if len(sent) == 0 {
		t.Fatal("hitting the record budget must flush the capture")
	}
	if !strings.HasPrefix(string(sent), "ASSERT at") {
		t.Errorf("flushed capture should start at the assert line, got %q", string(sent))
	}
	if got := strings.Count(string(sent), "\n"); got != 5 {
		t.Errorf("flushed capture should hold %d records, got %d", 5, got)
	}
}
