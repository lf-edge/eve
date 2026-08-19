// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/onsi/gomega"
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
	g := gomega.NewWithT(t)

	t.Run("cgo abort is captured from its first line", func(t *testing.T) {
		_, pending := feedPanicRecords(t, pillarRecords(cgoAbortRecords))
		g.Expect(pending).To(gomega.HavePrefix("ASSERT at lib/cgolib/tree.c:190"),
			"capture must start at the C assert line, not at the Go traceback")
		g.Expect(pending).To(gomega.ContainSubstring("cgolib.OpenAll()"))
		g.Expect(pending).To(gomega.ContainSubstring("signal arrived during cgo execution"))
	})

	t.Run("go panic and runtime throw are captured", func(t *testing.T) {
		for _, first := range []string{
			"panic: runtime error: invalid memory address or nil pointer dereference",
			"fatal error: concurrent map writes",
			"[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x123]",
		} {
			_, pending := feedPanicRecords(t, pillarRecords([]string{first, "goroutine 1 [running]:"}))
			g.Expect(pending).To(gomega.HavePrefix(first), "should trigger on %q", first)
		}
	})

	t.Run("ordinary pillar logs do not trigger a capture", func(t *testing.T) {
		_, pending := feedPanicRecords(t, pillarRecords([]string{
			`{"level":"info","msg":"periodic metrics published","pid":4280}`,
			`{"level":"error","msg":"handling panic: recovered"}`,
		}))
		g.Expect(pending).To(gomega.BeEmpty())
	})

	t.Run("a reported rebootReason does not re-trigger", func(t *testing.T) {
		_, pending := feedPanicRecords(t, pillarRecords([]string{
			`panic: some old crash rebootReason from the previous boot`,
		}))
		g.Expect(pending).To(gomega.BeEmpty())
	})
}

func TestPanicCaptureSpansOtherSources(t *testing.T) {
	g := gomega.NewWithT(t)

	// A traceback is a burst of thousands of records; other services keep
	// logging in between, and those interleaved records must not end it.
	records := pillarRecords(cgoAbortRecords[:4])
	records = append(records, inputEntry{source: "zedbox", content: "some other service logged"})
	records = append(records, inputEntry{source: "kube", content: "and another"})
	records = append(records, pillarRecords(cgoAbortRecords[4:])...)

	_, pending := feedPanicRecords(t, records)
	g.Expect(pending).To(gomega.ContainSubstring("cgolib.OpenAll()"),
		"records after an interleaved non-pillar record must still be captured")
	g.Expect(pending).ToNot(gomega.ContainSubstring("some other service logged"))
}

func TestPanicCaptureBudget(t *testing.T) {
	g := gomega.NewWithT(t)

	origRecords, origSize := maxPanicRecords, maxPanicBufSize
	maxPanicRecords = 5
	t.Cleanup(func() { maxPanicRecords, maxPanicBufSize = origRecords, origSize })

	sent, _ := feedPanicRecords(t, pillarRecords(cgoAbortRecords))
	g.Expect(sent).ToNot(gomega.BeEmpty(), "hitting the record budget must flush the capture")
	g.Expect(string(sent)).To(gomega.HavePrefix("ASSERT at"))
	g.Expect(strings.Count(string(sent), "\n")).To(gomega.Equal(5))
}
