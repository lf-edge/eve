// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package nodeagent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

var (
	prevBoot  = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	panicTime = prevBoot.Add(436 * time.Second)
)

type pstoreFixture struct {
	tc        *testCtx
	pstore    string
	kcrashes  string
	nextIndex int
}

func newPstoreFixture(t *testing.T) *pstoreFixture {
	t.Helper()
	tc := newTestCtx()
	dir := t.TempDir()
	f := &pstoreFixture{
		tc:       tc,
		pstore:   filepath.Join(dir, "pstore"),
		kcrashes: filepath.Join(dir, "kcrashes"),
	}
	if err := os.Mkdir(f.pstore, 0755); err != nil {
		t.Fatal(err)
	}
	tc.ctx.paths.pstoreDir = f.pstore
	tc.ctx.paths.kcrashesDir = f.kcrashes
	tc.ctx.paths.restartCounterFile = filepath.Join(dir, "restartcounter")
	tc.ctx.paths.firstbootFile = filepath.Join(dir, "no-such-firstboot")
	mustWrite(t, tc.ctx.paths.restartCounterFile, "7")
	if err := os.Chtimes(tc.ctx.paths.restartCounterFile, prevBoot, prevBoot); err != nil {
		t.Fatal(err)
	}
	return f
}

// addDump writes the records of one dump as pstore_dump() lays them out:
// the log's newest end in Part1, all written within the second starting at
// ts unless span moves the later parts into the next second.
func (f *pstoreFixture) addDump(t *testing.T, reason string, ts time.Time,
	span time.Duration, parts ...string) []string {
	t.Helper()
	var names []string
	for i, body := range parts {
		f.nextIndex++
		name := fmt.Sprintf("dmesg-efi_pstore-%d", f.nextIndex)
		content := fmt.Sprintf("%s#1 Part%d\n%s", reason, i+1, body)
		mtime := ts
		if i > 0 {
			mtime = ts.Add(span)
		}
		f.write(t, name, content, mtime)
		names = append(names, name)
	}
	return names
}

func (f *pstoreFixture) write(t *testing.T, name, content string, mtime time.Time) {
	t.Helper()
	path := filepath.Join(f.pstore, name)
	mustWrite(t, path, content)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func (f *pstoreFixture) remaining(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(f.pstore)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// panicParts are the parts of a dm-verity panic, Part1 (newest log) first.
var panicParts = []string{
	"<4>[  436.2] Call Trace:\n<4>[  436.2]  dump_stack_lvl+0x5d/0x80\n<4>[  436.2]  ret_from_fork_asm+0x1a/0x30\n",
	"<0>[  436.1] Kernel panic - not syncing: dm-verity device corrupted\n",
	"<3>[  435.9] device-mapper: verity: metadata block 75190 is corrupted\n",
}

func TestGroupPstoreRecordsAcrossSecondBoundary(t *testing.T) {
	f := newPstoreFixture(t)
	f.addDump(t, "Panic", panicTime, time.Second, panicParts...)
	f.addDump(t, "Panic", panicTime.Add(200*time.Second), 0, panicParts[:2]...)
	records, _ := readPstoreRecords(f.pstore)
	dumps := groupPstoreRecords(records)
	if len(dumps) != 2 {
		t.Fatalf("expected 2 dumps, got %d", len(dumps))
	}
	if n := len(dumps[0].records); n != 3 {
		t.Errorf("expected 3 records in the first dump, got %d", n)
	}
	want := panicParts[2] + panicParts[1] + panicParts[0]
	if got := dumps[0].text(); got != want {
		t.Errorf("assembled text\n%q\nwant\n%q", got, want)
	}
	if got := dumps[1].panicLine(); got != "Kernel panic - not syncing: dm-verity device corrupted" {
		t.Errorf("partial dump panic line %q", got)
	}
}

func TestPstoreRebootReasonTable(t *testing.T) {
	dump := func(reason string, ts time.Time, current bool) *pstoreDump {
		return &pstoreDump{current: current, records: []pstoreRecord{{
			reason: reason, count: 1, part: 1, time: ts,
			body: "<0>[ 1.0] Kernel panic - not syncing: boom\n"}}}
	}
	crash := dump("Panic", panicTime, true)
	tests := []struct {
		name         string
		dumps        []*pstoreDump
		storedReason string
		storedBoot   types.BootReason
		storedTime   time.Time
		wantDump     *pstoreDump
		wantReason   string
		wantBoot     types.BootReason
	}{
		{"no crash", []*pstoreDump{dump("Shutdown", panicTime, true)},
			"", types.BootReasonNone, time.Time{}, nil, "", types.BootReasonNone},
		{"stale crash only", []*pstoreDump{dump("Panic", panicTime, false)},
			"", types.BootReasonNone, time.Time{}, nil, "", types.BootReasonNone},
		{"no stored reason", []*pstoreDump{crash},
			"", types.BootReasonNone, time.Time{}, crash,
			"kernel panic, pstore: Kernel panic - not syncing: boom",
			types.BootReasonKernel},
		{"panic loop", []*pstoreDump{dump("Oops", prevBoot.Add(time.Minute), true), crash},
			"", types.BootReasonNone, time.Time{}, crash,
			"kernel panic, pstore: Kernel panic - not syncing: boom (2 panics)",
			types.BootReasonKernel},
		{"kdump wins", []*pstoreDump{crash},
			"kernel panic, dmesg collected", types.BootReasonKernel,
			panicTime.Add(time.Minute), crash, "", types.BootReasonNone},
		{"panic after stored reason", []*pstoreDump{crash},
			"Reboot from agent zedagent\n", types.BootReasonRebootCmd,
			panicTime.Add(-time.Minute), crash,
			"kernel panic after Reboot from agent zedagent",
			types.BootReasonRebootCmd},
		{"panic after watchdog reboot", []*pstoreDump{crash},
			"Watchdog hung", types.BootReasonWatchdogHung,
			panicTime.Add(-time.Minute), crash,
			"kernel panic after Watchdog hung", types.BootReasonWatchdogHung},
		{"panic after reason without boot reason", []*pstoreDump{crash},
			"Reboot from agent zedagent", types.BootReasonNone,
			panicTime.Add(-time.Minute), crash,
			"kernel panic after Reboot from agent zedagent",
			types.BootReasonKernel},
		{"stored reason newer", []*pstoreDump{crash},
			"Reboot from agent zedagent", types.BootReasonRebootCmd,
			panicTime.Add(time.Minute), crash, "", types.BootReasonNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, reason, br := pstoreRebootReason(tt.dumps, tt.storedReason,
				tt.storedBoot, tt.storedTime)
			if d != tt.wantDump || reason != tt.wantReason || br != tt.wantBoot {
				t.Errorf("got (%p, %q, %v), want (%p, %q, %v)", d, reason, br,
					tt.wantDump, tt.wantReason, tt.wantBoot)
			}
		})
	}
}

// TestHandlePstoreRecords runs a previous-boot panic, a stale dump and a
// compressed record through to the published reboot reason.
func TestHandlePstoreRecords(t *testing.T) {
	f := newPstoreFixture(t)
	f.addDump(t, "Panic", prevBoot.Add(-24*time.Hour), 0, panicParts...)
	f.addDump(t, "Panic", panicTime, time.Second, panicParts...)
	f.write(t, "dmesg-efi_pstore-99.enc.z", "\x78\x9c", prevBoot.Add(-48*time.Hour))

	handlePstoreRecords(f.tc.ctx)

	if left := f.remaining(t); len(left) != 0 {
		t.Errorf("expected pstore to be empty, left %v", left)
	}
	saved, err := os.ReadDir(f.kcrashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) != 3 {
		t.Errorf("expected 3 files in kcrashes, got %d", len(saved))
	}
	b, err := os.ReadFile(filepath.Join(f.kcrashes,
		"pstore-"+panicTime.Format(time.RFC3339)+".log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "ret_from_fork_asm") {
		t.Errorf("saved dump lacks the call trace: %q", b)
	}
	if f.tc.rebootStore.kernelWrites != 1 {
		t.Fatalf("expected one reboot reason write, got %d",
			f.tc.rebootStore.kernelWrites)
	}

	handleLastRebootReason(f.tc.ctx)

	ctx := f.tc.ctx
	if ctx.bootReason != types.BootReasonKernel {
		t.Errorf("bootReason %v", ctx.bootReason)
	}
	if ctx.rebootReason != "kernel panic, pstore: Kernel panic - not syncing: dm-verity device corrupted" {
		t.Errorf("rebootReason %q", ctx.rebootReason)
	}
	if !ctx.rebootTime.Equal(panicTime) {
		t.Errorf("rebootTime %v, want %v", ctx.rebootTime, panicTime)
	}
	want := panicParts[1] + panicParts[0]
	if ctx.rebootStack != want {
		t.Errorf("rebootStack\n%q\nwant\n%q", ctx.rebootStack, want)
	}
}

// TestHandlePstoreRecordsPanicDuringReboot checks that a panic on the way
// down from a watchdog reboot keeps the watchdog boot reason, so zedagent
// still starts from the backup config.
func TestHandlePstoreRecordsPanicDuringReboot(t *testing.T) {
	f := newPstoreFixture(t)
	f.addDump(t, "Panic", panicTime, 0, panicParts...)
	rs := f.tc.rebootStore
	rs.rebootReason = "Watchdog hung\n"
	rs.rebootTime = panicTime.Add(-time.Minute)
	rs.bootReason, rs.bootTime = types.BootReasonWatchdogHung, rs.rebootTime

	handlePstoreRecords(f.tc.ctx)
	handleLastRebootReason(f.tc.ctx)

	ctx := f.tc.ctx
	if ctx.bootReason != types.BootReasonWatchdogHung {
		t.Errorf("bootReason %v", ctx.bootReason)
	}
	if ctx.bootReason.StartWithSavedConfig() {
		t.Errorf("boot reason %v starts from the saved config", ctx.bootReason)
	}
	if !strings.HasPrefix(ctx.rebootReason, "kernel panic after Watchdog hung") {
		t.Errorf("rebootReason %q", ctx.rebootReason)
	}
	if want := panicParts[1] + panicParts[0]; ctx.rebootStack != want {
		t.Errorf("rebootStack\n%q\nwant\n%q", ctx.rebootStack, want)
	}
}

func TestPstoreRebootStack(t *testing.T) {
	frames := strings.Repeat("<4>[  436.2]  ? filemap_map_pages+0x3a1/0x5c0\n", 60)
	d := &pstoreDump{records: []pstoreRecord{{part: 1,
		body: panicParts[2] + panicParts[1] + panicParts[0] + frames}}}
	got := d.rebootStack()
	if !strings.HasPrefix(got, panicParts[1]+panicParts[0]) {
		t.Errorf("rebootStack does not start at the panic line: %q", got)
	}
	if !strings.HasSuffix(got, "/0x5c0\n...") {
		t.Errorf("rebootStack not cut after a whole line: %q", got)
	}
	if n := len([]rune(got)); n > maxRebootStackSize+len("...") {
		t.Errorf("rebootStack is %d runes", n)
	}
	if truncateRebootStack(got) != got {
		t.Errorf("handleLastRebootReason would truncate rebootStack again")
	}

	noPanic := &pstoreDump{records: []pstoreRecord{{part: 1, body: frames}}}
	if got := noPanic.rebootStack(); got != truncateRebootStack(frames) {
		t.Errorf("dump without a panic line: %q", got)
	}
}

// TestHandlePstoreRecordsKeepsUnsaved checks that no record is erased
// before a durable copy of it exists.
func TestHandlePstoreRecordsKeepsUnsaved(t *testing.T) {
	t.Run("reboot reason write fails", func(t *testing.T) {
		f := newPstoreFixture(t)
		names := f.addDump(t, "Panic", panicTime, 0, panicParts...)
		f.tc.rebootStore.writeKernelErr = errors.New("disk full")
		handlePstoreRecords(f.tc.ctx)
		if left := f.remaining(t); len(left) != len(names) {
			t.Errorf("expected %v kept, left %v", names, left)
		}
	})
	t.Run("kcrashes not writable", func(t *testing.T) {
		f := newPstoreFixture(t)
		mustWrite(t, f.kcrashes, "not a directory")
		f.addDump(t, "Panic", prevBoot.Add(-time.Hour), 0, panicParts...)
		names := f.addDump(t, "Panic", panicTime, 0, panicParts...)
		handlePstoreRecords(f.tc.ctx)
		// The current dump is durable as the reboot reason; the stale
		// one has no copy.
		left := f.remaining(t)
		if len(left) != len(names) {
			t.Errorf("expected only the stale dump kept, left %v", left)
		}
		for _, n := range names {
			for _, l := range left {
				if n == l {
					t.Errorf("current dump record %s was not erased", n)
				}
			}
		}
	})
}

func TestSaveKcrashFilesRotation(t *testing.T) {
	initTestLog()
	dir := t.TempDir()
	for i := 0; i < 8; i++ {
		path := filepath.Join(dir, fmt.Sprintf("dmesg-old-%d.log", i))
		mustWrite(t, path, "old")
		ts := prevBoot.Add(-time.Duration(i+1) * time.Hour)
		if err := os.Chtimes(path, ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	oldEncrypted := filepath.Join(dir, "dmesg-efi_pstore-1"+encryptedSuffix)
	mustWrite(t, oldEncrypted, "old")
	ancient := prevBoot.Add(-365 * 24 * time.Hour)
	if err := os.Chtimes(oldEncrypted, ancient, ancient); err != nil {
		t.Fatal(err)
	}
	var files []*kcrashFile
	for i := 0; i < 12; i++ {
		files = append(files, &kcrashFile{
			name:    fmt.Sprintf("pstore-%02d.log", i),
			content: []byte("new"),
			time:    prevBoot.Add(time.Duration(i) * time.Minute),
		})
	}
	const newEncrypted = 16
	for i := 0; i < newEncrypted; i++ {
		files = append(files, &kcrashFile{
			name:    fmt.Sprintf("dmesg-efi_pstore-%d%s", 100+i, encryptedSuffix),
			content: []byte("\x78\x9c"),
			time:    ancient,
		})
	}
	saveKcrashFiles(dir, files)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var dumps, encrypted int
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), encryptedSuffix) {
			encrypted++
		} else {
			dumps++
		}
	}
	if dumps != maxKcrashes {
		t.Errorf("expected %d dump files, got %d", maxKcrashes, dumps)
	}
	if encrypted != newEncrypted+1 {
		t.Errorf("expected %d compressed records, got %d", newEncrypted+1, encrypted)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "dmesg-old") ||
			e.Name() == "pstore-00.log" || e.Name() == "pstore-01.log" {
			t.Errorf("%s should have been rotated out", e.Name())
		}
	}
	for _, f := range files {
		if !f.saved {
			t.Errorf("%s not marked saved", f.name)
		}
	}
}

// logCapture is a logrus hook that records each entry's message and
// obj_type field.
type logCapture struct{ lines []string }

func (c *logCapture) Levels() []logrus.Level { return logrus.AllLevels }
func (c *logCapture) Fire(e *logrus.Entry) error {
	c.lines = append(c.lines, fmt.Sprintf("%v|%s", e.Data["obj_type"], e.Message))
	return nil
}

// captureLog points the package logger at a capturing hook for one test.
func captureLog(t *testing.T) *logCapture {
	t.Helper()
	initTestLog()
	saved := log
	logger := logrus.New()
	logger.SetLevel(logrus.TraceLevel)
	logger.SetOutput(io.Discard)
	c := &logCapture{}
	logger.AddHook(c)
	// NewSourceLogObject caches by source name, so each capture needs its own.
	log = base.NewSourceLogObject(logger, "nodeagent_test_"+t.Name(), 1)
	t.Cleanup(func() { log = saved })
	return c
}

// TestHandlePstoreRecordsLogsKernelStack checks that each dump is logged
// line by line on the kernel_panic_stacks log object, and that the reboot
// stack written from it is not logged a second time.
func TestHandlePstoreRecordsLogsKernelStack(t *testing.T) {
	f := newPstoreFixture(t)
	c := captureLog(t)
	f.addDump(t, "Panic", panicTime, time.Second, panicParts...)

	handlePstoreRecords(f.tc.ctx)
	handleLastRebootReason(f.tc.ctx)

	var header, end, dmesg int
	var tagged []string
	for _, l := range c.lines {
		switch {
		case strings.Contains(l, "|Kernel panic stack trace from pstore (Panic#1"):
			header++
		case strings.HasSuffix(l, "|Kernel panic stack trace: end of stack"):
			end++
		case strings.HasPrefix(l, string(base.KernelPanicStacksType)+"|[kernel panic #"):
			tagged = append(tagged, l)
		case strings.Contains(l, "[dmesg #"):
			dmesg++
		}
	}
	if header != 1 || end != 1 {
		t.Errorf("expected one header and end marker, got %d and %d", header, end)
	}
	// The lines before the panic line, here the dm-verity error, are logged
	// too, although the reboot stack starts at the panic line.
	text := panicParts[2] + panicParts[1] + panicParts[0]
	var want []string
	for i, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		want = append(want, fmt.Sprintf("%s|[kernel panic #%d]: %s",
			base.KernelPanicStacksType, i, l))
	}
	if !slices.Equal(tagged, want) {
		t.Errorf("tagged kernel log lines\n%q\nwant\n%q", tagged, want)
	}
	if strings.Contains(f.tc.ctx.rebootStack, "metadata block 75190") {
		t.Errorf("rebootStack holds the lines before the panic: %q", f.tc.ctx.rebootStack)
	}
	if dmesg != 0 {
		t.Errorf("reboot stack logged again as %d [dmesg] lines", dmesg)
	}
}
