// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/tabwriter"
)

// Output presents the progress of a run.
type Output interface {
	// Started is called once, before any job starts.
	Started(jobs []*Job, parallel int)
	// Line is called for each line of output of a job.
	Line(job *Job, line string)
	// Event is called for a status change worth reporting about a job.
	Event(job *Job, text string)
	// JobDone is called when a job has finished, after its final Event.
	JobDone(job *Job)
	// Finished is called once, after all jobs are done.
	Finished(jobs []*Job)
}

// CountsConsumer is implemented by an Output which wants to show how many jobs
// are in each state. The Orchestrator hands it a function returning the counts.
type CountsConsumer interface {
	SetCounts(func() map[State]int)
}

// SnapshotConsumer is implemented by an Output which wants to read the state
// of the jobs. The Orchestrator hands it a function returning a consistent copy.
type SnapshotConsumer interface {
	SetSnapshot(func() []JobInfo)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// LineWriter splits what is written to it into lines, which it hands to a
// callback and, verbatim, to an optional log file.
type LineWriter struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	onLine  func(line string)
	logFile io.Writer
}

func newLineWriter(onLine func(string), logFile io.Writer) *LineWriter {
	return &LineWriter{onLine: onLine, logFile: logFile}
}

// Write implements io.Writer.
func (w *LineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.logFile != nil {
		_, _ = w.logFile.Write(p)
	}
	w.buf.Write(p)
	for {
		i := bytes.IndexByte(w.buf.Bytes(), '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(w.buf.Next(i+1)), "\r\n")
		w.onLine(line)
	}
	return len(p), nil
}

// Flush emits an unterminated last line.
func (w *LineWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len() > 0 {
		w.onLine(strings.TrimRight(w.buf.String(), "\r\n"))
		w.buf.Reset()
	}
}

func openJobLog(dir string, job *Job) (*os.File, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	job.LogPath = filepath.Join(dir, strings.ReplaceAll(job.Name, "/", "_")+".log")
	return os.Create(job.LogPath)
}

// prefixedOutput prints the output of all jobs interleaved, each line
// prefixed with the job name (in a per-job color, if enabled).
type prefixedOutput struct {
	mu    sync.Mutex
	w     io.Writer
	color bool
	width int
}

// NewPrefixedOutput returns an Output printing every job's output line by
// line to w, prefixed with the job name.
func NewPrefixedOutput(w io.Writer, color bool) Output {
	return &prefixedOutput{w: w, color: color}
}

func (o *prefixedOutput) prefix(job *Job, index int) string {
	name := fmt.Sprintf("%-*s", o.width, job.Name)
	if o.color {
		return fmt.Sprintf("\x1b[%dm[%s]\x1b[0m", 31+index%6, name)
	}
	return "[" + name + "]"
}

func (o *prefixedOutput) index(job *Job) int {
	return int(hash(job.Name))
}

func hash(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h = (h ^ uint32(s[i])) * 16777619
	}
	return h
}

func (o *prefixedOutput) Started(jobs []*Job, parallel int) {
	for _, job := range jobs {
		o.width = max(o.width, len(job.Name))
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	_, _ = fmt.Fprintf(o.w, "Running %d test(s), at most %d at a time\n", len(jobs), parallel)
}

func (o *prefixedOutput) Line(job *Job, line string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, _ = fmt.Fprintf(o.w, "%s %s\n", o.prefix(job, o.index(job)), line)
}

func (o *prefixedOutput) Event(job *Job, text string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, _ = fmt.Fprintf(o.w, "%s >>> %s\n", o.prefix(job, o.index(job)), text)
}

func (o *prefixedOutput) JobDone(*Job) {}

func (o *prefixedOutput) Finished(jobs []*Job) {
	o.mu.Lock()
	defer o.mu.Unlock()
	writeSummary(o.w, jobs)
}

// plainOutput only reports status changes and, for a failed job, the end of
// its output. The full output of every job goes to its log file.
type plainOutput struct {
	mu sync.Mutex
	w  io.Writer
}

// NewPlainOutput returns an Output suited for logs and pipes, i.e. when there is no terminal.
func NewPlainOutput(w io.Writer) Output {
	return &plainOutput{w: w}
}

func (o *plainOutput) Started(jobs []*Job, parallel int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, _ = fmt.Fprintf(o.w, "Running %d test(s), at most %d at a time\n", len(jobs), parallel)
}

func (o *plainOutput) Line(*Job, string) {}

func (o *plainOutput) Event(job *Job, text string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, _ = fmt.Fprintf(o.w, "%s: %s\n", job.Name, text)
}

func (o *plainOutput) JobDone(job *Job) {
	if job.State != Failed {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	_, _ = fmt.Fprintf(o.w, "--- last output of %s ---\n", job.Name)
	for _, line := range job.Tail() {
		_, _ = fmt.Fprintln(o.w, line)
	}
	_, _ = fmt.Fprintf(o.w, "--- end of %s ---\n", job.Name)
}

func (o *plainOutput) Finished(jobs []*Job) {
	o.mu.Lock()
	defer o.mu.Unlock()
	writeSummary(o.w, jobs)
}

// WriteSummary prints the results table of a finished run.
func WriteSummary(w io.Writer, jobs []*Job) {
	writeSummary(w, jobs)
}

func writeSummary(w io.Writer, jobs []*Job) {
	counts := map[State]int{}
	for _, job := range jobs {
		counts[job.State]++
	}
	_, _ = fmt.Fprintf(w, "\nSummary: %d passed, %d failed, %d cancelled\n",
		counts[Passed], counts[Failed], counts[Cancelled]+counts[Queued])
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "  TEST\tRESULT\tDURATION\tLOG")
	for _, job := range jobs {
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", job.Name, job.State, job.Duration(), job.LogPath)
	}
	_ = tw.Flush()
}
