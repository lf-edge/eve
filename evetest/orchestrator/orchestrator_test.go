// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeExecutor finishes each job after a delay with a configured exit code.
type fakeExecutor struct {
	delay     time.Duration
	exitCodes map[string]int
	busyPorts map[int]bool // ports on which starting fails once

	mu       sync.Mutex
	running  int
	maxRun   int
	ports    map[string]int
	busyOnce map[int]bool
}

func (f *fakeExecutor) Run(ctx context.Context, job *Job, out *LineWriter) (int, error) {
	f.mu.Lock()
	if f.busyPorts[job.Port] && !f.busyOnce[job.Port] {
		if f.busyOnce == nil {
			f.busyOnce = map[int]bool{}
		}
		f.busyOnce[job.Port] = true
		f.mu.Unlock()
		return 125, ErrPortBusy
	}
	f.running++
	f.maxRun = max(f.maxRun, f.running)
	if f.ports == nil {
		f.ports = map[string]int{}
	}
	f.ports[job.Name] = job.Port
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.running--
		f.mu.Unlock()
	}()

	_, _ = out.Write([]byte("hello from " + job.Name + "\npartial"))
	select {
	case <-time.After(f.delay):
		return f.exitCodes[job.Name], nil
	case <-ctx.Done():
		return 143, nil
	}
}

func (f *fakeExecutor) Kill(*Job) {}

func newTestOrchestrator(t *testing.T, cfg Config, exec Executor) *Orchestrator {
	t.Helper()
	t.Setenv("EVETEST_HOME", t.TempDir())
	if cfg.PortBase == 0 {
		cfg.PortBase = 50021
	}
	cfg.PortFree = func(int) bool { return true }
	r, err := New(cfg, exec)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParallelLimitAndPorts(t *testing.T) {
	exec := &fakeExecutor{delay: 50 * time.Millisecond}
	var buf bytes.Buffer
	r := newTestOrchestrator(t, Config{
		Names: []string{"a", "b", "c", "d", "e"}, Parallel: 2,
		Output: NewPrefixedOutput(&buf, false),
	}, exec)
	jobs := r.Run(context.Background())
	if !Succeeded(jobs) {
		t.Fatalf("expected success: %s", buf.String())
	}
	if exec.maxRun != 2 {
		t.Errorf("max concurrently running = %d, want 2", exec.maxRun)
	}
	if !strings.Contains(buf.String(), "[a] hello from a") ||
		!strings.Contains(buf.String(), "[e] partial") {
		t.Errorf("job output missing or not prefixed:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "5 passed, 0 failed") {
		t.Errorf("unexpected summary:\n%s", buf.String())
	}
}

func TestPortsAreDistinctWhileRunning(t *testing.T) {
	exec := &fakeExecutor{delay: 50 * time.Millisecond}
	r := newTestOrchestrator(t, Config{Names: []string{"a", "b", "c"}, Parallel: 3}, exec)
	r.Run(context.Background())
	seen := map[int]string{}
	for name, port := range exec.ports {
		if other, dup := seen[port]; dup {
			t.Errorf("%s and %s ran on the same port %d at the same time", name, other, port)
		}
		seen[port] = name
	}
}

func TestSequentialByDefault(t *testing.T) {
	exec := &fakeExecutor{delay: 10 * time.Millisecond}
	r := newTestOrchestrator(t, Config{Names: []string{"a", "b", "c"}}, exec)
	r.Run(context.Background())
	if exec.maxRun != 1 {
		t.Errorf("max concurrently running = %d, want 1", exec.maxRun)
	}
}

func TestFailureDoesNotStopOthersByDefault(t *testing.T) {
	exec := &fakeExecutor{exitCodes: map[string]int{"a": 1}}
	r := newTestOrchestrator(t, Config{Names: []string{"a", "b"}}, exec)
	jobs := r.Run(context.Background())
	if jobs[0].State != Failed || jobs[1].State != Passed {
		t.Errorf("states = %s, %s; want failed, passed", jobs[0].State, jobs[1].State)
	}
	if Succeeded(jobs) {
		t.Error("Succeeded() = true with a failed job")
	}
}

func TestStoppedJobIsCancelledNotFailed(t *testing.T) {
	exec := &fakeExecutor{exitCodes: map[string]int{"a": 143}}
	r := newTestOrchestrator(t, Config{Names: []string{"a", "b"}, FailFast: true}, exec)
	jobs := r.Run(context.Background())
	if jobs[0].State != Cancelled || jobs[1].State != Passed {
		t.Errorf("states = %s, %s; want cancelled, passed (a stop must not trigger fail-fast)",
			jobs[0].State, jobs[1].State)
	}
	if Succeeded(jobs) {
		t.Error("Succeeded() = true with a stopped job")
	}
}

func TestFailFast(t *testing.T) {
	exec := &fakeExecutor{delay: 5 * time.Second, exitCodes: map[string]int{}}
	exec.exitCodes["a"] = 1
	// a fails quickly, b is long-running and must be cancelled, c never starts.
	fast := &perJobDelay{fakeExecutor: exec, delays: map[string]time.Duration{"a": 20 * time.Millisecond}}
	r := newTestOrchestrator(t, Config{Names: []string{"a", "b", "c"}, Parallel: 2, FailFast: true}, fast)
	start := time.Now()
	jobs := r.Run(context.Background())
	if time.Since(start) > 2*time.Second {
		t.Fatal("fail-fast did not cancel the running job")
	}
	want := []State{Failed, Cancelled, Cancelled}
	for i, job := range jobs {
		if job.State != want[i] {
			t.Errorf("job %s: state %s, want %s", job.Name, job.State, want[i])
		}
	}
}

type perJobDelay struct {
	*fakeExecutor
	delays map[string]time.Duration
}

func (p *perJobDelay) Run(ctx context.Context, job *Job, out *LineWriter) (int, error) {
	if d, ok := p.delays[job.Name]; ok {
		select {
		case <-time.After(d):
			return p.exitCodes[job.Name], nil
		case <-ctx.Done():
			return 143, nil
		}
	}
	return p.fakeExecutor.Run(ctx, job, out)
}

func TestCancelStopsRunningAndQueued(t *testing.T) {
	exec := &fakeExecutor{delay: 5 * time.Second}
	r := newTestOrchestrator(t, Config{Names: []string{"a", "b", "c"}, Parallel: 1}, exec)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	jobs := r.Run(ctx)
	for _, job := range jobs {
		if job.State != Cancelled {
			t.Errorf("job %s: state %s, want cancelled", job.Name, job.State)
		}
	}
}

func TestPortBusyRetriesOnNextPort(t *testing.T) {
	exec := &fakeExecutor{busyPorts: map[int]bool{50021: true}}
	r := newTestOrchestrator(t, Config{Names: []string{"a"}}, exec)
	jobs := r.Run(context.Background())
	if jobs[0].State != Passed || jobs[0].Port != 50022 {
		t.Errorf("state %s on port %d, want passed on 50022", jobs[0].State, jobs[0].Port)
	}
}

func TestAllocatePortSkipsUnavailable(t *testing.T) {
	t.Setenv("EVETEST_HOME", t.TempDir())
	r, err := New(Config{
		Names:           []string{"a"},
		PortBase:        50021,
		PortFree:        func(p int) bool { return p != 50021 },
		ContainerExists: func(n string) bool { return n == "evetest-50022" },
	}, &fakeExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	port, err := r.allocatePort()
	if err != nil || port != 50023 {
		t.Errorf("allocatePort() = %d, %v; want 50023", port, err)
	}
}

func TestDuplicateAndEmptyNames(t *testing.T) {
	if _, err := New(Config{Names: []string{"a", "a"}}, &fakeExecutor{}); err == nil {
		t.Error("duplicate names accepted")
	}
	if _, err := New(Config{}, &fakeExecutor{}); err == nil {
		t.Error("empty list accepted")
	}
}

func TestPlainOutputShowsTailOfFailedJob(t *testing.T) {
	exec := &fakeExecutor{exitCodes: map[string]int{"a": 2}}
	var buf bytes.Buffer
	r := newTestOrchestrator(t, Config{Names: []string{"a", "b"}, Output: NewPlainOutput(&buf)}, exec)
	r.Run(context.Background())
	out := buf.String()
	if !strings.Contains(out, "--- last output of a ---\nhello from a\npartial") {
		t.Errorf("missing tail of failed job:\n%s", out)
	}
	if strings.Contains(out, "last output of b") {
		t.Errorf("tail printed for a passed job:\n%s", out)
	}
}

func TestLogFileHasFullOutput(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeExecutor{}
	r := newTestOrchestrator(t, Config{Names: []string{"suite/x"}, LogDir: dir}, exec)
	jobs := r.Run(context.Background())
	if !strings.HasSuffix(jobs[0].LogPath, "suite_x.log") {
		t.Fatalf("log path %q", jobs[0].LogPath)
	}
}

func TestRerun(t *testing.T) {
	dir := t.TempDir()
	exec := &fakeExecutor{exitCodes: map[string]int{"a": 1}}
	var finished int
	r := newTestOrchestrator(t, Config{
		Names: []string{"a", "b"}, Parallel: 2, LogDir: dir,
		Output: &finishCounter{Output: NewPlainOutput(discard{}), n: &finished},
	}, exec)
	jobs := r.Run(context.Background())
	if jobs[0].State != Failed || jobs[1].State != Passed || finished != 1 {
		t.Fatalf("states %s, %s, finished %d", jobs[0].State, jobs[1].State, finished)
	}
	if err := r.Rerun("b", Versions{}); err != nil {
		t.Fatal(err)
	}
	if err := r.Rerun("nosuch", Versions{}); err == nil {
		t.Error("rerun of an unknown test accepted")
	}
	exec.mu.Lock()
	exec.exitCodes["a"] = 0
	exec.mu.Unlock()
	r.Wait()
	if err := r.Rerun("a", Versions{}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	if jobs[0].State != Passed || jobs[0].ExitCode != 0 || jobs[0].Attempt != 2 {
		t.Errorf("a: state %s, exit code %d, attempt %d", jobs[0].State, jobs[0].ExitCode, jobs[0].Attempt)
	}
	if finished != 3 {
		t.Errorf("Finished called %d times, want 3", finished)
	}
	if !strings.HasSuffix(jobs[0].LogPath, "a.2.log") {
		t.Errorf("log of the rerun overwrites the first: %s", jobs[0].LogPath)
	}
}

func TestRerunChangesVersions(t *testing.T) {
	exec := &fakeExecutor{}
	r := newTestOrchestrator(t, Config{
		Names: []string{"a", "b"}, Parallel: 2, Versions: Versions{Evetest: "e1", SDN: "s1"},
	}, exec)
	jobs := r.Run(context.Background())
	if err := r.Rerun("a", Versions{Evetest: "e2"}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	if got := jobs[0].Versions; got != (Versions{Evetest: "e2", SDN: "s1"}) {
		t.Errorf("a runs with %+v, want e2 and the previous SDN version", got)
	}
	if got := jobs[1].Versions; got != (Versions{Evetest: "e1", SDN: "s1"}) {
		t.Errorf("b was changed to %+v", got)
	}
}

func TestCancelQueuedJobDoesNotRunAndCanBeRerun(t *testing.T) {
	exec := &fakeExecutor{delay: 300 * time.Millisecond}
	r := newTestOrchestrator(t, Config{Names: []string{"a", "b", "c"}, Parallel: 1}, exec)
	done := make(chan []*Job)
	go func() { done <- r.Run(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	if err := r.CancelQueued("b"); err != nil {
		t.Fatal(err)
	}
	if err := r.CancelQueued("a"); err == nil {
		t.Error("a running test was cancelled as if queued")
	}
	jobs := <-done
	if jobs[0].State != Passed || jobs[1].State != Cancelled || jobs[2].State != Passed {
		t.Fatalf("states %s, %s, %s; want passed, cancelled, passed", jobs[0].State, jobs[1].State, jobs[2].State)
	}
	if _, ran := exec.ports["b"]; ran {
		t.Error("the cancelled test ran")
	}
	if err := r.Rerun("b", Versions{}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	if jobs[1].State != Passed {
		t.Errorf("rerun of the cancelled test: %s", jobs[1].State)
	}
}

func TestRerunRefusedWhileActiveOrStopping(t *testing.T) {
	exec := &fakeExecutor{delay: 5 * time.Second}
	r := newTestOrchestrator(t, Config{Names: []string{"a", "b"}, Parallel: 1}, exec)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	if err := r.Rerun("a", Versions{}); err == nil {
		t.Error("rerun of a running test accepted")
	}
	if err := r.Rerun("b", Versions{}); err == nil {
		t.Error("rerun of a queued test accepted")
	}
	cancel()
	<-done
	if err := r.Rerun("a", Versions{}); err == nil {
		t.Error("rerun accepted after the run was stopped")
	}
}

type finishCounter struct {
	Output
	n *int
}

func (f *finishCounter) Finished(jobs []*Job) {
	*f.n++
	f.Output.Finished(jobs)
}

func TestParseNames(t *testing.T) {
	got := ParseNames(" a, b ,,c ")
	if strings.Join(got, "|") != "a|b|c" {
		t.Errorf("ParseNames = %v", got)
	}
}
