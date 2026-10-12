// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package orchestrator runs several evetest tests or suites as parallel evetest
// instances (containers), each on its own API port. It is the engine behind
// "evetest run", which the Makefile starts in a container when more than one
// test is requested.
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve/evetest/instances"
)

// State of a job.
type State string

// Job states.
const (
	Queued    State = "queued"
	Running   State = "running"
	Passed    State = "passed"
	Failed    State = "failed"
	Cancelled State = "cancelled"
)

const (
	// maxStartAttempts bounds the retries of a job whose container could not
	// start because its API port got taken in the meantime.
	maxStartAttempts = 5
	// tailLines is how many of the last output lines of a job are kept, to
	// show why it failed.
	tailLines = 40
)

// ErrPortBusy is returned by an Executor when the container could not be
// started because its API port is already in use.
var ErrPortBusy = errors.New("API port is already in use")

// Job is one test or suite execution.
type Job struct {
	Name      string
	Port      int
	Container string
	State     State
	ExitCode  int
	Started   time.Time
	Finished  time.Time
	LogPath   string

	tail []string
}

// Duration of the job so far, or in total once finished.
func (j *Job) Duration() time.Duration {
	if j.Started.IsZero() {
		return 0
	}
	if j.Finished.IsZero() {
		return time.Since(j.Started).Round(time.Second)
	}
	return j.Finished.Sub(j.Started).Round(time.Second)
}

// Tail returns the last lines of the job output.
func (j *Job) Tail() []string {
	return j.tail
}

// Executor runs one job to completion.
type Executor interface {
	// Run executes the job in a container named job.Container publishing
	// job.Port, writing its output to out, and returns its exit code. It
	// returns ErrPortBusy if the container could not be started because the
	// port is taken. When ctx is cancelled, Run must stop the job gracefully.
	Run(ctx context.Context, job *Job, out *LineWriter) (exitCode int, err error)
	// Kill terminates a running job's container immediately.
	Kill(job *Job)
}

// Config of an Orchestrator.
type Config struct {
	// Names of the tests and suites to run, in order.
	Names []string
	// Parallel is the maximum number of jobs running at the same time.
	Parallel int
	// FailFast cancels all queued and running jobs once a job fails.
	FailFast bool
	// PortBase is the first API port to try; ports are then tried upwards.
	PortBase int
	// LogDir receives the full output of each job; no logs are kept if empty.
	LogDir string
	// Output reports progress and job output.
	Output Output

	// PortFree reports whether a TCP port can be bound on this host. The
	// default tries to listen on it.
	PortFree func(port int) bool
	// ContainerExists reports whether a container of the given name exists.
	// By default no check is made.
	ContainerExists func(name string) bool
}

// Orchestrator schedules the jobs.
type Orchestrator struct {
	cfg  Config
	exec Executor
	jobs []*Job

	mu    sync.Mutex // guards port allocation and job state
	ports map[int]bool
}

// New creates an Orchestrator. Duplicate names are rejected: the artifacts of two
// runs of the same name started in the same second would collide.
func New(cfg Config, exec Executor) (*Orchestrator, error) {
	if len(cfg.Names) == 0 {
		return nil, errors.New("no tests to run")
	}
	if cfg.Parallel < 1 {
		cfg.Parallel = 1
	}
	if cfg.PortFree == nil {
		cfg.PortFree = tcpPortFree
	}
	if cfg.ContainerExists == nil {
		cfg.ContainerExists = func(string) bool { return false }
	}
	if cfg.Output == nil {
		cfg.Output = NewPlainOutput(discard{})
	}
	r := &Orchestrator{cfg: cfg, exec: exec, ports: map[int]bool{}}
	if c, ok := cfg.Output.(CountsConsumer); ok {
		c.SetCounts(r.counts)
	}
	seen := map[string]bool{}
	for _, name := range cfg.Names {
		if seen[name] {
			return nil, fmt.Errorf("test %q is listed more than once", name)
		}
		seen[name] = true
		r.jobs = append(r.jobs, &Job{Name: name, State: Queued})
	}
	return r, nil
}

// Jobs returns the jobs in the order they were given.
func (r *Orchestrator) Jobs() []*Job {
	return r.jobs
}

// Run executes all jobs, at most Config.Parallel at a time, and returns once
// all of them have finished or been cancelled. Cancelling ctx stops running
// jobs gracefully and cancels the queued ones.
func (r *Orchestrator) Run(ctx context.Context) []*Job {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	queue := make(chan *Job, len(r.jobs))
	for _, job := range r.jobs {
		queue <- job
	}
	close(queue)

	r.cfg.Output.Started(r.jobs, r.cfg.Parallel)
	var wg sync.WaitGroup
	for i := 0; i < min(r.cfg.Parallel, len(r.jobs)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range queue {
				if ctx.Err() != nil {
					r.setState(job, Cancelled)
					r.cfg.Output.Event(job, "cancelled before it started")
					continue
				}
				r.runJob(ctx, job)
				if job.State == Failed && r.cfg.FailFast {
					r.cfg.Output.Event(job, "failed, cancelling the other tests (fail-fast)")
					cancel()
				}
			}
		}()
	}
	wg.Wait()
	r.cfg.Output.Finished(r.jobs)
	return r.jobs
}

// counts returns the number of jobs in each state.
func (r *Orchestrator) counts() map[State]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	counts := map[State]int{}
	for _, job := range r.jobs {
		counts[job.State]++
	}
	return counts
}

// KillAll terminates all running jobs immediately.
func (r *Orchestrator) KillAll() {
	r.mu.Lock()
	var running []*Job
	for _, job := range r.jobs {
		if job.State == Running {
			running = append(running, job)
		}
	}
	r.mu.Unlock()
	for _, job := range running {
		r.exec.Kill(job)
	}
}

func (r *Orchestrator) setState(job *Job, state State) {
	r.mu.Lock()
	job.State = state
	r.mu.Unlock()
}

func (r *Orchestrator) runJob(ctx context.Context, job *Job) {
	logFile, err := openJobLog(r.cfg.LogDir, job)
	if err != nil {
		r.cfg.Output.Event(job, fmt.Sprintf("cannot create the log file: %v", err))
	}
	if logFile != nil {
		defer func() { _ = logFile.Close() }()
	}
	out := newLineWriter(func(line string) {
		r.mu.Lock()
		job.tail = append(job.tail, line)
		if len(job.tail) > tailLines {
			job.tail = job.tail[len(job.tail)-tailLines:]
		}
		r.mu.Unlock()
		r.cfg.Output.Line(job, line)
	}, logFile)

	var exitCode int
	var busyPorts []int
	defer func() {
		for _, p := range busyPorts {
			r.releasePort(p)
		}
	}()
	for attempt := 1; ; attempt++ {
		port, err := r.allocatePort()
		if err != nil {
			r.finish(job, Failed, -1)
			r.cfg.Output.Event(job, fmt.Sprintf("failed: %v", err))
			return
		}
		r.mu.Lock()
		job.Port, job.Container = port, fmt.Sprintf("evetest-%d", port)
		job.State, job.Started = Running, time.Now()
		r.mu.Unlock()
		r.cfg.Output.Event(job, fmt.Sprintf("started on API port %d", port))

		exitCode, err = r.exec.Run(ctx, job, out)
		out.Flush()
		if errors.Is(err, ErrPortBusy) && attempt < maxStartAttempts {
			// Keep the port reserved while retrying, so that it is not
			// tried again; it is released when the job is done.
			busyPorts = append(busyPorts, port)
			continue
		}
		r.releasePort(port)
		if err != nil {
			exitCode = -1
			r.cfg.Output.Event(job, fmt.Sprintf("failed to run: %v", err))
		}
		break
	}

	switch {
	case exitCode == 0:
		r.finish(job, Passed, exitCode)
	case ctx.Err() != nil, stoppedBySignal(exitCode):
		r.finish(job, Cancelled, exitCode)
	default:
		r.finish(job, Failed, exitCode)
	}
	r.cfg.Output.Event(job, fmt.Sprintf("%s after %s (exit code %d)", job.State, job.Duration(), exitCode))
	r.cfg.Output.JobDone(job)
}

// stoppedBySignal tells whether the exit code is that of an evetest container
// stopped from outside, e.g. with "evetest stop": its entrypoint exits with
// 128 plus the number of the SIGINT or SIGTERM it received.
func stoppedBySignal(exitCode int) bool {
	return exitCode == 130 || exitCode == 143
}

func (r *Orchestrator) finish(job *Job, state State, exitCode int) {
	r.mu.Lock()
	job.State, job.ExitCode, job.Finished = state, exitCode, time.Now()
	if job.Started.IsZero() {
		job.Started = job.Finished
	}
	r.mu.Unlock()
}

// allocatePort picks a free API port. It is not enough for the port to be
// free right now: it must not be handed to another job whose container is
// still starting, nor be named in the instance registry or by a container.
func (r *Orchestrator) allocatePort() (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	registered := map[int]bool{}
	if list, err := instances.List(); err == nil {
		for _, inst := range list {
			registered[inst.Port] = true
		}
	}
	for port := r.cfg.PortBase; port <= 65535; port++ {
		if r.ports[port] || registered[port] || !r.cfg.PortFree(port) ||
			r.cfg.ContainerExists(fmt.Sprintf("evetest-%d", port)) {
			continue
		}
		r.ports[port] = true
		return port, nil
	}
	return 0, fmt.Errorf("no free API port from %d upwards", r.cfg.PortBase)
}

func (r *Orchestrator) releasePort(port int) {
	r.mu.Lock()
	delete(r.ports, port)
	r.mu.Unlock()
}

func tcpPortFree(port int) bool {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// Succeeded tells whether every job passed.
func Succeeded(jobs []*Job) bool {
	for _, job := range jobs {
		if job.State != Passed {
			return false
		}
	}
	return true
}

// ParseNames splits a comma-separated list of names.
func ParseNames(list string) []string {
	var names []string
	for _, name := range strings.Split(list, ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}
