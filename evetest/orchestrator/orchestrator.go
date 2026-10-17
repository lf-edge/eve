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
	"slices"
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

// Versions are the versions of the evetest and SDN images a job runs with. An
// empty field means that the shared setting of the run applies.
type Versions struct {
	Evetest string
	SDN     string
}

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
	// Attempt counts the executions of the job: 1 for the first, more for
	// each rerun.
	Attempt int
	// Versions of the images the job runs with; a rerun may change them.
	Versions Versions

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
	// Versions the jobs run with at first.
	Versions Versions

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

	// notifyMu serializes the call of Output.Finished, which tells that the
	// orchestrator went idle, with Rerun, which ends the idleness. It is taken
	// before mu.
	notifyMu sync.Mutex

	mu      sync.Mutex // guards port allocation, job state and the queue
	ports   map[int]bool
	pending []queuedJob
	workers int // goroutines executing jobs, at most Config.Parallel
	// parent is the context passed to Run; reruns are bound to it.
	parent context.Context
	idle   *sync.Cond
}

// queuedJob is a job waiting for a free slot.
type queuedJob struct {
	job *Job
	ctx context.Context
	// cancel stops the other jobs of the same Run call once this one fails,
	// if fail-fast is on; nil for a rerun.
	cancel context.CancelFunc
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
	r.idle = sync.NewCond(&r.mu)
	if c, ok := cfg.Output.(CountsConsumer); ok {
		c.SetCounts(r.counts)
	}
	if c, ok := cfg.Output.(SnapshotConsumer); ok {
		c.SetSnapshot(r.snapshot)
	}
	seen := map[string]bool{}
	for _, name := range cfg.Names {
		if seen[name] {
			return nil, fmt.Errorf("test %q is listed more than once", name)
		}
		seen[name] = true
		r.jobs = append(r.jobs, &Job{Name: name, State: Queued, Versions: cfg.Versions})
	}
	return r, nil
}

// Jobs returns the jobs in the order they were given.
func (r *Orchestrator) Jobs() []*Job {
	return r.jobs
}

// Run executes all jobs, at most Config.Parallel at a time, and returns once
// all of them have finished or been cancelled. Cancelling ctx stops running
// jobs gracefully and cancels the queued ones. Jobs may be run again with
// Rerun after that; Wait then tells when they are done.
func (r *Orchestrator) Run(ctx context.Context) []*Job {
	batch, cancel := context.WithCancel(ctx)
	defer cancel()

	r.cfg.Output.Started(r.jobs, r.cfg.Parallel)
	r.mu.Lock()
	r.parent = ctx
	for _, job := range r.jobs {
		r.pending = append(r.pending, queuedJob{job: job, ctx: batch, cancel: cancel})
	}
	r.mu.Unlock()
	r.schedule()
	r.Wait()
	return r.jobs
}

// Wait blocks until no job is queued or running.
func (r *Orchestrator) Wait() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for r.workers > 0 || len(r.pending) > 0 {
		r.idle.Wait()
	}
}

// Rerun queues a finished job to be executed again, with a fresh output and
// log, and with the given versions of the images; empty fields keep those of
// the previous execution. It fails if the job is queued or running, or if the run is being
// stopped. Fail-fast does not apply to reruns.
func (r *Orchestrator) Rerun(name string, versions Versions) error {
	r.notifyMu.Lock()
	defer r.notifyMu.Unlock()
	r.mu.Lock()
	var job *Job
	for _, j := range r.jobs {
		if j.Name == name {
			job = j
		}
	}
	switch {
	case job == nil:
		r.mu.Unlock()
		return fmt.Errorf("no test %q in this run", name)
	case r.parent == nil:
		r.mu.Unlock()
		return errors.New("the run has not started")
	case r.parent.Err() != nil:
		r.mu.Unlock()
		return errors.New("the run is being stopped")
	case job.State != Passed && job.State != Failed && job.State != Cancelled:
		state := job.State
		r.mu.Unlock()
		return fmt.Errorf("test is %s", state)
	}
	job.State, job.ExitCode = Queued, 0
	job.Started, job.Finished = time.Time{}, time.Time{}
	job.Port, job.Container, job.tail = 0, "", nil
	if versions.Evetest != "" {
		job.Versions.Evetest = versions.Evetest
	}
	if versions.SDN != "" {
		job.Versions.SDN = versions.SDN
	}
	r.pending = append(r.pending, queuedJob{job: job, ctx: r.parent})
	r.mu.Unlock()
	r.schedule()
	r.cfg.Output.Event(job, "queued for a rerun")
	return nil
}

// CancelQueued cancels a job which is still waiting for a free slot, so that it
// does not run; Rerun queues it again. It fails if the job is not waiting, e.g.
// because it has just been started.
func (r *Orchestrator) CancelQueued(name string) error {
	r.mu.Lock()
	var job *Job
	for i, q := range r.pending {
		if q.job.Name == name {
			job = q.job
			r.pending = slices.Delete(r.pending, i, i+1)
			job.State = Cancelled
			break
		}
	}
	r.mu.Unlock()
	if job == nil {
		return errors.New("test is not waiting in the queue")
	}
	r.cfg.Output.Event(job, "cancelled before it started")
	return nil
}

// schedule starts workers for queued jobs while there are free slots.
func (r *Orchestrator) schedule() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for r.workers < r.cfg.Parallel && len(r.pending) > 0 {
		q := r.pending[0]
		r.pending = r.pending[1:]
		r.workers++
		go r.work(q)
	}
}

// work executes queued jobs one after another until none is left. The last
// worker to finish reports that the orchestrator is idle.
func (r *Orchestrator) work(q queuedJob) {
	for {
		if q.ctx.Err() != nil {
			r.setState(q.job, Cancelled)
			r.cfg.Output.Event(q.job, "cancelled before it started")
		} else {
			r.runJob(q.ctx, q.job)
			if q.job.State == Failed && r.cfg.FailFast && q.cancel != nil {
				r.cfg.Output.Event(q.job, "failed, cancelling the other tests (fail-fast)")
				q.cancel()
			}
		}

		r.notifyMu.Lock()
		r.mu.Lock()
		if len(r.pending) > 0 {
			q = r.pending[0]
			r.pending = r.pending[1:]
			r.mu.Unlock()
			r.notifyMu.Unlock()
			continue
		}
		last := r.workers == 1
		r.mu.Unlock()
		if last {
			r.cfg.Output.Finished(r.jobs)
		}
		r.mu.Lock()
		r.workers--
		r.idle.Broadcast()
		r.mu.Unlock()
		r.notifyMu.Unlock()
		return
	}
}

// JobInfo is a consistent copy of a job's state.
type JobInfo struct {
	Name      string
	State     State
	Port      int
	Container string
	ExitCode  int
	Started   time.Time
	Finished  time.Time
	Versions  Versions
}

// Duration of the job so far, or in total once finished.
func (j JobInfo) Duration() time.Duration {
	if j.Started.IsZero() {
		return 0
	}
	if j.Finished.IsZero() {
		return time.Since(j.Started).Round(time.Second)
	}
	return j.Finished.Sub(j.Started).Round(time.Second)
}

// snapshot returns a copy of the state of all jobs, in order.
func (r *Orchestrator) snapshot() []JobInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	infos := make([]JobInfo, len(r.jobs))
	for i, j := range r.jobs {
		infos[i] = JobInfo{j.Name, j.State, j.Port, j.Container, j.ExitCode, j.Started, j.Finished, j.Versions}
	}
	return infos
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
	r.mu.Lock()
	job.Attempt++
	r.mu.Unlock()
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
