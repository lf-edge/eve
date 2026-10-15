// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tmuxSession = "run"
	// paneInterval is how often a running job's pane is checked for exit.
	paneInterval = 300 * time.Millisecond
)

var tmuxPrefixRe = regexp.MustCompile(`^(C-|M-)?[a-zA-Z0-9]$`)

// TmuxConfig configures a TmuxUI.
type TmuxConfig struct {
	RunID string
	// Prefix is the tmux prefix key, e.g. "C-a". It differs from tmux's default
	// so that it does not clash with a tmux already running on the user's side.
	Prefix string
	// Docker describes the jobs' containers. Interactive and color output are
	// set by the TmuxUI.
	Docker DockerExecutor
	// StopPID is signalled (SIGINT) by the "stop all" key binding.
	StopPID int
	// Width and Height give the initial terminal size.
	Width, Height int
	// EVE says which EVE is tested, e.g. "EVE 0.0.0-master-e933b992"; it is shown
	// in the status line. May be empty.
	EVE string
}

// TmuxUI shows the jobs in the panes of a single tmux session, tiled in one
// window, all visible in the terminal at once. A job's container runs in the
// foreground of its pane (docker run -it), so the pane takes keyboard input
// (e.g. to resume a paused test), has scrollback and can be zoomed. It is both
// an Output and the source of the Executor which runs the jobs in the panes.
//
// A failed job's pane moves to a window of its own, so that its output stays
// on screen without taking a place in the tiles. The pane of a job which passed
// (or was stopped) is closed right away; its output is in its log file. The
// first window lists what the orchestrator reports as it happens, and its
// summary at the end.
type TmuxUI struct {
	cfg    TmuxConfig
	dir    string
	conf   string
	events string
	socket string
	// cliScript opens a shell for the evetest CLI next to a test's pane.
	cliScript string

	mu         sync.Mutex
	counts     func() map[State]int
	total      int
	finished   bool
	jobsWindow string
	panes      map[string]string // job name -> pane id
	attach     *exec.Cmd
	closed     chan struct{}
	startErr   error
}

// NewTmuxUI prepares a tmux UI; the session starts with Output.Started.
func NewTmuxUI(cfg TmuxConfig) (*TmuxUI, error) {
	if _, err := exec.LookPath("tmux"); err != nil {
		return nil, errors.New("tmux is not installed")
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "C-a"
	}
	if !tmuxPrefixRe.MatchString(cfg.Prefix) {
		return nil, fmt.Errorf("invalid tmux prefix key %q (examples: C-a, C-b, M-a)", cfg.Prefix)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		cfg.Width, cfg.Height = 200, 50
	}
	cfg.Docker.Interactive = true
	cfg.Docker.ColorOutput = "true"

	dir, err := os.MkdirTemp("", "evetest-tmux-")
	if err != nil {
		return nil, err
	}
	u := &TmuxUI{
		cfg:    cfg,
		dir:    dir,
		conf:   filepath.Join(dir, "tmux.conf"),
		events: filepath.Join(dir, "events.log"),
		socket: "evetest-" + cfg.RunID,
		panes:  map[string]string{},
		closed: make(chan struct{}),

		cliScript: filepath.Join(dir, "cli-pane.sh"),
	}
	if err = os.WriteFile(u.events, nil, 0o600); err != nil {
		return nil, err
	}
	if err = os.WriteFile(u.cliScript, []byte(cliPaneScript), 0o600); err != nil {
		return nil, err
	}
	if err = os.WriteFile(u.conf, []byte(u.config()), 0o600); err != nil {
		return nil, err
	}
	return u, nil
}

// cliPaneScript opens a shell for the evetest CLI next to the pane of a test.
// It is run by the key bindings with the split direction (-v: below, -h: to the
// right), the pane to split and the port and name of its test. The shell gets
// the port in EVETEST_INSTANCE, so that "evetest" commands in it act on that
// test without --instance; the pane options let the border say what it is. Unlike
// the panes of tests, which stay to show their output, the shell's pane goes
// away when the shell exits.
const cliPaneScript = `#!/bin/sh
flag=$1
target=$2
port=$3
name=$4
if [ -z "$port" ]; then
    tmux display-message "evetest: select the pane of a test first"
    exit 0
fi
pane=$(tmux split-window "$flag" -t "$target" -P -F '#{pane_id}' -e "EVETEST_INSTANCE=$port") || exit 0
tmux set-option -p -t "$pane" @evetest_port "$port"
tmux set-option -p -t "$pane" @evetest_name "$name"
tmux set-option -p -t "$pane" @evetest_role cli
tmux set-option -p -t "$pane" remain-on-exit off
`

// paneBorderFormat is the title of a pane: a test's name, port and state, or,
// for a CLI shell, whose shell it is.
const paneBorderFormat = `#{?#{==:#{@evetest_role},cli},` +
	` #{@evetest_name}: evetest CLI shell ,` +
	`#{?#{@evetest_name},` +
	` #{@evetest_name} (API port #{@evetest_port}) ` +
	`#{?pane_dead,#{?#{==:#{pane_dead_status},0},PASSED,FAILED (exit code #{pane_dead_status})},RUNNING} ,` +
	` orchestrator }}`

func (u *TmuxUI) config() string {
	p := u.cfg.Prefix
	cli := func(flag string) string {
		return `run-shell "sh ` + u.cliScript + ` ` + flag + ` '#{pane_id}' '#{@evetest_port}' '#{@evetest_name}'"`
	}
	return strings.NewReplacer(
		"@PREFIX@", p,
		"@KEY@", strings.TrimPrefix(strings.TrimPrefix(p, "C-"), "M-"),
		"@PID@", strconv.Itoa(u.cfg.StopPID),
		"@BORDER@", paneBorderFormat,
		"@CLI_BELOW@", cli("-v"),
		"@CLI_RIGHT@", cli("-h"),
	).Replace(`set -g prefix @PREFIX@
unbind C-b
bind @KEY@ send-prefix
set -g mouse on
set -g history-limit 100000
set -g remain-on-exit on
set -g default-terminal screen-256color
set -sg escape-time 10
set -g status on
set -g status-left-length 400
set -g status-right ''
set -g pane-border-status top
set -g pane-border-format '@BORDER@'
unbind d
bind Q if-shell -F "#{@evetest_finished}" "kill-session" "confirm-before -p \"Stop all tests and close? (y/n)\" kill-session"
bind X run-shell "kill -INT @PID@"
bind e @CLI_BELOW@
bind '"' @CLI_BELOW@
bind % @CLI_RIGHT@
`)
}

func (u *TmuxUI) tmux(args ...string) (string, error) {
	full := append([]string{"-u", "-L", u.socket, "-f", u.conf}, args...)
	out, err := exec.Command("tmux", full...).CombinedOutput()
	text := strings.TrimRight(string(out), "\n")
	if err != nil {
		return text, fmt.Errorf("tmux %s: %w: %s", args[0], err, text)
	}
	return text, nil
}

// Closed is closed once the user's tmux client has exited, whether because
// the user closed the session or because it was torn down.
func (u *TmuxUI) Closed() <-chan struct{} {
	return u.closed
}

// Wait blocks until the user closes the session.
func (u *TmuxUI) Wait() {
	<-u.closed
}

// Close tears down the tmux server and removes its files.
func (u *TmuxUI) Close() {
	_, _ = u.tmux("kill-server")
	_ = os.RemoveAll(u.dir)
}

// SetCounts implements CountsConsumer.
func (u *TmuxUI) SetCounts(f func() map[State]int) {
	u.counts = f
}

// Started implements Output: it starts the session and attaches the terminal.
func (u *TmuxUI) Started(jobs []*Job, parallel int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.total = len(jobs)
	_, err := u.tmux("new-session", "-d", "-s", tmuxSession, "-n", "orchestrator",
		"-x", strconv.Itoa(u.cfg.Width), "-y", strconv.Itoa(u.cfg.Height),
		"tail -n +1 -F "+shellQuote(u.events))
	if err != nil {
		u.startErr = err
		fmt.Fprintln(os.Stderr, err)
		close(u.closed)
		return
	}
	u.appendEvent(fmt.Sprintf("Running %d test(s), at most %d at a time", len(jobs), parallel))
	if u.cfg.EVE != "" {
		u.appendText("Testing " + u.cfg.EVE)
	}
	u.appendText("")
	u.appendText(u.keysHelp())
	u.appendText("")
	u.updateStatus()

	u.attach = exec.Command("tmux", "-u", "-L", u.socket, "attach-session", "-t", tmuxSession)
	u.attach.Stdin, u.attach.Stdout, u.attach.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err = u.attach.Start(); err != nil {
		u.startErr = err
		fmt.Fprintln(os.Stderr, err)
		close(u.closed)
		return
	}
	go func() {
		_ = u.attach.Wait()
		close(u.closed)
	}()
}

// Line implements Output. The output of a job is in its pane.
func (u *TmuxUI) Line(*Job, string) {}

// Event implements Output.
func (u *TmuxUI) Event(job *Job, text string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.appendEvent(job.Name + ": " + text)
	u.updateStatus()
}

// JobDone implements Output: it moves the pane of a failed job to a window of
// its own and marks the panes of the others for removal.
func (u *TmuxUI) JobDone(job *Job) {
	u.mu.Lock()
	defer u.mu.Unlock()
	pane := u.panes[job.Name]
	if pane == "" {
		return
	}
	if job.State == Failed {
		u.keepFailed(pane, job.Name)
	} else {
		_, _ = u.tmux("kill-pane", "-t", pane)
	}
	delete(u.panes, job.Name)
	// Let the remaining panes use the space which became free. The window is
	// gone if that was its last pane.
	if u.jobsWindow != "" {
		_, _ = u.tmux("select-layout", "-t", u.jobsWindow, "tiled")
	}
	u.updateStatus()
}

// keepFailed gives the pane of a failed job a window of its own, so that its
// output stays on screen. If it is the only pane of the jobs window, tmux would
// just rename that window, so do that and let the next job get a new jobs
// window. u.mu must be held.
func (u *TmuxUI) keepFailed(pane, name string) {
	title := "FAILED " + name
	out, err := u.tmux("display-message", "-p", "-t", pane, "#{window_id} #{window_panes}")
	if fields := strings.Fields(out); err == nil && len(fields) == 2 &&
		fields[0] == u.jobsWindow && fields[1] == "1" {
		if _, err = u.tmux("rename-window", "-t", u.jobsWindow, title); err != nil {
			u.appendEvent(err.Error())
		}
		u.jobsWindow = ""
		return
	}
	if _, err = u.tmux("break-pane", "-d", "-s", pane, "-n", title); err != nil {
		u.appendEvent(err.Error())
	}
}

// Finished implements Output.
func (u *TmuxUI) Finished(jobs []*Job) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.finished = true
	// Closing the session needs no confirmation once nothing is running.
	_, _ = u.tmux("set-option", "-g", "@evetest_finished", "1")
	var sb strings.Builder
	WriteSummary(&sb, jobs)
	u.appendText(sb.String())
	u.appendText(u.outputHelp())
	u.appendText("All tests finished. Close this session with " + u.cfg.Prefix + " Q.")
	u.updateStatus()
}

// keysHelp explains how to move around, for the orchestrator window.
func (u *TmuxUI) keysHelp() string {
	p := u.cfg.Prefix
	return "Keys (prefix is " + p + "): click a pane, or press " + p + " and an arrow key (or o), to select it;\n" +
		"  " + p + " z zooms it. " + p + " n / " + p + " p switch windows (this one, failed tests).\n" +
		"  " + p + " e opens a shell below the selected test for the evetest CLI (exit closes it).\n" +
		"  " + p + " Q closes the session, " + p + " X stops all tests.\n" +
		"  Scroll a pane with the mouse wheel, or " + p + " [ and then PgUp/PgDn/arrows (q leaves)."
}

// outputHelp tells where to find the output of the finished tests. u.mu must
// be held.
func (u *TmuxUI) outputHelp() string {
	p := u.cfg.Prefix
	var sb strings.Builder
	sb.WriteString("Output of the tests:\n")
	windows, _ := u.tmux("list-windows", "-F", "#{window_index} #{window_name}")
	failed := 0
	for _, line := range strings.Split(windows, "\n") {
		index, name, ok := strings.Cut(line, " ")
		if ok && strings.HasPrefix(name, "FAILED ") {
			fmt.Fprintf(&sb, "  %s %s  shows the output of %s (scroll with the mouse wheel or %s [)\n",
				p, index, strings.TrimPrefix(name, "FAILED "), p)
			failed++
		}
	}
	if failed > 0 {
		fmt.Fprintf(&sb, "  (the failed tests are in windows named FAILED <test>, also %s n / %s p)\n", p, p)
	}
	sb.WriteString("  The full output of every test is in its log file, see the LOG column above.")
	return sb.String()
}

// appendEvent adds a line, with the time, to the orchestrator window.
func (u *TmuxUI) appendEvent(text string) {
	u.appendText(time.Now().Format("15:04:05") + " " + text)
}

// appendText adds text as it is to the orchestrator window.
func (u *TmuxUI) appendText(text string) {
	f, err := os.OpenFile(u.events, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintln(f, text)
}

// updateStatus refreshes the status line. u.mu must be held.
func (u *TmuxUI) updateStatus() {
	_, _ = u.tmux("set-option", "-g", "status-left", strings.ReplaceAll(u.statusText(), "#", "##"))
}

// statusText is the left part of the status line. u.mu must be held.
func (u *TmuxUI) statusText() string {
	title := "evetest " + u.cfg.RunID
	if u.finished {
		title += " FINISHED"
	}
	text := " " + title + ":"
	if u.counts != nil {
		c := u.counts()
		text += fmt.Sprintf(" running %d, queued %d, passed %d, failed %d",
			c[Running], c[Queued], c[Passed], c[Failed])
	}
	if u.cfg.EVE != "" {
		text += " | " + u.cfg.EVE
	}
	return fmt.Sprintf("%s | %s Q: close, %s X: stop all | ", text, u.cfg.Prefix, u.cfg.Prefix)
}

// Executor returns the Executor running the jobs in the panes.
func (u *TmuxUI) Executor() Executor {
	return &tmuxExecutor{u: u}
}

// spawn starts the command in a new pane of the jobs window.
func (u *TmuxUI) spawn(job *Job, command string) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.startErr != nil {
		return "", u.startErr
	}
	var pane string
	if u.jobsWindow != "" {
		out, err := u.tmux("split-window", "-d", "-P", "-F", "#{pane_id}", "-t", u.jobsWindow, command)
		if err == nil {
			pane = out
		} else {
			u.jobsWindow = ""
		}
	}
	if u.jobsWindow == "" {
		out, err := u.tmux("new-window", "-d", "-P", "-F", "#{pane_id} #{window_id}",
			"-t", tmuxSession+":", "-n", "jobs", command)
		if err != nil {
			return "", err
		}
		fields := strings.Fields(out)
		if len(fields) != 2 {
			return "", fmt.Errorf("unexpected tmux output %q", out)
		}
		pane, u.jobsWindow = fields[0], fields[1]
		_, _ = u.tmux("select-window", "-t", u.jobsWindow)
	}
	u.panes[job.Name] = pane
	_, _ = u.tmux("set-option", "-p", "-t", pane, "@evetest_name", job.Name)
	_, _ = u.tmux("set-option", "-p", "-t", pane, "@evetest_port", strconv.Itoa(job.Port))

	_, _ = u.tmux("select-layout", "-t", u.jobsWindow, "tiled")
	return pane, nil
}

// paneState reports whether the pane's command has exited, with its exit code.
// exists is false if the pane is gone (e.g. closed by the user).
func (u *TmuxUI) paneState(pane string) (dead bool, status int, exists bool) {
	out, err := u.tmux("display-message", "-p", "-t", pane, "#{pane_dead}:#{pane_dead_status}:#{pane_dead_signal}")
	if err != nil {
		return false, 0, false
	}
	fields := strings.Split(out, ":")
	if len(fields) != 3 {
		return false, 0, false
	}
	if fields[0] != "1" {
		return false, 0, true
	}
	if fields[1] != "" {
		status, _ = strconv.Atoi(fields[1])
	} else if sig, err := strconv.Atoi(fields[2]); err == nil {
		status = 128 + sig
	}
	return true, status, true
}

type tmuxExecutor struct {
	u *TmuxUI
}

// Run implements Executor.
func (e *tmuxExecutor) Run(ctx context.Context, job *Job, out *LineWriter) (int, error) {
	u := e.u
	args := append([]string{"docker"}, u.cfg.Docker.runArgs(job)...)
	pane, err := u.spawn(job, shellJoin(args))
	if err != nil {
		return -1, err
	}

	done := ctx.Done()
	var dead bool
	var status int
	for !dead {
		select {
		case <-done:
			done = nil
			go func() {
				_ = exec.Command("docker", "stop", "-t", gracefulStopTimeout, job.Container).Run()
			}()
		case <-time.After(paneInterval):
		}
		var exists bool
		dead, status, exists = u.paneState(pane)
		if !exists {
			// The user closed the pane, which is an intentional stop (reported
			// as SIGTERM); the container may still be running.
			_ = exec.Command("docker", "stop", "-t", gracefulStopTimeout, job.Container).Run()
			return 143, nil
		}
	}

	// The pane keeps its content; save it as the job's log.
	text, _ := u.tmux("capture-pane", "-p", "-J", "-S", "-", "-t", pane)
	_, _ = out.Write([]byte(text + "\n"))
	if status == 125 && portBusy(strings.Split(text, "\n")) {
		_, _ = u.tmux("kill-pane", "-t", pane)
		return status, ErrPortBusy
	}
	return status, nil
}

// Kill implements Executor.
func (e *tmuxExecutor) Kill(job *Job) {
	_ = exec.Command("docker", "kill", job.Container).Run()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellJoin(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = shellQuote(a)
	}
	return strings.Join(quoted, " ")
}
