// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/lf-edge/eve/evetest/instances"
)

const (
	// dashboardLogLines is how many lines of output of a job the dashboard
	// keeps for its log view.
	dashboardLogLines = 5000
	dashboardTick     = 250 * time.Millisecond
	statePollInterval = 2 * time.Second
	// minTableNameWidth keeps the name column readable for short names.
	minTableNameWidth = 12
	// flashDuration is how long a message stays in place of the key help.
	flashDuration = 6 * time.Second
)

// logLineRe matches the log lines of the harness and the broker.
var logLineRe = regexp.MustCompile(`^(\w+)\s+time="[^"]*"\s+level=(\w+)\s+msg="(.*)"$`)

// sanitizeLine makes a line of job output safe to place on the screen: a
// carriage return rewinds the line, so only what follows it counts, and tabs
// are expanded (the terminal's tab stops would shift the columns).
func sanitizeLine(line string) string {
	line = strings.TrimRight(line, "\r")
	if i := strings.LastIndex(line, "\r"); i >= 0 {
		line = line[i+1:]
	}
	return strings.ReplaceAll(line, "\t", "    ")
}

// summarizeLine shortens a line for the table: the framework's log lines lose
// their timestamp and quoting.
func summarizeLine(line string) string {
	line = strings.TrimSpace(ansi.Strip(line))
	if m := logLineRe.FindStringSubmatch(line); m != nil {
		return fmt.Sprintf("%s %s: %s", m[1], m[2], strings.ReplaceAll(m[3], `\"`, `"`))
	}
	return line
}

// DashboardConfig configures a Dashboard.
type DashboardConfig struct {
	RunID string
	// Ctx is cancelled to stop all jobs gracefully; Cancel does that.
	Ctx    context.Context
	Cancel context.CancelFunc
	// KillAll terminates all running jobs immediately.
	KillAll func()
	// CancelQueued cancels the job of the given name, which is waiting for a
	// free slot, so that it does not run.
	CancelQueued func(name string) error
	// Rerun queues the finished job of the given name to run again, with
	// the given image versions.
	Rerun func(name string, versions Versions) error
	// EVE says which EVE is tested, e.g. "EVE 0.0.0-master-e933b992"; it is shown
	// at the right end of the header. May be empty.
	EVE string
	// CLIPath is the evetest executable, run to open an ssh session to a job's
	// EVE device or to resume a paused test.
	CLIPath string
}

// Dashboard presents a run as a single interactive screen: a table with one
// row per job (state, time, last line of output), and a full-screen log view
// of the selected job. It is both an Output and a terminal program.
type Dashboard struct {
	cfg  DashboardConfig
	prog *tea.Program

	mu       sync.Mutex
	snapshot func() []JobInfo
	jobs     map[string]*dashJob
	names    []string
	finished bool
}

type dashJob struct {
	// attempt is the execution of the job which the lines are from.
	attempt int
	lines   []string
	last    string
	// state is what the instance itself reports while the job runs.
	state string
}

// NewDashboard prepares the dashboard for the given jobs.
func NewDashboard(cfg DashboardConfig, names []string) *Dashboard {
	d := &Dashboard{cfg: cfg, jobs: map[string]*dashJob{}, names: names}
	for _, name := range names {
		d.jobs[name] = &dashJob{}
	}
	d.prog = tea.NewProgram(&dashModel{d: d}, tea.WithAltScreen())
	return d
}

// SetKillAll sets the function which terminates all running jobs immediately.
func (d *Dashboard) SetKillAll(f func()) {
	d.cfg.KillAll = f
}

// SetCancelQueued sets the function which cancels a job waiting in the queue.
func (d *Dashboard) SetCancelQueued(f func(name string) error) {
	d.cfg.CancelQueued = f
}

// SetRerun sets the function which queues a finished job to run again.
func (d *Dashboard) SetRerun(rerun func(name string, versions Versions) error) {
	d.cfg.Rerun = rerun
}

// Run shows the dashboard until the user quits it.
func (d *Dashboard) Run() error {
	stop := make(chan struct{})
	defer close(stop)
	go d.pollStates(stop)
	_, err := d.prog.Run()
	return err
}

// pollStates asks each running instance what it is doing, e.g. whether it is
// paused at a checkpoint or after a failure.
func (d *Dashboard) pollStates(stop <-chan struct{}) {
	ticker := time.NewTicker(statePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		d.mu.Lock()
		snapshot := d.snapshot
		d.mu.Unlock()
		if snapshot == nil {
			continue
		}
		var wg sync.WaitGroup
		for _, info := range snapshot() {
			if info.State != Running || info.Port == 0 {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				state := instances.State(instances.Instance{Name: info.Name, Port: info.Port})
				if state == "unreachable" || state == "unknown" {
					// Not up yet, or already shutting down.
					state = ""
				}
				d.mu.Lock()
				d.jobs[info.Name].state = state
				d.mu.Unlock()
			}()
		}
		wg.Wait()
	}
}

// SetSnapshot implements SnapshotConsumer.
func (d *Dashboard) SetSnapshot(f func() []JobInfo) {
	d.mu.Lock()
	d.snapshot = f
	d.mu.Unlock()
}

// Started implements Output.
func (d *Dashboard) Started([]*Job, int) {}

// Line implements Output.
func (d *Dashboard) Line(job *Job, line string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	j := d.jobs[job.Name]
	if job.Attempt != j.attempt {
		// A rerun: keep the earlier output, to compare with, behind a divider.
		if j.attempt != 0 {
			j.lines = append(j.lines, "", fmt.Sprintf("--- run %d ---", job.Attempt), "")
		}
		j.attempt, j.last = job.Attempt, ""
	}
	line = sanitizeLine(line)
	j.lines = append(j.lines, line)
	if len(j.lines) > dashboardLogLines {
		j.lines = j.lines[len(j.lines)-dashboardLogLines:]
	}
	if text := summarizeLine(line); text != "" {
		j.last = text
	}
}

// Event implements Output.
func (d *Dashboard) Event(job *Job, text string) {
	d.prog.Send(flashMsg(job.Name + ": " + text))
}

// JobDone implements Output.
func (d *Dashboard) JobDone(job *Job) {
	d.mu.Lock()
	d.jobs[job.Name].state = ""
	d.mu.Unlock()
}

// Finished implements Output.
func (d *Dashboard) Finished([]*Job) {
	d.mu.Lock()
	d.finished = true
	d.mu.Unlock()
	d.prog.Send(finishedMsg{})
}

type (
	tickMsg     time.Time
	finishedMsg struct{}
	flashMsg    string
	// devicesMsg carries the EVE devices of a test, asked for to open ssh.
	devicesMsg struct {
		info  JobInfo
		names []string
		err   error
	}
)

type viewMode int

const (
	tableView viewMode = iota
	logView
)

type dashModel struct {
	d             *Dashboard
	width, height int
	mode          viewMode
	cursor        int
	// scroll is how many lines the log view is scrolled up from the end;
	// 0 follows the output.
	scroll   int
	confirm  bool
	stopping bool
	flash    string
	flashAt  time.Time
	// menu lists the EVE devices to choose from for ssh; nil when closed.
	menu       []string
	menuCursor int
	menuJob    JobInfo
	// prompt asks for the image versions of a rerun; nil when closed.
	prompt *versionPrompt
}

// versionPrompt is the form shown before a rerun: one field per image version,
// each starting out as the version of the previous run.
type versionPrompt struct {
	job    JobInfo
	fields []*promptField
	cursor int
}

type promptField struct {
	label string
	// current is what the previous run used, which an empty input keeps.
	current string
	input   string
}

// value is what the field stands for: the input, or else the previous version.
func (f *promptField) value() string {
	if f.input != "" {
		return f.input
	}
	return f.current
}

func (m *dashModel) setFlash(text string) {
	m.flash, m.flashAt = text, time.Now()
}

func tick() tea.Cmd {
	return tea.Tick(dashboardTick, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Init implements tea.Model.
func (m *dashModel) Init() tea.Cmd {
	return tick()
}

func (m *dashModel) infos() []JobInfo {
	m.d.mu.Lock()
	snapshot := m.d.snapshot
	m.d.mu.Unlock()
	if snapshot == nil {
		return nil
	}
	return snapshot()
}

// selected returns the job under the cursor.
func (m *dashModel) selected() (JobInfo, bool) {
	infos := m.infos()
	if m.cursor < 0 || m.cursor >= len(infos) {
		return JobInfo{}, false
	}
	return infos[m.cursor], true
}

// Update implements tea.Model.
func (m *dashModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tickMsg:
		return m, tick()
	case flashMsg:
		m.setFlash(string(msg))
	case devicesMsg:
		return m.handleDevices(msg)
	case finishedMsg:
		// Stopping means that the user wants out; otherwise keep the screen
		// to look at the results.
		if m.stopping || m.d.cfg.Ctx.Err() != nil {
			return m, tea.Quit
		}
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// finished tells whether the run is over: all jobs are done and no rerun has
// been queued since.
func (m *dashModel) finished() bool {
	m.d.mu.Lock()
	finished := m.d.finished
	m.d.mu.Unlock()
	if !finished {
		return false
	}
	for _, info := range m.infos() {
		if info.State == Queued || info.State == Running {
			return false
		}
	}
	return true
}

func (m *dashModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if m.prompt != nil {
		return m.handlePromptKey(msg)
	}
	if m.menu != nil {
		return m.handleMenuKey(key)
	}
	if m.confirm {
		m.confirm = false
		if key == "y" || key == "Y" {
			m.stopping = true
			m.setFlash("stopping all tests gracefully, press q again to kill them")
			m.d.cfg.Cancel()
		}
		return m, nil
	}
	switch key {
	case "ctrl+c", "q":
		switch {
		case m.finished():
			return m, tea.Quit
		case m.stopping:
			m.d.cfg.KillAll()
			m.setFlash("killing all tests")
		default:
			m.confirm = true
		}
	case "up", "k":
		if m.mode == logView {
			m.scroll++
		} else if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.mode == logView {
			m.scroll = max(0, m.scroll-1)
		} else if m.cursor < len(m.d.names)-1 {
			m.cursor++
		}
	case "pgup":
		m.scroll += max(1, m.height-4)
	case "pgdown":
		m.scroll = max(0, m.scroll-max(1, m.height-4))
	case "g", "home":
		m.scroll = dashboardLogLines
	case "G", "end":
		m.scroll = 0
	case "enter", "l", "right":
		m.mode, m.scroll = logView, 0
	case "esc", "h", "left":
		m.mode = tableView
	case "s":
		return m, m.sshCmd()
	case "c":
		return m, m.continueCmd()
	case "x":
		return m, m.stopCmd()
	case "r":
		return m, m.rerunCmd()
	default:
		if len(key) == 1 && key[0] >= '1' && key[0] <= '9' {
			if n := int(key[0] - '1'); n < len(m.d.names) {
				m.cursor, m.scroll = n, 0
			}
		}
	}
	return m, nil
}

// sshCmd starts opening an ssh session to an EVE device of the selected job.
// A test may have several devices; which one is settled once they are known.
func (m *dashModel) sshCmd() tea.Cmd {
	info, ok := m.selected()
	if !ok || info.State != Running {
		m.setFlash("no running test selected")
		return nil
	}
	return func() tea.Msg {
		names, err := instances.Devices(instances.Instance{Name: info.Name, Port: info.Port})
		return devicesMsg{info: info, names: names, err: err}
	}
}

func (m *dashModel) handleDevices(msg devicesMsg) (tea.Model, tea.Cmd) {
	switch {
	case msg.err != nil:
		m.setFlash(fmt.Sprintf("%s: cannot get the EVE devices: %v", msg.info.Name, msg.err))
	case len(msg.names) == 0:
		m.setFlash(msg.info.Name + ": no EVE device yet")
	case len(msg.names) == 1:
		return m, m.sshExec(msg.info, msg.names[0])
	default:
		m.menu, m.menuCursor, m.menuJob = msg.names, 0, msg.info
	}
	return m, nil
}

func (m *dashModel) handleMenuKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		m.menuCursor = max(0, m.menuCursor-1)
	case "down", "j":
		m.menuCursor = min(len(m.menu)-1, m.menuCursor+1)
	case "esc", "q", "ctrl+c":
		m.menu = nil
	case "enter":
		device := m.menu[m.menuCursor]
		m.menu = nil
		return m, m.sshExec(m.menuJob, device)
	default:
		if len(key) == 1 && key[0] >= '1' && key[0] <= '9' {
			if n := int(key[0] - '1'); n < len(m.menu) {
				device := m.menu[n]
				m.menu = nil
				return m, m.sshExec(m.menuJob, device)
			}
		}
	}
	return m, nil
}

// sshExec runs an interactive ssh session to the device, with the dashboard
// suspended. A failed session waits for Enter, so that its error can be read
// before the dashboard redraws the screen.
func (m *dashModel) sshExec(info JobInfo, device string) tea.Cmd {
	const script = `"$@"; rc=$?; if [ "$rc" -ne 0 ]; then ` +
		`printf '\nssh failed (exit code %s). Press Enter to return. ' "$rc"; read -r _; fi; exit "$rc"`
	cmd := exec.Command("sh", "-c", script, "sh",
		m.d.cfg.CLIPath, "-i", strconv.Itoa(info.Port), "eve", "-d", device, "ssh")
	return tea.ExecProcess(cmd, func(err error) tea.Msg {
		if err != nil {
			return flashMsg(fmt.Sprintf("%s: ssh to %s failed", info.Name, device))
		}
		return flashMsg("")
	})
}

// continueCmd resumes the selected job if it is paused.
func (m *dashModel) continueCmd() tea.Cmd {
	info, ok := m.selected()
	if !ok || info.State != Running {
		m.setFlash("no running test selected")
		return nil
	}
	cli := m.d.cfg.CLIPath
	return func() tea.Msg {
		out, err := exec.Command(cli, "-i", strconv.Itoa(info.Port), "continue").CombinedOutput()
		if err != nil {
			return flashMsg(fmt.Sprintf("%s: continue failed: %s", info.Name, strings.TrimSpace(string(out))))
		}
		return flashMsg(info.Name + ": " + strings.TrimSpace(string(out)))
	}
}

// stopCmd stops the selected job gracefully; a job waiting in the queue is
// cancelled, so that it does not start.
func (m *dashModel) stopCmd() tea.Cmd {
	info, ok := m.selected()
	switch {
	case ok && info.State == Queued && m.d.cfg.CancelQueued != nil:
		cancelQueued := m.d.cfg.CancelQueued
		return func() tea.Msg {
			if err := cancelQueued(info.Name); err != nil {
				return flashMsg(fmt.Sprintf("%s: cannot cancel: %v", info.Name, err))
			}
			return nil
		}
	case !ok || info.State != Running:
		m.setFlash("no running or queued test selected")
		return nil
	}
	m.setFlash(info.Name + ": stopping")
	return func() tea.Msg {
		_ = exec.Command("docker", "stop", "-t", gracefulStopTimeout, info.Container).Run()
		return flashMsg(info.Name + ": stopped")
	}
}

// rerunCmd starts asking for the image versions to rerun the selected job
// with, which must be done. The test code is read afresh when it starts, so
// changes made to the tests since are picked up; the framework is the one of
// the image version chosen.
func (m *dashModel) rerunCmd() tea.Cmd {
	info, ok := m.selected()
	switch {
	case !ok:
		return nil
	case info.State == Queued || info.State == Running:
		m.setFlash(info.Name + ": already " + string(info.State) + ", stop it first to rerun it")
		return nil
	case m.d.cfg.Rerun == nil:
		m.setFlash("rerun is not available")
		return nil
	}
	m.openPrompt(info)
	return nil
}

func (m *dashModel) openPrompt(info JobInfo) {
	p := &versionPrompt{job: info}
	p.fields = append(p.fields, &promptField{label: "evetest image", current: info.Versions.Evetest})
	if info.Versions.SDN != "" {
		p.fields = append(p.fields, &promptField{label: "SDN image", current: info.Versions.SDN})
	}
	m.prompt = p
}

func (m *dashModel) handlePromptKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	p := m.prompt
	field := p.fields[p.cursor]
	switch msg.Type {
	case tea.KeyEsc, tea.KeyCtrlC:
		m.prompt = nil
	case tea.KeyEnter:
		if p.cursor < len(p.fields)-1 {
			p.cursor++
			return m, nil
		}
		m.prompt = nil
		return m, m.submitRerun(p)
	case tea.KeyUp, tea.KeyShiftTab:
		p.cursor = max(0, p.cursor-1)
	case tea.KeyDown:
		p.cursor = min(len(p.fields)-1, p.cursor+1)
	case tea.KeyBackspace:
		if r := []rune(field.input); len(r) > 0 {
			field.input = string(r[:len(r)-1])
		}
	case tea.KeyCtrlU:
		field.input = ""
	case tea.KeyRunes:
		field.input += strings.TrimSpace(string(msg.Runes))
	}
	return m, nil
}

// submitRerun queues the job with the versions entered.
func (m *dashModel) submitRerun(p *versionPrompt) tea.Cmd {
	versions := Versions{Evetest: p.fields[0].value()}
	if len(p.fields) > 1 {
		versions.SDN = p.fields[1].value()
	}
	rerun, name := m.d.cfg.Rerun, p.job.Name
	m.setFlash(name + ": checking the images, pulling missing ones")
	return func() tea.Msg {
		if err := rerun(name, versions); err != nil {
			return flashMsg(fmt.Sprintf("%s: cannot rerun: %v", name, err))
		}
		return nil
	}
}

func (m *dashModel) promptBody() []string {
	p := m.prompt
	lines := []string{styleBold.Render("Rerun " + p.job.Name + " with which versions?"), ""}
	for i, f := range p.fields {
		input := f.input
		if input == "" {
			input = styleDim.Render(f.current + " (as in the previous run)")
		}
		if i == p.cursor {
			input += styleCursor.Render(" ")
		}
		lines = append(lines, fmt.Sprintf(" %-14s %s", f.label, input))
	}
	return lines
}

var (
	styleBold   = lipgloss.NewStyle().Bold(true)
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	styleGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	styleRed    = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	styleYellow = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	styleCursor = lipgloss.NewStyle().Reverse(true)
)

// View implements tea.Model.
func (m *dashModel) View() string {
	if m.width == 0 {
		return ""
	}
	var body []string
	switch {
	case m.prompt != nil:
		body = m.promptBody()
	case m.menu != nil:
		body = m.menuBody()
	case m.mode == logView:
		body = m.logBody()
	default:
		body = m.tableBody()
	}
	// Pin the footer to the last line.
	for len(body) < m.height-1 {
		body = append(body, "")
	}
	if len(body) > m.height-1 {
		body = body[:m.height-1]
	}
	return strings.Join(append(body, m.footer()), "\n")
}

// runStatus is shown next to the run id once the run is over or being stopped.
func (m *dashModel) runStatus() string {
	switch {
	case m.finished():
		return "  FINISHED"
	case m.stopping:
		return "  STOPPING"
	}
	return ""
}

func (m *dashModel) header(infos []JobInfo) string {
	counts := map[State]int{}
	for _, info := range infos {
		counts[info.State]++
	}
	left := styleBold.Render("evetest "+m.d.cfg.RunID+m.runStatus()) + styleDim.Render(fmt.Sprintf(
		"   running %d, queued %d, passed %d, failed %d, cancelled %d",
		counts[Running], counts[Queued], counts[Passed], counts[Failed], counts[Cancelled]))
	if m.d.cfg.EVE == "" {
		return left
	}
	return rightAlign(left, styleBold.Render(m.d.cfg.EVE), m.width)
}

// rightAlign puts right at the right edge of a line of the given width, after
// left. When both do not fit, left is shortened.
func rightAlign(left, right string, width int) string {
	rightWidth := ansi.StringWidth(right)
	if rightWidth >= width {
		return ansi.Truncate(right, width, "…")
	}
	if ansi.StringWidth(left)+1+rightWidth > width {
		left = ansi.Truncate(left, width-rightWidth-1, "…")
	}
	return left + strings.Repeat(" ", width-ansi.StringWidth(left)-rightWidth) + right
}

func (m *dashModel) stateText(info JobInfo) string {
	switch info.State {
	case Running:
		m.d.mu.Lock()
		state := m.d.jobs[info.Name].state
		m.d.mu.Unlock()
		if state == "" {
			state = "running"
		}
		if strings.HasPrefix(state, "paused") {
			return styleYellow.Render(state)
		}
		return state
	case Passed:
		return styleGreen.Render("passed")
	case Failed:
		return styleRed.Render(fmt.Sprintf("FAILED (exit code %d)", info.ExitCode))
	case Cancelled:
		return styleYellow.Render("cancelled")
	}
	return styleDim.Render(string(info.State))
}

func (m *dashModel) tableBody() []string {
	infos := m.infos()
	nameWidth := minTableNameWidth
	for _, name := range m.d.names {
		nameWidth = max(nameWidth, len(name))
	}
	const stateWidth = 30
	rest := max(10, m.width-(4+nameWidth+2+5+2+stateWidth+2+8+2))

	showPort := !m.finished()
	portTitle := ""
	if showPort {
		portTitle = "PORT"
	}
	lines := []string{m.header(infos), "",
		styleDim.Render(fmt.Sprintf("%3s %-*s  %-5s  %-*s  %-8s  %s",
			"#", nameWidth, "TEST", portTitle, stateWidth, "STATE", "TIME", "LAST OUTPUT"))}
	for i, info := range infos {
		port := ""
		if showPort && info.Port != 0 {
			port = strconv.Itoa(info.Port)
		}
		m.d.mu.Lock()
		last := m.d.jobs[info.Name].last
		m.d.mu.Unlock()
		state := ansi.Truncate(m.stateText(info), stateWidth, "…")
		row := fmt.Sprintf("%3d %-*s  %-5s  %s%s  %-8s  %s", i+1, nameWidth, info.Name, port,
			state, strings.Repeat(" ", max(0, stateWidth-ansi.StringWidth(state))),
			info.Duration(), ansi.Truncate(last, rest, "…"))
		if i == m.cursor {
			row = styleCursor.Render(ansi.Truncate(row, m.width, ""))
		}
		lines = append(lines, row)
	}
	return lines
}

func (m *dashModel) logBody() []string {
	info, ok := m.selected()
	if !ok {
		return nil
	}
	m.d.mu.Lock()
	all := m.d.jobs[info.Name].lines
	m.d.mu.Unlock()

	portNote := ""
	if !m.finished() {
		portNote = fmt.Sprintf("  (port %d)", info.Port)
	}
	title := fmt.Sprintf("%s%s  %s%s", info.Name, portNote,
		ansi.Strip(m.stateText(info)), m.runStatus())
	lines := []string{styleBold.Render(title)}
	room := max(1, m.height-3)
	end := len(all) - m.scroll
	if end < 0 {
		m.scroll = len(all)
		end = 0
	}
	start := max(0, end-room)
	for _, line := range all[start:end] {
		lines = append(lines, ansi.Truncate(line, m.width, ""))
	}
	return lines
}

func (m *dashModel) menuBody() []string {
	lines := []string{styleBold.Render("Open ssh to which EVE device of " + m.menuJob.Name + "?"), ""}
	for i, name := range m.menu {
		row := fmt.Sprintf(" %d  %s", i+1, name)
		if i == m.menuCursor {
			row = styleCursor.Render(row)
		}
		lines = append(lines, row)
	}
	return lines
}

func (m *dashModel) footer() string {
	switch {
	case m.prompt != nil:
		return styleDim.Render("type a version, or enter to keep the previous one  up/down: field  esc: cancel")
	case m.menu != nil:
		return styleDim.Render("up/down or 1-9: select  enter: open ssh  esc: cancel")
	case m.confirm:
		return styleYellow.Render("Stop all tests gracefully? (y/n)")
	case m.flash != "" && time.Since(m.flashAt) < flashDuration:
		return ansi.Truncate(m.flash, m.width, "…")
	case m.mode == logView:
		return styleDim.Render("esc: back  up/down, pgup/pgdn: scroll  g/G: top/follow  s: ssh to EVE  c: continue  x: stop or cancel test  r: rerun  q: quit")
	}
	return styleDim.Render("up/down or 1-9: select  enter: output  s: ssh to EVE  c: continue paused test  x: stop or cancel test  r: rerun  q: quit")
}
