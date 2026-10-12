// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
)

func newTestDashboard(t *testing.T, infos []JobInfo) (*dashModel, *int) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cancelled := 0
	var names []string
	for _, info := range infos {
		names = append(names, info.Name)
	}
	d := NewDashboard(DashboardConfig{
		RunID: "run1", Ctx: ctx,
		Cancel:  func() { cancelled++; cancel() },
		KillAll: func() {},
	}, names)
	d.SetSnapshot(func() []JobInfo { return infos })
	model := &dashModel{d: d, width: 120, height: 20}
	return model, &cancelled
}

func press(m *dashModel, keys ...string) {
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "ctrl+c":
			msg = tea.KeyMsg{Type: tea.KeyCtrlC}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		m.Update(msg)
	}
}

func TestDashboardTable(t *testing.T) {
	infos := []JobInfo{
		{Name: "TestA", State: Running, Port: 50021, Started: time.Now()},
		{Name: "TestB", State: Failed, Port: 50022, ExitCode: 1, Started: time.Now(), Finished: time.Now()},
		{Name: "TestC", State: Queued},
	}
	m, _ := newTestDashboard(t, infos)
	m.d.jobs["TestA"].last = "waiting for device"
	m.d.jobs["TestA"].state = "paused (checkpoint x)"
	view := ansi.Strip(m.View())
	for _, want := range []string{"evetest run1", "running 1, queued 1, passed 0, failed 1",
		"TestA", "50021", "paused (checkpoint x)", "waiting for device",
		"FAILED (exit code 1)", "TestC", "queued", "q: quit"} {
		if !strings.Contains(view, want) {
			t.Errorf("view lacks %q:\n%s", want, view)
		}
	}
	if got := strings.Count(view, "\n") + 1; got != m.height {
		t.Errorf("view has %d lines, want the screen height %d", got, m.height)
	}
}

func TestDashboardShowsEVEUnderTest(t *testing.T) {
	m, _ := newTestDashboard(t, []JobInfo{{Name: "TestA", State: Running}})
	first := func() string { return strings.Split(ansi.Strip(m.View()), "\n")[0] }
	if line := first(); strings.Contains(line, "EVE") || !strings.HasPrefix(line, "evetest run1") {
		t.Errorf("without an EVE the header is just the run: %q", line)
	}

	m.d.cfg.EVE = "EVE 0.0.0-master-e933b992"
	line := first()
	if !strings.HasPrefix(line, "evetest run1") {
		t.Errorf("the run must stay at the left: %q", line)
	}
	if want := m.width - len(m.d.cfg.EVE); strings.Index(line, m.d.cfg.EVE) != want {
		t.Errorf("the EVE must end at the right edge (column %d): %q", m.width, line)
	}

	// A narrow terminal gives up part of the counts, never the EVE.
	m.width = 60
	line = first()
	if ansi.StringWidth(line) != 60 || !strings.HasSuffix(line, m.d.cfg.EVE) ||
		!strings.HasPrefix(line, "evetest run1") {
		t.Errorf("a narrow header must still hold the run and the EVE in %d columns: %q", m.width, line)
	}
}

func TestDashboardColumnsLineUp(t *testing.T) {
	infos := []JobInfo{
		{Name: "TestA", State: Running, Port: 50021, Started: time.Now()},
		{Name: "TestLongerName", State: Failed, ExitCode: 1, Port: 50022, Started: time.Now(), Finished: time.Now()},
	}
	m, _ := newTestDashboard(t, infos)
	m.d.jobs["TestA"].last = "waiting for the device"
	m.cursor = 1 // the selected row is rendered differently; both kinds must line up
	lines := strings.Split(ansi.Strip(m.View()), "\n")
	header := -1
	for i, line := range lines {
		if strings.Contains(line, "LAST OUTPUT") {
			header = i
		}
	}
	if header < 0 || header+2 >= len(lines) {
		t.Fatalf("no table header in:\n%s", strings.Join(lines, "\n"))
	}
	for r, cells := range [][2]string{
		{"TEST", "TestA"}, {"PORT", "50021"}, {"STATE", "running"}, {"TIME", "0s"},
		{"LAST OUTPUT", "waiting for the device"},
	} {
		want := strings.Index(lines[header], cells[0])
		if got := strings.Index(lines[header+1], cells[1]); got != want {
			t.Errorf("row 1: %q starts at column %d, but its header %q at %d (case %d)",
				cells[1], got, cells[0], want, r)
		}
	}
	// The second row has a longer name, which widens the name column.
	for _, cells := range [][2]string{{"TEST", "TestLongerName"}, {"PORT", "50022"}, {"STATE", "FAILED"}} {
		want := strings.Index(lines[header], cells[0])
		if got := strings.Index(lines[header+2], cells[1]); got != want {
			t.Errorf("row 2: %q starts at column %d, but its header %q at %d",
				cells[1], got, cells[0], want)
		}
	}
}

func TestDashboardSelectionAndLogView(t *testing.T) {
	infos := []JobInfo{{Name: "TestA", State: Running}, {Name: "TestB", State: Running}}
	m, _ := newTestDashboard(t, infos)
	m.d.jobs["TestB"].lines = []string{"line one", "line two"}
	press(m, "2", "enter")
	if m.mode != logView || m.cursor != 1 {
		t.Fatalf("mode %v cursor %d, want log view of the second job", m.mode, m.cursor)
	}
	view := ansi.Strip(m.View())
	if !strings.Contains(view, "TestB") || !strings.Contains(view, "line two") ||
		strings.Contains(view, "TestA") {
		t.Errorf("unexpected log view:\n%s", view)
	}
	press(m, "esc")
	if m.mode != tableView {
		t.Error("esc did not return to the table")
	}
	press(m, "9")
	if m.cursor != 1 {
		t.Errorf("selecting a non-existing row moved the cursor to %d", m.cursor)
	}
}

func TestDashboardQuitAsksBeforeStopping(t *testing.T) {
	m, cancelled := newTestDashboard(t, []JobInfo{{Name: "TestA", State: Running}})
	press(m, "q")
	if !m.confirm || *cancelled != 0 {
		t.Fatal("q must ask for confirmation first")
	}
	press(m, "n")
	if m.confirm || *cancelled != 0 || m.stopping {
		t.Fatal("n must dismiss the question")
	}
	press(m, "q", "y")
	if *cancelled != 1 || !m.stopping {
		t.Fatal("y must stop all tests gracefully")
	}
	_, cmd := m.Update(finishedMsg{})
	if cmd == nil || cmd() != tea.Quit() {
		t.Error("the dashboard must quit once the stopped run has finished")
	}
}

func TestDashboardStaysOpenAfterFinish(t *testing.T) {
	m, _ := newTestDashboard(t, []JobInfo{{Name: "TestA", State: Passed}})
	m.d.finished = true
	if _, cmd := m.Update(finishedMsg{}); cmd != nil {
		t.Error("a finished run must keep the screen for inspection")
	}
	if !strings.Contains(ansi.Strip(m.View()), "FINISHED") {
		t.Error("view does not show that the run finished")
	}
	_, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	if cmd == nil || cmd() != tea.Quit() {
		t.Error("q must quit a finished run without asking")
	}
}

func TestDashboardActionsNeedRunningJob(t *testing.T) {
	m, _ := newTestDashboard(t, []JobInfo{{Name: "TestA", State: Passed}})
	for _, key := range []string{"s", "c", "x"} {
		if _, cmd := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}); cmd != nil {
			t.Errorf("key %q on a finished job started a command", key)
		}
		if !strings.Contains(m.flash, "no running test selected") {
			t.Errorf("key %q: flash = %q", key, m.flash)
		}
		m.flash = ""
	}
}

func TestDashboardKeepsOnlyRecentLines(t *testing.T) {
	m, _ := newTestDashboard(t, []JobInfo{{Name: "TestA", State: Running}})
	job := &Job{Name: "TestA"}
	for i := 0; i < dashboardLogLines+10; i++ {
		m.d.Line(job, "x")
	}
	if n := len(m.d.jobs["TestA"].lines); n != dashboardLogLines {
		t.Errorf("kept %d lines, want %d", n, dashboardLogLines)
	}
}

func TestSanitizeLine(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                      "plain",
		"ok  \tgithub.com/x\t0.01s":  "ok      github.com/x    0.01s",
		"progress 10%\rprogress 99%": "progress 99%",
		"line\r":                     "line",
	} {
		if got := sanitizeLine(in); got != want {
			t.Errorf("sanitizeLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSummarizeLine(t *testing.T) {
	in := "\x1b[32mHARNESS  time=\"2026-10-12T14:40:03Z\" level=info msg=\"Waiting for \\\"x\\\"\"\x1b[0m"
	if got, want := summarizeLine(in), `HARNESS info: Waiting for "x"`; got != want {
		t.Errorf("summarizeLine = %q, want %q", got, want)
	}
	if got := summarizeLine("  just text "); got != "just text" {
		t.Errorf("summarizeLine = %q", got)
	}
}

func TestDashboardFlashExpires(t *testing.T) {
	m, _ := newTestDashboard(t, []JobInfo{{Name: "TestA", State: Running}})
	m.setFlash("something happened")
	if !strings.Contains(ansi.Strip(m.View()), "something happened") {
		t.Error("a fresh message is not shown")
	}
	m.flashAt = time.Now().Add(-2 * flashDuration)
	view := ansi.Strip(m.View())
	if strings.Contains(view, "something happened") || !strings.Contains(view, "q: quit") {
		t.Errorf("an old message must give way to the key help:\n%s", view)
	}
}

func TestDashboardLogViewShowsRunStatus(t *testing.T) {
	m, _ := newTestDashboard(t, []JobInfo{{Name: "TestA", State: Passed}})
	m.d.finished = true
	press(m, "enter")
	if !strings.Contains(ansi.Strip(m.View()), "FINISHED") {
		t.Error("the log view does not show that the run finished")
	}
}

func TestDashboardTableHasNoControlCharacters(t *testing.T) {
	m, _ := newTestDashboard(t, []JobInfo{{Name: "TestA", State: Running}})
	m.d.Line(&Job{Name: "TestA"}, "ok  \tgithub.com/x/y\t0.021s [no tests to run]\r")
	view := ansi.Strip(m.View())
	if strings.ContainsAny(view, "\t\r") {
		t.Errorf("the screen contains tabs or carriage returns:\n%q", view)
	}
	if !strings.Contains(view, "ok      github.com/x/y    0.021s") {
		t.Errorf("unexpected last output column:\n%s", view)
	}
}

func TestDashboardSSHAsksWhichDeviceWhenSeveral(t *testing.T) {
	m, _ := newTestDashboard(t, []JobInfo{{Name: "TestA", State: Running, Port: 50021}})
	info, _ := m.selected()

	_, cmd := m.Update(devicesMsg{info: info, names: []string{"edge-1", "edge-2", "edge-3"}})
	if cmd != nil || m.menu == nil {
		t.Fatal("with several devices a menu must open, and nothing may run yet")
	}
	view := ansi.Strip(m.View())
	for _, want := range []string{"which EVE device of TestA", "edge-1", "edge-2", "edge-3", "enter: open ssh"} {
		if !strings.Contains(view, want) {
			t.Errorf("menu lacks %q:\n%s", want, view)
		}
	}
	press(m, "j", "j", "j")
	if m.menuCursor != 2 {
		t.Errorf("cursor at %d, must stop at the last device", m.menuCursor)
	}
	press(m, "k")
	press(m, "esc")
	if m.menu != nil {
		t.Error("esc must close the menu")
	}

	m.Update(devicesMsg{info: info, names: []string{"edge-1", "edge-2"}})
	if _, cmd = m.handleKey(tea.KeyMsg{Type: tea.KeyEnter}); cmd == nil || m.menu != nil {
		t.Error("enter must pick the device and run ssh")
	}
	m.Update(devicesMsg{info: info, names: []string{"edge-1", "edge-2"}})
	if _, cmd = m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")}); cmd == nil || m.menu != nil {
		t.Error("a digit must pick the device and run ssh")
	}
}

func TestDashboardSSHWithOneOrNoDevice(t *testing.T) {
	m, _ := newTestDashboard(t, []JobInfo{{Name: "TestA", State: Running, Port: 50021}})
	info, _ := m.selected()

	if _, cmd := m.Update(devicesMsg{info: info, names: []string{"edge-1"}}); cmd == nil || m.menu != nil {
		t.Error("a single device must be connected to directly, without a menu")
	}
	if _, cmd := m.Update(devicesMsg{info: info}); cmd != nil || !strings.Contains(m.flash, "no EVE device yet") {
		t.Errorf("no device: cmd %v, flash %q", cmd, m.flash)
	}
	if _, cmd := m.Update(devicesMsg{info: info, err: context.DeadlineExceeded}); cmd != nil ||
		!strings.Contains(m.flash, "cannot get the EVE devices") {
		t.Errorf("error: cmd %v, flash %q", cmd, m.flash)
	}
}
