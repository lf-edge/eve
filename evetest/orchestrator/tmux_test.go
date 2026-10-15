// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTmuxConfig(t *testing.T) {
	u := &TmuxUI{cfg: TmuxConfig{Prefix: "C-a", StopPID: 42}, cliScript: "/tmp/x/cli-pane.sh"}
	conf := u.config()
	for _, want := range []string{
		"set -g prefix C-a\n",
		"bind a send-prefix\n",
		`bind X run-shell "kill -INT 42"`,
		`bind Q if-shell -F "#{@evetest_finished}" "kill-session" "confirm-before`,
		`bind e run-shell "sh /tmp/x/cli-pane.sh -v '#{pane_id}' '#{@evetest_port}' '#{@evetest_name}'"`,
		`bind '"' run-shell "sh /tmp/x/cli-pane.sh -v `,
		`bind % run-shell "sh /tmp/x/cli-pane.sh -h `,
		"unbind d\n",
		"set -g pane-border-format '#{?#{==:#{@evetest_role},cli},",
		"evetest CLI shell",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("config lacks %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "@PREFIX@") || strings.Contains(conf, "@BORDER@") ||
		strings.Contains(conf, "@CLI_") {
		t.Errorf("unreplaced placeholder:\n%s", conf)
	}
}

func TestCLIPaneScript(t *testing.T) {
	for _, want := range []string{
		`split-window "$flag" -t "$target"`,
		`-e "EVETEST_INSTANCE=$port"`,
		`@evetest_role cli`,
		`@evetest_name "$name"`,
		`@evetest_port "$port"`,
		`remain-on-exit off`,
	} {
		if !strings.Contains(cliPaneScript, want) {
			t.Errorf("script lacks %q:\n%s", want, cliPaneScript)
		}
	}
}

func TestTmuxPrefixValidation(t *testing.T) {
	for prefix, valid := range map[string]bool{
		"C-a": true, "C-b": true, "M-x": true, "a": true,
		"": false, "C-ab": false, "C-a;kill-server": false, "C-": false,
	} {
		if got := tmuxPrefixRe.MatchString(prefix); got != valid && prefix != "" {
			t.Errorf("prefix %q: valid = %t, want %t", prefix, got, valid)
		}
	}
}

func TestShellJoin(t *testing.T) {
	got := shellJoin([]string{"docker", "run", "-e", "A=it's b", "img"})
	want := `'docker' 'run' '-e' 'A=it'\''s b' 'img'`
	if got != want {
		t.Errorf("shellJoin = %s, want %s", got, want)
	}
}

func TestTmuxKeysHelp(t *testing.T) {
	u := &TmuxUI{cfg: TmuxConfig{Prefix: "C-b"}}
	help := u.keysHelp()
	for _, want := range []string{"prefix is C-b", "click a pane", "C-b z", "C-b e", "C-b Q", "C-b X",
		"mouse wheel", "C-b ["} {
		if !strings.Contains(help, want) {
			t.Errorf("keys help lacks %q:\n%s", want, help)
		}
	}
}

func TestOrchestratorWindowTimestampsOnlyEvents(t *testing.T) {
	u := &TmuxUI{events: filepath.Join(t.TempDir(), "events.log")}
	if err := os.WriteFile(u.events, nil, 0o600); err != nil { // NewTmuxUI creates it
		t.Fatal(err)
	}
	u.appendEvent("TestA: started on API port 50021")
	u.appendText("All tests finished.")
	data, err := os.ReadFile(u.events)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines: %q", len(lines), lines)
	}
	if !regexp.MustCompile(`^\d\d:\d\d:\d\d TestA: started on API port 50021$`).MatchString(lines[0]) {
		t.Errorf("an event must start with the time: %q", lines[0])
	}
	if lines[1] != "All tests finished." {
		t.Errorf("plain text must be left as it is: %q", lines[1])
	}
}

func TestTmuxStatusText(t *testing.T) {
	u := &TmuxUI{cfg: TmuxConfig{RunID: "r1", Prefix: "C-a", EVE: "EVE 0.0.0-master-e933b992"}}
	u.counts = func() map[State]int { return map[State]int{Running: 2, Queued: 1, Passed: 3, Failed: 1} }
	text := u.statusText()
	for _, want := range []string{"evetest r1:", "running 2, queued 1, passed 3, failed 1",
		"| EVE 0.0.0-master-e933b992 |", "C-a Q: close"} {
		if !strings.Contains(text, want) {
			t.Errorf("status lacks %q: %s", want, text)
		}
	}
	if strings.Contains(text, "FINISHED") {
		t.Error("a running run is shown as finished")
	}
	u.finished = true
	if text = u.statusText(); !strings.Contains(text, "evetest r1 FINISHED:") {
		t.Errorf("status does not show that the run finished: %s", text)
	}
	u.cfg.EVE = ""
	if text = u.statusText(); strings.Contains(text, "EVE") {
		t.Errorf("status mentions EVE although none is given: %s", text)
	}
}
