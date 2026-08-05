// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Supervisor's Start/Stop/kill paths are intentionally NOT
// exercised by unit tests. Synthesising k3s with /bin/sleep stubs
// produced fragile timing-dependent tests (process-group SIGTERM,
// trap-vs-default signal disposition, /proc descendant races) that
// did not actually validate the k3s-supervision contract.
//
// The tests below cover the pure logic that IS unit-testable:
//   - truncate / cmdlineMatchesOrphan
//   - column-aware /proc/net/tcp parsing (hasListener)
//   - RunHooks ordering, exec-bit gate, failure-continuation
//   - constructor defaults + option overrides
//   - Stop on a never-started supervisor is a no-op
//   - Start with a missing binary returns an error (no real process
//     ever exists)

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 10, "abc"},
		{"abc", 3, "abc"},
		{"abcd", 3, "abc..."},
		{"", 5, ""},
	}
	for _, c := range cases {
		if got := truncate(c.in, c.n); got != c.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

func TestCmdlineMatchesOrphan(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"k3s server matches", "k3s server --foo", true},
		{"k3s init matches", "k3s init worker", true},
		{"k3s-server matches", "/var/lib/k3s/bin/k3s-server --x", true},
		{"abs path matches", "/usr/bin/k3s server", true},
		{"unrelated does not match", "/usr/bin/containerd --x", false},
		{"kube-init excluded", "/usr/bin/k3s kube-init", false},
		{"exclude wins over match", "/usr/bin/k3s server kube-init", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cmdlineMatchesOrphan(c.in); got != c.want {
				t.Errorf("cmdlineMatchesOrphan(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestHasListenerColumnAware(t *testing.T) {
	// hasListener must match field[1] (local_address) only, not
	// any substring of the row.
	header := "  sl  local_address rem_address   st\n"
	cases := []struct {
		name string
		row  string
		want bool
	}{
		{
			name: "port 6443 in local_address matches",
			row:  "   0: 00000000:192B 00000000:0000 0A",
			want: true,
		},
		{
			name: "port 6443 in rem_address only does NOT match",
			row:  "   0: 00000000:9999 00000000:192B 06",
			want: false,
		},
		{
			name: "192B substring in inode column does NOT match",
			row:  "   0: 00000000:9999 00000000:0000 0A 0:0 192B",
			want: false,
		},
		{
			name: "different port does not match",
			row:  "   0: 00000000:1F40 00000000:0000 0A",
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hasListener([]byte(header+c.row+"\n"), []int{6443})
			if got != c.want {
				t.Errorf("hasListener(%q) = %v, want %v", c.row, got, c.want)
			}
		})
	}
}

func TestRunHooksLexicalOrderAndExecutableOnly(t *testing.T) {
	hooks := t.TempDir()
	logFile := filepath.Join(t.TempDir(), "log")
	makeHook(t, hooks, "20-second.sh", logFile, "second")
	makeHook(t, hooks, "10-first.sh", logFile, "first")
	makeHook(t, hooks, "30-skipped.sh", logFile, "skipped")
	if err := os.Chmod(filepath.Join(hooks, "30-skipped.sh"), 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	NewSupervisor(WithHooksDir(hooks)).RunHooks()

	got, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if string(got) != "first\nsecond\n" {
		t.Errorf("hook log = %q, want %q", string(got), "first\nsecond\n")
	}
}

func TestRunHooksMissingDirIsSilent(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-hooks-here")
	if got := NewSupervisor(WithHooksDir(missing)).RunHooks(); got != nil {
		t.Errorf("missing hooks dir should yield no results, got %+v", got)
	}
}

func TestRunHooksContinuesPastHookFailure(t *testing.T) {
	hooks := t.TempDir()
	logFile := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(filepath.Join(hooks, "10-failing.sh"),
		[]byte("#!/bin/sh\nprintf 'failing\\n' >>"+logFile+"\nexit 7\n"),
		0755); err != nil {
		t.Fatalf("write failing hook: %v", err)
	}
	makeHook(t, hooks, "20-after.sh", logFile, "after")

	NewSupervisor(WithHooksDir(hooks)).RunHooks()

	got, _ := os.ReadFile(logFile)
	if !strings.Contains(string(got), "failing") || !strings.Contains(string(got), "after") {
		t.Errorf("expected both hooks to run; log = %q", string(got))
	}
}

func TestSupervisorStopWithoutStartIsNoop(t *testing.T) {
	s := NewSupervisor(WithHooksDir(t.TempDir()))
	if err := s.Stop(); err != nil {
		t.Errorf("Stop on never-started supervisor: %v", err)
	}
}

func TestSupervisorStartFailsWhenBinaryMissing(t *testing.T) {
	s := NewSupervisor(
		WithK3sBinary(filepath.Join(t.TempDir(), "no-such-k3s")),
		WithK3sArgs([]string{"server"}),
		WithLogFile(filepath.Join(t.TempDir(), "log")),
		WithPidFile(filepath.Join(t.TempDir(), "pid")),
		WithHooksDir(t.TempDir()),
	)
	err := s.Start()
	if err == nil {
		t.Fatal("expected Start to fail with missing binary, got nil")
	}
	if errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("missing-binary error misclassified as already-running: %v", err)
	}
}

func TestNewSupervisorAppliesDefaults(t *testing.T) {
	s := NewSupervisor()
	if s.k3sBinary != K3sSymlink {
		t.Errorf("default k3sBinary = %q, want %q", s.k3sBinary, K3sSymlink)
	}
	if len(s.k3sArgs) != 1 || s.k3sArgs[0] != "server" {
		t.Errorf("default k3sArgs = %v, want [\"server\"]", s.k3sArgs)
	}
	if s.logFile != supervisorLogFile {
		t.Errorf("default logFile = %q, want %q", s.logFile, supervisorLogFile)
	}
}

func TestNewSupervisorOptionsOverride(t *testing.T) {
	s := NewSupervisor(
		WithK3sBinary("/bin/x"),
		WithK3sArgs([]string{"a", "b"}),
		WithLogFile("/tmp/l"),
		WithHooksDir("/tmp/h"),
		WithPidFile("/tmp/p"),
	)
	if s.k3sBinary != "/bin/x" || s.k3sArgs[0] != "a" || s.k3sArgs[1] != "b" ||
		s.logFile != "/tmp/l" || s.hooksDir != "/tmp/h" || s.pidFile != "/tmp/p" {
		t.Errorf("options not applied correctly: %+v", s)
	}
}

func makeHook(t *testing.T, dir, name, logFile, line string) {
	t.Helper()
	body := fmt.Sprintf("#!/bin/sh\nprintf '%s\\n' >>%s\n", line, logFile)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0755); err != nil {
		t.Fatalf("write hook %s: %v", name, err)
	}
}

// writeHook drops an executable script at dir/name exiting with code.
func writeHook(t *testing.T, dir, name string, code int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	body := fmt.Sprintf("#!/bin/sh\nexit %d\n", code)
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0755); err != nil {
		t.Fatalf("write hook %s: %v", p, err)
	}
}

// Required hooks run before the optional ones, and each set runs in
// lexical order.
func TestRunHooksOrderAndRequiredFlag(t *testing.T) {
	dir := t.TempDir()
	req := filepath.Join(dir, requiredHooksSubdir)
	writeHook(t, dir, "20-second", 0)
	writeHook(t, dir, "10-first", 0)
	writeHook(t, req, "50-req-b", 0)
	writeHook(t, req, "10-req-a", 0)

	s := NewSupervisor(WithHooksDir(dir))
	got := s.RunHooks()

	want := []struct {
		name     string
		required bool
	}{
		{"10-req-a", true},
		{"50-req-b", true},
		{"10-first", false},
		{"20-second", false},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d results %+v, want %d", len(got), got, len(want))
	}
	for i, w := range want {
		if got[i].Name != w.name || got[i].Required != w.required {
			t.Errorf("result[%d] = {%s required=%v}, want {%s required=%v}",
				i, got[i].Name, got[i].Required, w.name, w.required)
		}
		if got[i].Err != nil {
			t.Errorf("result[%d] %s: unexpected err %v", i, got[i].Name, got[i].Err)
		}
	}
	if RequiredHookFailed(got) {
		t.Error("RequiredHookFailed = true with all hooks exiting 0")
	}
}

func TestRunHooksRequiredFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	writeHook(t, filepath.Join(dir, requiredHooksSubdir), "10-boom", 3)
	writeHook(t, dir, "20-fine", 0)

	got := NewSupervisor(WithHooksDir(dir)).RunHooks()
	if !RequiredHookFailed(got) {
		t.Fatalf("RequiredHookFailed = false, want true; results=%+v", got)
	}
	if got[0].ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", got[0].ExitCode)
	}
	// The optional hook must still have run.
	if len(got) != 2 || got[1].Name != "20-fine" || got[1].Err != nil {
		t.Errorf("optional hook should still run and succeed; results=%+v", got)
	}
}

// An optional hook failing must not mark the run as required-failed —
// that is what keeps a buggy operator cleanup from wedging restarts.
func TestRunHooksOptionalFailureDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	writeHook(t, dir, "10-bad", 1)

	got := NewSupervisor(WithHooksDir(dir)).RunHooks()
	if len(got) != 1 || got[0].Err == nil {
		t.Fatalf("expected one failed result, got %+v", got)
	}
	if RequiredHookFailed(got) {
		t.Error("RequiredHookFailed = true for a non-required hook")
	}
}
