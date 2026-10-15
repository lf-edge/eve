// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneRuns(t *testing.T) {
	dir := t.TempDir()
	// mkRun creates a run directory with a log (and the docker options file of a
	// run which was killed), all last written the given time ago.
	mkRun := func(name string, ago time.Duration, files ...string) {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		then := time.Now().Add(-ago)
		for _, f := range append(files, "Test.log") {
			if err := os.WriteFile(filepath.Join(path, f), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(filepath.Join(path, f), then, then); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chtimes(path, then, then); err != nil {
			t.Fatal(err)
		}
	}
	mkRun("just-finished", time.Second)               // its logs are still being settled
	mkRun("starting-run", time.Second, "docker-args") // make has just prepared it
	mkRun("finished-long-ago", time.Hour)
	mkRun("killed-run", time.Hour, "docker-args") // its orchestrator was killed
	mkRun("alive-run", time.Hour)                 // its orchestrator still runs
	mkRun("unknown-run", time.Hour)               // Docker cannot tell
	mkRun("current-run", time.Hour)               // this very run
	if err := os.WriteFile(filepath.Join(dir, "stray-file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	asked := map[string]bool{}
	running := func(id string) (bool, error) {
		asked[id] = true
		switch id {
		case "alive-run":
			return true, nil
		case "unknown-run":
			return false, errors.New("cannot connect to Docker")
		}
		return false, nil
	}
	if removed := PruneRuns(dir, "current-run", running); removed != 2 {
		t.Errorf("removed %d directories, want 2", removed)
	}
	for name, wantExists := range map[string]bool{
		"finished-long-ago": false, "killed-run": false,
		"just-finished": true, "starting-run": true, "alive-run": true,
		"unknown-run": true, "current-run": true, "stray-file": true,
	} {
		_, err := os.Stat(filepath.Join(dir, name))
		if (err == nil) != wantExists {
			t.Errorf("%s: exists = %t, want %t", name, err == nil, wantExists)
		}
	}
	for _, id := range []string{"just-finished", "starting-run", "current-run"} {
		if asked[id] {
			t.Errorf("Docker was asked about %s, which must be left alone anyway", id)
		}
	}
}

func TestLastActivityCountsFilesNotOnlyTheDirectory(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "Test.log")
	if err := os.WriteFile(log, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(dir, old, old); err != nil { // the directory itself looks idle
		t.Fatal(err)
	}
	if time.Since(lastActivity(dir)) > time.Minute {
		t.Error("a log written just now must count as activity")
	}
}

func TestPruneRunsWithoutDirectory(t *testing.T) {
	running := func(string) (bool, error) { return false, nil }
	if removed := PruneRuns(filepath.Join(t.TempDir(), "missing"), "x", running); removed != 0 {
		t.Errorf("removed %d from a missing directory", removed)
	}
}
