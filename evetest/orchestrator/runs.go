// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"os"
	"path/filepath"
	"time"
)

// runIdleGrace is how long a run directory must have been untouched before it
// may be removed. It covers a run which is just starting ("make" prepares its
// directory a moment before the orchestrator container, which is what shows
// that a run is alive, exists) as well as one which has just finished.
const runIdleGrace = 5 * time.Minute

// PruneRuns removes the per-run directories in dir (the logs of the tests of a
// run) of runs which are over, i.e. whose orchestrator container is not running
// according to running and which nothing has written to for runIdleGrace. It
// leaves alone the directory named current, and those for which running cannot
// tell (e.g. Docker does not answer). It returns how many directories it
// removed. Best-effort: what cannot be removed is tried again by the next run.
func PruneRuns(dir, current string, running func(runID string) (bool, error)) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if !e.IsDir() || e.Name() == current || time.Since(lastActivity(path)) < runIdleGrace {
			continue
		}
		if alive, err := running(e.Name()); err != nil || alive {
			continue
		}
		if os.RemoveAll(path) == nil {
			removed++
		}
	}
	return removed
}

// lastActivity is the latest modification time of the directory and the files
// in it. The directory's own time only changes when a file is created in it,
// not when a log is appended to.
func lastActivity(dir string) time.Time {
	var latest time.Time
	if info, err := os.Stat(dir); err == nil {
		latest = info.ModTime()
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
	}
	return latest
}
