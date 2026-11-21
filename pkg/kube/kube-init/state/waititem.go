// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// WaitItemDir holds the operator breakpoint files. On /persist so a
// breakpoint can be staged and then survive the reboot that reaches
// the point of interest.
var WaitItemDir = "/persist/k3s"

// waitItemPollInterval is how often a held breakpoint re-checks. Long
// on purpose: a held daemon logs one line a minute, which reads as a
// deliberate hold rather than a hang.
var waitItemPollInterval = 60 * time.Second

// held tracks the breakpoint currently blocking a caller, so the
// control socket can report it. The file existing is not the same as
// the daemon being stopped at it — the daemon may not have reached
// that point yet, or may never reach it — and that distinction is the
// whole question an operator is asking.
var held struct {
	mu    sync.Mutex
	item  string
	since time.Time
}

// HeldBreakpoint returns the breakpoint currently blocking the daemon
// and how long it has been held. ok is false when nothing is held.
func HeldBreakpoint() (item string, since time.Time, ok bool) {
	held.mu.Lock()
	defer held.mu.Unlock()
	return held.item, held.since, held.item != ""
}

func setHeld(item string) {
	held.mu.Lock()
	held.item = item
	held.since = time.Now()
	held.mu.Unlock()
}

func clearHeld() {
	held.mu.Lock()
	held.item = ""
	held.since = time.Time{}
	held.mu.Unlock()
}

// ItemPath returns the breakpoint file path for item. Exported so the
// control CLI stages and clears the same paths the daemon watches.
func ItemPath(item string) string {
	return filepath.Join(WaitItemDir, "wait_"+item)
}

// WaitForItem blocks while /persist/k3s/wait_<item> exists, so an
// operator can freeze the daemon at a named point and inspect the
// node. Returns immediately when the file is absent, which is the
// normal case — this costs one stat per call site.
//
// The init sequence is long, fast and largely one-way: by the time
// anyone reacts to a failure, later steps have overwritten the state
// that explains it. Staging a breakpoint before the reboot is the only
// way to catch the node at, say, "k3s installed but Longhorn not yet
// applied". Ported from cluster-init.sh's wait_for_item.
//
// Cancelling ctx releases the wait, so a SIGTERM still shuts the
// daemon down cleanly while a breakpoint is held.
func WaitForItem(ctx context.Context, item string) {
	path := ItemPath(item)
	if _, err := os.Stat(path); err != nil {
		return
	}

	log.Printf("BREAKPOINT %q held by %s — remove the file to continue", item, path)
	setHeld(item)
	defer clearHeld()
	ticker := time.NewTicker(waitItemPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("BREAKPOINT %q released by shutdown", item)
			return
		case <-ticker.C:
			if _, err := os.Stat(path); err != nil {
				log.Printf("BREAKPOINT %q released, continuing", item)
				return
			}
			log.Printf("BREAKPOINT %q still held by %s", item, path)
		}
	}
}
