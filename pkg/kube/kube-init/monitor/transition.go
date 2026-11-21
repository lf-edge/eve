// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

const (
	// joinStallTimeout caps how long a join may make no forward
	// progress before we reboot to retry. Deliberately a stall limit
	// and not a duration budget: the total time a join needs depends
	// on disk speed, image count and pod scheduling and cannot be
	// predicted, whereas "nothing has advanced for this long" means
	// the same thing on every device.
	joinStallTimeout = 5 * time.Minute

	// transitionMaxReboots caps the reboot-retry count before giving
	// up. Three is empirical: by the third attempt either the join
	// has stuck for a fundamental reason or the controller config
	// has changed and we are reading a stale marker.
	transitionMaxReboots = 3
)

// joinProgress records when this join last reached a stage it had not
// reached before. Zero means "nothing yet this boot", in which case the
// stall clock runs from the marker's own timestamp.
var joinProgress struct {
	mu sync.Mutex
	at time.Time
}

// NoteJoinProgress records that the join advanced. Called by the FSM
// when it enters a stage further along than any reached since the
// transition began — not on every state change, because a crash loop
// changes state continuously without getting anywhere.
func NoteJoinProgress(stage string) {
	// Only meaningful while a join is being watched. Outside that the
	// call is a no-op, so first-boot deploy and steady-state readiness
	// checks do not stamp a clock nobody reads or log about a join
	// that is not happening.
	if !joinWatchdogActive.Load() {
		return
	}
	joinProgress.mu.Lock()
	joinProgress.at = time.Now()
	joinProgress.mu.Unlock()
	log.Printf("cluster join progress: reached %s", stage)
}

// MarkJoinComplete is the success event: the node reached RUNNING after
// a join, so WaitReady succeeded and this node is Ready in the cluster.
// Clears the marker, which retires the watchdog on its next tick. Safe
// to call when no join is in flight.
func MarkJoinComplete() {
	marked, err := state.IsMarked(state.TransitionToCluster)
	if err != nil || !marked {
		return
	}
	log.Printf("cluster join complete — node is Ready, clearing transition marker")
	if err := state.Unmark(state.TransitionToCluster); err != nil {
		log.Printf("warning: remove transition marker: %v", err)
	}
	joinProgress.mu.Lock()
	joinProgress.at = time.Time{}
	joinProgress.mu.Unlock()
}

// sinceJoinProgress returns how long it has been since the join last
// advanced, falling back to the marker timestamp when this boot has
// seen no advance yet (e.g. the daemon restarted mid-join).
func sinceJoinProgress(markerWritten time.Time) time.Duration {
	joinProgress.mu.Lock()
	at := joinProgress.at
	joinProgress.mu.Unlock()
	if at.IsZero() {
		at = markerWritten
	}
	return time.Since(at)
}

// joinWatchdogActive guards against a second watchdog goroutine: both
// start sites (daemon boot and the end of the transition runner) can
// fire for the same join, and two of them would race to increment the
// marker's reboot count.
var joinWatchdogActive atomic.Bool

// StartJoinWatchdog runs CheckClusterTransitionDone on a ticker for as
// long as the transition-to-cluster marker is on disk, then stops.
// Returns immediately if there is no marker or a watchdog is already
// running.
//
// The watchdog is deliberately not part of the monitor goroutine set:
// those only start once the FSM reaches RUNNING, which requires the
// node to be Ready — the exact thing a stuck join never achieves. Tying
// the watchdog to the marker instead of to an FSM state is what makes
// it reachable in the failure it exists for. ctx must be the daemon's
// long-lived context, not a per-state one.
func StartJoinWatchdog(ctx context.Context) {
	marked, err := state.IsMarked(state.TransitionToCluster)
	if err != nil {
		log.Printf("warning: check transition marker for watchdog: %v", err)
		return
	}
	if !marked {
		return
	}
	if !joinWatchdogActive.CompareAndSwap(false, true) {
		return
	}

	// New join, new progress clock. Any timestamp left over from first
	// boot describes a different episode, and carrying it forward
	// spends part of this join's stall budget before it starts.
	joinProgress.mu.Lock()
	joinProgress.at = time.Time{}
	joinProgress.mu.Unlock()

	log.Printf("cluster-join watchdog started (checking every %v)",
		clusterJoinRetryInterval)
	go func() {
		defer joinWatchdogActive.Store(false)
		ticker := time.NewTicker(clusterJoinRetryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !CheckClusterTransitionDone(ctx) {
					log.Printf("cluster-join watchdog stopped")
					return
				}
			}
		}
	}()
}

// CheckClusterTransitionDone progresses the cluster-join retry
// state machine for a non-bootstrap node.
//
// Marker file format: "<unix_timestamp> <reboot_count>" — the
// monitor writes the marker when it first observes the cluster-
// transition condition and rewrites it on each reboot retry.
//
// Returns true while the transition is still in progress (the
// marker remains on disk), false when the marker is gone or
// definitively cleared.
//
// On marker-read failure the function returns true so the caller
// keeps polling; treating an unreadable marker as "transition
// complete" would silently terminate the retry loop while the
// join is still half-finished.
func CheckClusterTransitionDone(ctx context.Context) bool {
	marked, err := state.IsMarked(state.TransitionToCluster)
	if err != nil {
		log.Printf("warning: check transition marker, retrying next tick: %v",
			err)
		return true
	}
	if !marked {
		return false
	}

	// Success is not detected here. NoteJoinProgress/MarkJoinComplete
	// are driven by the FSM, which knows the join worked the moment it
	// reaches RUNNING — WaitReady having succeeded subsumes "this node
	// is Ready in the cluster".
	//
	// Asking the cluster directly would be worse: counting Ready nodes
	// needs a kubeclient, which does not exist until EvK3sReady, so on
	// every tick of a still-joining node the count comes back zero and
	// is indistinguishable from a broken cluster — and a watchdog that
	// cannot tell those apart reboots nodes that have joined perfectly
	// well, at exactly the stall limit.

	transitionTS, rebootCount, err := parseTransitionMarker(string(state.TransitionToCluster))
	if err != nil {
		log.Printf("warning: parse transition marker: %v", err)
		// Malformed marker — treat as still in progress so the
		// next tick can heal it (write a fresh timestamp).
		return true
	}

	// Stall, not duration. How long a join takes is unknowable — it
	// covers a k3s restart, an image import, registration and every
	// kube-system pod — and any budget for it is a guess that some
	// slower device will fail. How long the join may make *no progress
	// at all* is a stable quantity. Every advance to a stage this join
	// has not reached before kicks the timer, so a slow-but-advancing
	// join is never rebooted, while a genuinely wedged one trips
	// promptly. A crash loop does not count: it revisits stages rather
	// than advancing, which is why "the state changed recently" is not
	// the same question.
	since := sinceJoinProgress(time.Unix(transitionTS, 0))
	if since < joinStallTimeout {
		log.Printf("cluster join still advancing: %v since last progress (stall limit: %v)",
			since.Truncate(time.Second), joinStallTimeout)
		return true
	}
	log.Printf("cluster join stalled: no progress for %v", since.Truncate(time.Second))

	rebootCount++
	if rebootCount > transitionMaxReboots {
		log.Printf("cluster transition: giving up after %d reboot attempts",
			transitionMaxReboots)
		if err := state.Unmark(state.TransitionToCluster); err != nil {
			log.Printf("warning: remove transition marker: %v", err)
		}
		return false
	}

	// AtomicWriteFile so a power-loss between mark and reboot
	// leaves the marker file consistent (the file is read again
	// after the reboot).
	newContent := fmt.Sprintf("%d %d", time.Now().Unix(), rebootCount)
	if err := state.AtomicWriteFile(string(state.TransitionToCluster),
		[]byte(newContent), 0644); err != nil {
		log.Printf("warning: update transition marker: %v", err)
		return true
	}

	reason := fmt.Sprintf("Reboot after retry cluster transition attempt %d",
		rebootCount)
	log.Printf("cluster transition: %s", reason)
	if err := state.RebootWithReason(reason); err != nil {
		log.Printf("warning: reboot failed: %v", err)
	}
	// RebootWithReason blocks until reboot; if it returns we are
	// in a degraded state but still mid-transition.
	return true
}

// parseTransitionMarker reads path and returns (unix_timestamp,
// reboot_count, err). A wildly-wrong timestamp (≤0 or more than
// 60s in the future) is rejected as corrupt — we don't want to
// immediately trigger a reboot on garbage data.
//
// Takes path as a parameter (rather than reading state.TransitionToCluster
// directly) so tests can point it at a tmp fixture.
func parseTransitionMarker(path string) (int64, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, fmt.Errorf("read transition marker: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("transition marker unexpected format: %q", string(data))
	}
	ts, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse transition timestamp %q: %w", fields[0], err)
	}
	if ts <= 0 || ts > time.Now().Unix()+60 {
		return 0, 0, fmt.Errorf("transition timestamp %d out of range", ts)
	}
	count, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, fmt.Errorf("parse reboot count %q: %w", fields[1], err)
	}
	return ts, count, nil
}

// JoinWatchdogActive reports whether a stuck-join watchdog is currently
// armed. Published in KubeInitStatus so a reboot it causes is
// attributable from the outside instead of requiring log archaeology.
func JoinWatchdogActive() bool {
	return joinWatchdogActive.Load()
}
