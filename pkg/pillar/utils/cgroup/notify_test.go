// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPollOutcome(t *testing.T) {
	cases := []struct {
		name    string
		revents int16
		rearm   bool
		wantErr bool
	}{
		{"psi POLLPRI wakes", unix.POLLPRI, false, false},
		{"psi POLLERR|POLLPRI is a removed cgroup", unix.POLLERR | unix.POLLPRI, false, true},
		{"psi POLLHUP is a removed cgroup", unix.POLLHUP, false, true},
		{"change POLLERR|POLLPRI is a change", unix.POLLERR | unix.POLLPRI, true, false},
		{"change POLLPRI is a change", unix.POLLPRI, true, false},
		{"change POLLNVAL is gone", unix.POLLNVAL, true, true},
		{"change no events is gone", 0, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := pollOutcome(c.revents, c.rearm)
			if (err != nil) != c.wantErr {
				t.Errorf("pollOutcome(%#x, %v) = %v, wantErr %v", c.revents, c.rearm, err, c.wantErr)
			}
		})
	}
}

// kernfs reports a file that was never read as changed, so a change notifier
// must read its file once when created, or its first Wait returns at once.
// This needs a real kernfs file: the root's cgroup.controllers, which does not
// change while the test runs.
func TestChangeNotifierWaitsForAChange(t *testing.T) {
	if _, err := os.Stat(Path("", "cgroup.controllers")); err != nil {
		t.Skipf("no cgroup v2 at %s: %v", Root, err)
	}
	n, err := NewChangeNotifier("", "cgroup.controllers")
	if err != nil {
		t.Fatal(err)
	}
	// Wait cannot be interrupted, so on success the goroutine stays blocked
	// until the test binary exits.
	woke := make(chan error, 1)
	go func() { woke <- n.Wait() }()
	select {
	case err := <-woke:
		t.Errorf("Wait returned (%v) although %s did not change", err, n.f.Name())
	case <-time.After(500 * time.Millisecond):
	}
}
