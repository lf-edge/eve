// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Notifier wakes on kernel notifications from one cgroup file.
type Notifier struct {
	f *os.File
	// rearm re-reads the file after each wake: a kernfs change notification
	// stays pending until the file is read again.
	rearm bool
}

// NewPressureTrigger arms a PSI trigger on group's <resource>.pressure (e.g.
// memory.pressure): Wait returns each time the group's tasks stall for stall
// within window, "some" counting any task, "full" all of them. It fails on a
// kernel without PSI.
func NewPressureTrigger(group, resource, kind string, stall, window time.Duration) (*Notifier, error) {
	if kind != "some" && kind != "full" {
		return nil, fmt.Errorf("PSI trigger kind %q, want some or full", kind)
	}
	f, err := os.OpenFile(Path(group, resource+".pressure"), os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	trigger := fmt.Sprintf("%s %d %d", kind, stall.Microseconds(), window.Microseconds())
	if _, err := f.WriteString(trigger); err != nil {
		f.Close()
		return nil, fmt.Errorf("arming %q on %s: %w", trigger, f.Name(), err)
	}
	return &Notifier{f: f}, nil
}

// NewChangeNotifier wakes each time the kernel changes group's file, such as
// memory.events, which generates a file modified event on every change.
func NewChangeNotifier(group, file string) (*Notifier, error) {
	f, err := os.Open(Path(group, file))
	if err != nil {
		return nil, err
	}
	// kernfs reports a file that was never read as changed, so without this
	// read the first Wait would return at once.
	if _, err := io.Copy(io.Discard, f); err != nil {
		f.Close()
		return nil, err
	}
	return &Notifier{f: f, rearm: true}, nil
}

// pollOutcome decides what a poll's revents mean. A PSI trigger wakes on
// POLLPRI; POLLERR, POLLHUP or POLLNVAL means the trigger is gone, e.g. the
// cgroup was removed, and polling again would return at once. A change
// notifier gets POLLERR|POLLPRI for every change: kernfs sets POLLERR as the
// normal "changed" signal, and only POLLHUP or POLLNVAL means the file is gone.
func pollOutcome(revents int16, rearm bool) error {
	if rearm {
		if revents&(unix.POLLHUP|unix.POLLNVAL) == 0 && revents&unix.POLLPRI != 0 {
			return nil
		}
		return fmt.Errorf("change notifier gone: poll returned %#x", revents)
	}
	if revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
		return fmt.Errorf("pressure trigger gone: poll returned %#x", revents)
	}
	if revents&unix.POLLPRI != 0 {
		return nil
	}
	return fmt.Errorf("pressure trigger: poll returned %#x", revents)
}

// Wait blocks until the next notification.
func (n *Notifier) Wait() error {
	fds := []unix.PollFd{{Fd: int32(n.f.Fd()), Events: unix.POLLPRI}}
	for {
		if _, err := unix.Poll(fds, -1); err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if err := pollOutcome(fds[0].Revents, n.rearm); err != nil {
			return fmt.Errorf("%s: %w", n.f.Name(), err)
		}
		if n.rearm {
			// The re-read re-arms the notification and is also what reports a
			// removed cgroup (it fails), so it must not be dropped.
			if _, err := n.f.Seek(0, io.SeekStart); err != nil {
				return err
			}
			if _, err := io.Copy(io.Discard, n.f); err != nil {
				return err
			}
		}
		return nil
	}
}

// Close releases the file, which disarms a PSI trigger.
func (n *Notifier) Close() error {
	return n.f.Close()
}
