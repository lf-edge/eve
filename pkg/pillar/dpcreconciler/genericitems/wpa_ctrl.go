// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// Events of wpa_supplicant that signal a change of the 802.1X authentication
	// state of a wired port (see src/common/wpa_ctrl.h).
	wpaEventConnected    = "CTRL-EVENT-CONNECTED"
	wpaEventDisconnected = "CTRL-EVENT-DISCONNECTED"
	wpaEventEAPSuccess   = "CTRL-EVENT-EAP-SUCCESS"
	wpaEventEAPFailure   = "CTRL-EVENT-EAP-FAILURE"

	wpaCtrlReplyTimeout = 5 * time.Second
	wpaCtrlKeepAlive    = 30 * time.Second
	wpaCtrlMaxMsgSize   = 8192

	// Values of the STATE field of the PNAC state file.
	pnacStateConnected    = "CONNECTED"
	pnacStateDisconnected = "DISCONNECTED"

	// Delay between the last wpa_supplicant event and the update of the
	// PNAC state file.
	pnacStateSettleDelay = 300 * time.Millisecond
)

// pnacStateForWpaEvent maps an event received from the wpa_supplicant control
// interface to the value of the STATE field of the PNAC state file.
// ok is false for events that do not change the authentication state.
//
// Note that wpa_cli -a does not forward the EAP events to the action script, and
// CTRL-EVENT-CONNECTED/DISCONNECTED are not emitted when a wired port
// re-authenticates without leaving the associated state.
func pnacStateForWpaEvent(event string) (state string, ok bool) {
	// Events are prefixed with a priority level, e.g. "<3>CTRL-EVENT-...".
	if strings.HasPrefix(event, "<") {
		if end := strings.IndexByte(event, '>'); end >= 0 {
			event = event[end+1:]
		}
	}
	switch {
	case strings.HasPrefix(event, wpaEventEAPSuccess),
		strings.HasPrefix(event, wpaEventConnected):
		return pnacStateConnected, true
	case strings.HasPrefix(event, wpaEventEAPFailure),
		strings.HasPrefix(event, wpaEventDisconnected):
		return pnacStateDisconnected, true
	}
	return "", false
}

// wpaEventListener attaches to the control socket of wpa_supplicant and invokes
// the handler for every unsolicited event it receives, until the context
// is canceled or the connection is lost.
// onAttached is called once the listener is registered with wpa_supplicant,
// i.e. when no further event can be missed.
func wpaEventListener(ctx context.Context, ctrlPath, localPath string,
	onAttached func(), handler func(event string)) error {
	laddr := &net.UnixAddr{Name: localPath, Net: "unixgram"}
	raddr := &net.UnixAddr{Name: ctrlPath, Net: "unixgram"}
	_ = os.Remove(localPath)
	conn, err := net.DialUnix("unixgram", laddr, raddr)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", ctrlPath, err)
	}
	// The socket file bound by DialUnix is not removed on Close.
	defer os.Remove(localPath)
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { _ = conn.Close() }) }
	defer closeConn()

	// Unblock the attach and the read loop when the context is canceled.
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			_, _ = conn.Write([]byte("DETACH"))
			closeConn()
		case <-stopped:
		}
	}()

	buf := make([]byte, wpaCtrlMaxMsgSize)
	if err = wpaCtrlAttach(conn, buf); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	if onAttached != nil {
		onAttached()
	}

	for {
		_ = conn.SetReadDeadline(time.Now().Add(wpaCtrlKeepAlive))
		n, err := conn.Read(buf)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Writing to the socket of a terminated wpa_supplicant fails,
				// which is how a lost connection is detected.
				if _, err = conn.Write([]byte("PING")); err != nil {
					return fmt.Errorf("lost connection to %s: %w", ctrlPath, err)
				}
				continue
			}
			return fmt.Errorf("failed to read from %s: %w", ctrlPath, err)
		}
		msg := strings.TrimSpace(string(buf[:n]))
		// Replies to commands (e.g. PONG) do not start with the priority prefix.
		if strings.HasPrefix(msg, "<") {
			handler(msg)
		}
	}
}

// wpaCtrlAttach registers the connection to receive unsolicited events.
func wpaCtrlAttach(conn *net.UnixConn, buf []byte) error {
	if _, err := conn.Write([]byte("ATTACH")); err != nil {
		return fmt.Errorf("failed to send ATTACH: %w", err)
	}
	deadline := time.Now().Add(wpaCtrlReplyTimeout)
	for {
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("no reply to ATTACH: %w", err)
		}
		msg := strings.TrimSpace(string(buf[:n]))
		if strings.HasPrefix(msg, "<") {
			continue
		}
		if msg != "OK" {
			return fmt.Errorf("unexpected reply to ATTACH: %q", msg)
		}
		return nil
	}
}

// pnacStateTracker coalesces bursts of wpa_supplicant events and then reports
// the resulting authentication state. The EAP events are emitted slightly before
// the supplicant state machines settle, so the consumer of the state file must
// not be notified immediately.
type pnacStateTracker struct {
	mu      sync.Mutex
	timer   *time.Timer
	pending string
	stopped bool
	delay   time.Duration
	write   func(state string)
}

func newPNACStateTracker(delay time.Duration, write func(state string)) *pnacStateTracker {
	return &pnacStateTracker{delay: delay, write: write}
}

func (t *pnacStateTracker) handleEvent(event string) {
	state, ok := pnacStateForWpaEvent(event)
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return
	}
	t.pending = state
	if t.timer == nil {
		t.timer = time.AfterFunc(t.delay, t.flush)
		return
	}
	t.timer.Reset(t.delay)
}

func (t *pnacStateTracker) flush() {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	state := t.pending
	t.mu.Unlock()
	t.write(state)
}

// stop cancels the delayed write, if any, and ignores all further events.
// A write that has already started is not waited for.
func (t *pnacStateTracker) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
	if t.timer != nil {
		t.timer.Stop()
	}
}
