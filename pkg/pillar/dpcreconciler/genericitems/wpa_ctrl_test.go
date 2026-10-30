// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package genericitems

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPNACStateForWpaEvent(t *testing.T) {
	t.Parallel()
	tests := []struct {
		event     string
		wantState string
		wantOK    bool
	}{
		{"<3>CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully",
			pnacStateConnected, true},
		{"<3>CTRL-EVENT-CONNECTED - Connection to 01:80:c2:00:00:03 completed",
			pnacStateConnected, true},
		{"<3>CTRL-EVENT-EAP-FAILURE EAP authentication failed",
			pnacStateDisconnected, true},
		{"<3>CTRL-EVENT-DISCONNECTED bssid=01:80:c2:00:00:03 reason=0",
			pnacStateDisconnected, true},
		{"CTRL-EVENT-EAP-SUCCESS without priority", pnacStateConnected, true},
		{"<3>CTRL-EVENT-EAP-STARTED EAP authentication started", "", false},
		{"<3>CTRL-EVENT-EAP-PEER-CERT depth=0 subject='CN=x'", "", false},
		{"<2>CTRL-EVENT-EAP-SUCCESS2 something", pnacStateConnected, true},
		{"PONG", "", false},
		{"", "", false},
	}
	for _, tc := range tests {
		state, ok := pnacStateForWpaEvent(tc.event)
		if state != tc.wantState || ok != tc.wantOK {
			t.Errorf("pnacStateForWpaEvent(%q) = (%q, %t), want (%q, %t)",
				tc.event, state, ok, tc.wantState, tc.wantOK)
		}
	}
}

func TestPNACStateTrackerCoalescesEvents(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var written []string
	writes := make(chan struct{}, 10)
	tracker := newPNACStateTracker(50*time.Millisecond, func(state string) {
		mu.Lock()
		written = append(written, state)
		mu.Unlock()
		writes <- struct{}{}
	})
	defer tracker.stop()

	tracker.handleEvent("<3>CTRL-EVENT-EAP-STARTED start")
	tracker.handleEvent("<3>CTRL-EVENT-EAP-SUCCESS ok")
	tracker.handleEvent("<3>CTRL-EVENT-CONNECTED ok")
	select {
	case <-writes:
	case <-time.After(5 * time.Second):
		t.Fatal("state was not written")
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(written) != 1 || written[0] != pnacStateConnected {
		t.Fatalf("written = %v, want a single %q", written, pnacStateConnected)
	}
}

// fakeSupplicant emulates the datagram control socket of wpa_supplicant.
type fakeSupplicant struct {
	conn *net.UnixConn

	mu       sync.Mutex
	attached net.Addr
	detached chan struct{}
	logoffs  atomic.Int32
}

func newFakeSupplicant(t *testing.T, path string) *fakeSupplicant {
	t.Helper()
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatalf("failed to listen on %s: %v", path, err)
	}
	f := &fakeSupplicant{conn: conn, detached: make(chan struct{})}
	t.Cleanup(func() { _ = conn.Close() })
	go f.serve()
	return f
}

func (f *fakeSupplicant) serve() {
	buf := make([]byte, 1024)
	for {
		n, addr, err := f.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		switch string(buf[:n]) {
		case "ATTACH":
			f.mu.Lock()
			f.attached = addr
			f.mu.Unlock()
			_, _ = f.conn.WriteTo([]byte("OK\n"), addr)
		case "PING":
			_, _ = f.conn.WriteTo([]byte("PONG\n"), addr)
		case "DETACH":
			close(f.detached)
		case "LOGOFF":
			f.logoffs.Add(1)
			_, _ = f.conn.WriteTo([]byte("OK\n"), addr)
		}
	}
}

func (f *fakeSupplicant) sendEvent(t *testing.T, event string) {
	t.Helper()
	f.mu.Lock()
	addr := f.attached
	f.mu.Unlock()
	if addr == nil {
		t.Fatal("no client attached")
	}
	if _, err := f.conn.WriteTo([]byte(event), addr); err != nil {
		t.Fatalf("failed to send event: %v", err)
	}
}

func TestWpaEventListener(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ctrlPath := filepath.Join(dir, "eth0")
	localPath := filepath.Join(dir, "client")
	supplicant := newFakeSupplicant(t, ctrlPath)

	attached := make(chan struct{})
	events := make(chan string, 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- wpaEventListener(ctx, ctrlPath, localPath,
			func() { close(attached) },
			func(event string) { events <- event })
	}()

	select {
	case <-attached:
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not attach")
	}

	supplicant.sendEvent(t, "<3>CTRL-EVENT-EAP-STARTED EAP authentication started")
	supplicant.sendEvent(t, "<3>CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully")
	for _, want := range []string{
		"<3>CTRL-EVENT-EAP-STARTED EAP authentication started",
		"<3>CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully",
	} {
		select {
		case got := <-events:
			if got != want {
				t.Errorf("event = %q, want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("event %q was not delivered", want)
		}
	}

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Errorf("listener returned error after cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not stop")
	}
	select {
	case <-supplicant.detached:
	case <-time.After(5 * time.Second):
		t.Error("listener did not detach")
	}
}

func TestPNACStateTrackerStop(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var writes int
	tracker := newPNACStateTracker(20*time.Millisecond, func(string) {
		mu.Lock()
		writes++
		mu.Unlock()
	})
	tracker.handleEvent("<3>CTRL-EVENT-EAP-SUCCESS ok")
	tracker.stop()
	// A flush that was already fired by the timer must not write anymore.
	tracker.flush()
	tracker.handleEvent("<3>CTRL-EVENT-EAP-FAILURE failed")
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if writes != 0 {
		t.Fatalf("state was written %d times after stop", writes)
	}
}

func TestWpaEventListenerCanceledDuringAttach(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ctrlPath := filepath.Join(dir, "eth0")
	// Socket that never replies to ATTACH.
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: ctrlPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("failed to listen on %s: %v", ctrlPath, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- wpaEventListener(ctx, ctrlPath, filepath.Join(dir, "client"),
			nil, func(string) {})
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("unexpected error after cancellation: %v", err)
		}
	case <-time.After(wpaCtrlReplyTimeout / 2):
		t.Fatal("listener did not stop promptly during ATTACH")
	}
}

func TestWpaEventListenerNoSupplicant(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	err := wpaEventListener(context.Background(), filepath.Join(dir, "missing"),
		filepath.Join(dir, "client"), nil, func(string) {})
	if err == nil {
		t.Fatal("expected an error when wpa_supplicant is not running")
	}
}

func TestWpaCtrlLogoff(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ctrlPath := filepath.Join(dir, "eth0")
	fake := newFakeSupplicant(t, ctrlPath)
	if err := wpaCtrlLogoff(ctrlPath, filepath.Join(dir, "client")); err != nil {
		t.Fatalf("LOGOFF failed: %v", err)
	}
	if n := fake.logoffs.Load(); n != 1 {
		t.Fatalf("expected 1 LOGOFF command, got %d", n)
	}
	if err := wpaCtrlLogoff(filepath.Join(dir, "missing"),
		filepath.Join(dir, "client")); err == nil {
		t.Fatal("expected an error when wpa_supplicant is not running")
	}
}
