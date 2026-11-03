// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/luthermonson/go-proxmox"
)

const (
	fakeTermUser   = "root@pam"
	fakeTermTicket = "PVEVNC:fake-ticket"
	fakeTermCookie = "PVEAuthCookie=fake-session"
)

// fakeTermProxy starts a TLS websocket server that speaks just enough of the
// PVE termproxy protocol: it checks the session cookie, answers the login,
// then hands the connection to serve, which runs after the login reply.
func fakeTermProxy(t *testing.T, loginReply string,
	serve func(conn *websocket.Conn)) (wsURL string, tlsConfig *tls.Config) {
	t.Helper()
	upgrader := websocket.Upgrader{Subprotocols: []string{"binary"}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != fakeTermCookie {
			http.Error(w, "no session", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, login, err := conn.ReadMessage()
		if err != nil || string(login) != fakeTermUser+":"+fakeTermTicket+"\n" {
			return
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, []byte(loginReply)); err != nil {
			return
		}
		if serve != nil {
			serve(conn)
		}
	}))
	t.Cleanup(srv.Close)
	transport := srv.Client().Transport.(*http.Transport)
	return "wss" + strings.TrimPrefix(srv.URL, "https"), transport.TLSClientConfig
}

func dialFakeTermProxy(t *testing.T, wsURL string, tlsConfig *tls.Config) *termConsole {
	t.Helper()
	header := http.Header{}
	header.Set("Cookie", fakeTermCookie)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	console, err := dialTermConsole(ctx, wsURL, header, tlsConfig, fakeTermUser, fakeTermTicket)
	if err != nil {
		t.Fatalf("dialTermConsole: %v", err)
	}
	return console
}

func TestTermConsoleReadWrite(t *testing.T) {
	received := make(chan string, 8)
	wsURL, tlsConfig := fakeTermProxy(t, "OK", func(conn *websocket.Conn) {
		if err := conn.WriteMessage(websocket.BinaryMessage, []byte("login: ")); err != nil {
			return
		}
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			received <- string(msg)
		}
	})
	console := dialFakeTermProxy(t, wsURL, tlsConfig)
	defer func() { _ = console.Close() }()

	if got := <-received; got != "1:80:24:" {
		t.Fatalf("expected the initial resize message, got %q", got)
	}
	// Read in small chunks to exercise the partial-read buffering.
	buf := make([]byte, 3)
	var out strings.Builder
	for out.Len() < len("login: ") {
		n, err := console.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		out.Write(buf[:n])
	}
	if out.String() != "login: " {
		t.Fatalf("unexpected console output %q", out.String())
	}
	// The length prefix counts bytes, not runes.
	if _, err := console.Write([]byte("rööt\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := <-received; got != "0:7:rööt\n" {
		t.Fatalf("unexpected input frame %q", got)
	}
}

func TestTermConsoleLoginRejected(t *testing.T) {
	wsURL, tlsConfig := fakeTermProxy(t, "NO", nil)
	header := http.Header{}
	header.Set("Cookie", fakeTermCookie)
	_, err := dialTermConsole(context.Background(), wsURL, header, tlsConfig,
		fakeTermUser, fakeTermTicket)
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("expected a rejected login, got %v", err)
	}
}

// TestTermConsoleBrokenConnection reproduces the go-proxmox TermWebSocket
// crash: the connection breaks underneath an active console, then the console
// is closed while a writer is still active. This must neither panic nor hang.
func TestTermConsoleBrokenConnection(t *testing.T) {
	wsURL, tlsConfig := fakeTermProxy(t, "OK", func(conn *websocket.Conn) {
		_ = conn.UnderlyingConn().Close()
	})
	console := dialFakeTermProxy(t, wsURL, tlsConfig)

	if _, err := console.Read(make([]byte, 16)); err == nil {
		t.Fatal("expected Read to fail on a broken connection")
	}
	// Further reads keep failing without touching the connection again.
	if _, err := console.Read(make([]byte, 16)); err == nil {
		t.Fatal("expected Read to keep failing")
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = console.Write([]byte("x"))
			}
		}
	}()
	for i := 0; i < 3; i++ {
		if err := console.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()

	if _, err := console.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("expected io.ErrClosedPipe after Close, got %v", err)
	}
}

// TestTermConsoleCloseUnblocksRead covers the console logger's shutdown path:
// Close from another goroutine must end a Read blocked on an idle console.
func TestTermConsoleCloseUnblocksRead(t *testing.T) {
	wsURL, tlsConfig := fakeTermProxy(t, "OK", func(conn *websocket.Conn) {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	})
	console := dialFakeTermProxy(t, wsURL, tlsConfig)

	readDone := make(chan error, 1)
	go func() {
		_, err := console.Read(make([]byte, 16))
		readDone <- err
	}()
	time.Sleep(100 * time.Millisecond)
	_ = console.Close()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("expected Read to fail after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read still blocked after Close")
	}
}

func TestTermWebSocketURL(t *testing.T) {
	term := &proxmox.Term{Port: 5900, Ticket: "PVEVNC:a+b/c="}
	got, err := termWebSocketURL("https://pve.example:8006/api2/json/", "pve1", 107, term)
	if err != nil {
		t.Fatal(err)
	}
	want := "wss://pve.example:8006/api2/json/nodes/pve1/qemu/107/vncwebsocket" +
		"?port=5900&vncticket=PVEVNC%3Aa%2Bb%2Fc%3D"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := termWebSocketURL("ftp://pve", "pve1", 107, term); err == nil {
		t.Fatal("expected an error for an unsupported scheme")
	}
}
