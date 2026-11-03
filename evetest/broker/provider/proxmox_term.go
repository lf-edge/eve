// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/luthermonson/go-proxmox"
)

const (
	// termHandshakeTimeout bounds the websocket upgrade and the termproxy
	// login exchange that follows it.
	termHandshakeTimeout = 30 * time.Second
	// termWriteTimeout bounds every single websocket write, so a connection
	// that stopped draining fails the write instead of blocking it forever.
	termWriteTimeout = 10 * time.Second
	// termKeepaliveInterval matches the ping period of PVE's own xterm.js
	// console client.
	termKeepaliveInterval = 30 * time.Second
	// termCloseTimeout bounds the best-effort close frame sent by Close.
	termCloseTimeout = 1 * time.Second
)

// termConsole is a client for a PVE termproxy websocket session (the protocol
// spoken by the PVE web UI's xterm.js console), exposed as an
// io.ReadWriteCloser.
//
// It replaces go-proxmox's TermWebSocket, whose close function closes its
// result channels while its own internal goroutines may still be sending on
// them: when the connection has already broken, the goroutine reporting the
// failed close frame blocks on the unbuffered error channel nobody reads any
// more, and panics with "send on closed channel" one second later. That
// happens in a library goroutine, so it cannot be recovered and kills the
// whole broker.
//
// Here no channels are involved: Read and Write go straight to the websocket,
// writes are serialized by writeMu (gorilla supports one concurrent writer),
// and Close only uses websocket methods that gorilla documents as safe to call
// concurrently with all others (WriteControl and Close).
type termConsole struct {
	conn *websocket.Conn

	// readBuf and readErr are only touched by Read, which (like any
	// io.Reader) must not be called concurrently with itself. readErr is
	// sticky: gorilla panics if a failed connection keeps being read.
	readBuf []byte
	readErr error

	writeMu sync.Mutex

	done      chan struct{}
	closeOnce sync.Once
}

// openSerialConsole opens a PVE termproxy session to the VM's serial console.
func (p *ProxmoxProvider) openSerialConsole(
	ctx context.Context, vm *proxmox.VirtualMachine) (io.ReadWriteCloser, error) {
	term, err := vm.TermProxy(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open termproxy for VM %d: %w", vm.VMID, err)
	}
	// TermProxy has just authenticated, so the client holds a session.
	session := p.client.Session()
	if session == nil {
		return nil, fmt.Errorf("no Proxmox API session to open the console of VM %d",
			vm.VMID)
	}
	wsURL, err := termWebSocketURL(p.conf.APIURL, vm.Node, int(vm.VMID), term)
	if err != nil {
		return nil, err
	}
	header := http.Header{}
	header.Set("Cookie", "PVEAuthCookie="+session.Ticket)
	header.Set("CSRFPreventionToken", session.CSRFPreventionToken)
	var tlsConfig *tls.Config
	if p.conf.TLSSkipVerify {
		tlsConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for a self-signed PVE cert
	}
	console, err := dialTermConsole(ctx, wsURL, header, tlsConfig, term.User, term.Ticket)
	if err != nil {
		return nil, fmt.Errorf("failed to open console websocket for VM %d: %w", vm.VMID, err)
	}
	return console, nil
}

// termWebSocketURL builds the vncwebsocket URL of a termproxy session from the
// REST API base URL (e.g. "https://pve:8006/api2/json").
func termWebSocketURL(
	apiURL, node string, vmID int, term *proxmox.Term) (string, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return "", fmt.Errorf("invalid Proxmox API URL %q: %w", apiURL, err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("unsupported Proxmox API URL scheme %q", u.Scheme)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") +
		fmt.Sprintf("/nodes/%s/qemu/%d/vncwebsocket", node, vmID)
	u.RawQuery = url.Values{
		"port":      []string{fmt.Sprintf("%d", term.Port)},
		"vncticket": []string{term.Ticket},
	}.Encode()
	return u.String(), nil
}

// dialTermConsole connects to a termproxy websocket and logs into the session
// with the termproxy ticket.
func dialTermConsole(ctx context.Context, wsURL string, header http.Header,
	tlsConfig *tls.Config, user, ticket string) (*termConsole, error) {
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: termHandshakeTimeout,
		TLSClientConfig:  tlsConfig,
		// PVE closes the upgraded connection right away unless the client
		// asks for the "binary" subprotocol, like xterm.js does.
		Subprotocols: []string{"binary"},
	}
	conn, resp, err := dialer.DialContext(ctx, wsURL, header)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	t := &termConsole{conn: conn, done: make(chan struct{})}
	if err := t.login(user, ticket); err != nil {
		_ = conn.Close()
		return nil, err
	}
	go t.keepalive()
	return t, nil
}

// login sends "<user>:<ticket>\n" and expects "OK" back, then sends an initial
// terminal size the way xterm.js does. The size only affects the termproxy
// pty on the PVE host, not the guest serial console.
func (t *termConsole) login(user, ticket string) error {
	deadline := time.Now().Add(termHandshakeTimeout)
	_ = t.conn.SetWriteDeadline(deadline)
	if err := t.conn.WriteMessage(websocket.BinaryMessage,
		[]byte(user+":"+ticket+"\n")); err != nil {
		return fmt.Errorf("failed to send termproxy login: %w", err)
	}
	_ = t.conn.SetReadDeadline(deadline)
	_, msg, err := t.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read termproxy login reply: %w", err)
	}
	if string(msg) != "OK" {
		return fmt.Errorf("termproxy login rejected: %q", msg)
	}
	_ = t.conn.SetReadDeadline(time.Time{})
	return t.writeMessage([]byte("1:80:24:"))
}

// keepalive pings the session until Close, and closes the console as soon as
// a ping fails: a connection that died without a FIN/RST would otherwise
// leave Read blocked forever.
func (t *termConsole) keepalive() {
	ticker := time.NewTicker(termKeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
			if err := t.writeMessage([]byte("2")); err != nil {
				_ = t.Close()
				return
			}
		}
	}
}

func (t *termConsole) writeMessage(msg []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	select {
	case <-t.done:
		return io.ErrClosedPipe
	default:
	}
	_ = t.conn.SetWriteDeadline(time.Now().Add(termWriteTimeout))
	return t.conn.WriteMessage(websocket.BinaryMessage, msg)
}

// Read returns console output.
func (t *termConsole) Read(p []byte) (int, error) {
	for len(t.readBuf) == 0 {
		if t.readErr != nil {
			return 0, t.readErr
		}
		_, msg, err := t.conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				err = io.EOF
			}
			t.readErr = err
			return 0, err
		}
		t.readBuf = msg
	}
	n := copy(p, t.readBuf)
	t.readBuf = t.readBuf[n:]
	return n, nil
}

// Write sends console input, framed as "0:<byte length>:<data>".
func (t *termConsole) Write(p []byte) (int, error) {
	msg := make([]byte, 0, len(p)+16)
	msg = fmt.Appendf(msg, "0:%d:", len(p))
	msg = append(msg, p...)
	if err := t.writeMessage(msg); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close ends the session. It is idempotent and safe to call concurrently with
// Read, Write and itself; a blocked Read or Write returns with an error.
// It always returns nil: the socket is closed even when the close frame or
// TLS close_notify cannot be delivered, which is the normal case for the
// already broken connections this is mostly called on.
func (t *termConsole) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
		_ = t.conn.WriteControl(websocket.CloseMessage, closeMsg,
			time.Now().Add(termCloseTimeout))
		_ = t.conn.Close()
	})
	return nil
}
