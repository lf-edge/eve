// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// fakeQMPServer speaks just enough QMP on conn for the client handshake and
// one command: it sends the greeting, acknowledges qmp_capabilities and then
// answers every command with reply, which is either a "return" or an "error"
// member. It records the commands it received.
func fakeQMPServer(t *testing.T, conn net.Conn, reply map[string]any) <-chan map[string]any {
	t.Helper()
	received := make(chan map[string]any, 8)
	go func() {
		defer close(received)
		enc := json.NewEncoder(conn)
		dec := json.NewDecoder(bufio.NewReader(conn))
		_ = enc.Encode(map[string]any{"QMP": map[string]any{
			"version": map[string]any{"package": "fake"}, "capabilities": []string{}}})
		for {
			var req map[string]any
			if err := dec.Decode(&req); err != nil {
				return
			}
			received <- req
			resp := map[string]any{"id": req["id"]}
			if req["execute"] == "qmp_capabilities" {
				resp["return"] = map[string]any{}
			} else {
				for k, v := range reply {
					resp[k] = v
				}
			}
			_ = enc.Encode(resp)
		}
	}()
	return received
}

func testLog() *logrus.Entry {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return logrus.NewEntry(l)
}

// The client must complete the QMP handshake on any established connection,
// pass a command's arguments through verbatim and hand back the "return"
// member as raw JSON.
func TestQMPClientExecuteRaw(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	received := fakeQMPServer(t, serverConn,
		map[string]any{"return": map[string]any{"status": "running"}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := newQMPClient(ctx, testLog(), clientConn)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	defer func() { _ = c.close() }()

	args := json.RawMessage(`{"driver":"usb-storage","id":"flash1"}`)
	out, err := c.executeRaw(ctx, "device_add", args)
	if err != nil {
		t.Fatalf("executeRaw failed: %v", err)
	}
	if string(out) != `{"status":"running"}` {
		t.Fatalf("unexpected return %s", out)
	}

	<-received // qmp_capabilities
	req := <-received
	if req["execute"] != "device_add" {
		t.Fatalf("server saw command %v, want device_add", req["execute"])
	}
	gotArgs, _ := json.Marshal(req["arguments"])
	if string(gotArgs) != string(args) {
		t.Fatalf("server saw arguments %s, want %s", gotArgs, args)
	}
}

// A command without a "return" member must yield "{}" rather than nothing,
// so callers always get valid JSON.
func TestQMPClientExecuteRawEmptyReturn(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	fakeQMPServer(t, serverConn, map[string]any{"return": map[string]any{}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := newQMPClient(ctx, testLog(), clientConn)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	defer func() { _ = c.close() }()

	out, err := c.executeRaw(ctx, "device_del", nil)
	if err != nil {
		t.Fatalf("executeRaw failed: %v", err)
	}
	if string(out) != `{}` {
		t.Fatalf("unexpected return %q, want {}", out)
	}
}

// A QMP error reply must surface as *QMPError with class and description, so
// that callers can tell a refused command from a broken connection.
func TestQMPClientErrorReply(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	fakeQMPServer(t, serverConn, map[string]any{"error": map[string]any{
		"class": "GenericError", "desc": "Duplicate device ID 'flash1'"}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := newQMPClient(ctx, testLog(), clientConn)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	defer func() { _ = c.close() }()

	_, err = c.executeRaw(ctx, "device_add", json.RawMessage(`{"id":"flash1"}`))
	var qmpErr *QMPError
	if !errors.As(err, &qmpErr) {
		t.Fatalf("expected *QMPError, got %T: %v", err, err)
	}
	if qmpErr.Class != "GenericError" || qmpErr.Desc != "Duplicate device ID 'flash1'" {
		t.Fatalf("unexpected QMP error %+v", qmpErr)
	}
}

func TestValidateScratchImageName(t *testing.T) {
	for _, name := range []string{"flash1", "a", "evtest-flash_2"} {
		if err := ValidateScratchImageName(name); err != nil {
			t.Fatalf("%q should be valid: %v", name, err)
		}
	}
	for _, name := range []string{"", "1flash", "../etc", "with space", "a/b",
		"abcdefghijklmnopqrstuvwxyz012345"} {
		if err := ValidateScratchImageName(name); err == nil {
			t.Fatalf("%q should be invalid", name)
		}
	}
}

// Once the connection is gone, further commands must fail with an error
// rather than panic on the torn-down client state; the proxmox provider
// caches clients across guest-initiated shutdowns and SSH drops.
func TestQMPClientExecuteAfterConnectionClosed(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	fakeQMPServer(t, serverConn, map[string]any{"return": map[string]any{}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := newQMPClient(ctx, testLog(), clientConn)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	defer func() { _ = c.close() }()

	_ = serverConn.Close()
	// The reader closes the event channel once it has torn the client down.
	select {
	case _, open := <-c.events():
		if open {
			t.Fatal("unexpected event")
		}
	case <-ctx.Done():
		t.Fatal("client did not notice the closed connection")
	}

	if _, err := c.executeRaw(ctx, "query-status", nil); err == nil {
		t.Fatal("executeRaw on a closed connection should fail")
	}
}
