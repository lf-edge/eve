// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build k

package zedkube

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

// initRestartTestLog gives the package-level logger a value; the restart paths log
// on success, and an unset log panics.
func initRestartTestLog() {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-zedkube", 0)
}

// serveSupervisor answers one connection with reply, and records the verb it was
// asked for. Returns the socket path.
func serveSupervisor(t *testing.T, reply string, gotVerb chan<- string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "k3s-supervisor.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		verb, _ := bufio.NewReader(conn).ReadString('\n')
		gotVerb <- verb
		_, _ = conn.Write([]byte(reply))
	}()
	return path
}

// The supervisor is asked to restart, and its OK reply is a success.
func TestRestartK3sViaSupervisorOK(t *testing.T) {
	initRestartTestLog()
	verbs := make(chan string, 1)
	path := serveSupervisor(t, "OK restarting\n", verbs)
	if err := restartK3sViaSupervisor(path); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got := <-verbs; got != "restart\n" {
		t.Errorf("supervisor asked for %q, want %q", got, "restart\n")
	}
}

// An ERR reply must surface as an error rather than be read as success -- the
// daemon uses the prefix, not the connection, to report refusal.
func TestRestartK3sViaSupervisorRefused(t *testing.T) {
	initRestartTestLog()
	verbs := make(chan string, 1)
	path := serveSupervisor(t, "ERR k3s is not running\n", verbs)
	err := restartK3sViaSupervisor(path)
	if err == nil {
		t.Fatal("an ERR reply must be an error")
	}
	select {
	case <-verbs:
	default:
		t.Error("the supervisor socket was never contacted")
	}
}

// A daemon that accepts the connection and says nothing must not count as a
// restart having happened.
func TestRestartK3sViaSupervisorSilent(t *testing.T) {
	initRestartTestLog()
	verbs := make(chan string, 1)
	path := serveSupervisor(t, "", verbs)
	if err := restartK3sViaSupervisor(path); err == nil {
		t.Fatal("an empty reply must be an error")
	}
	select {
	case <-verbs:
	default:
		t.Error("the supervisor socket was never contacted")
	}
}

func TestRestartK3sViaSupervisorNoSocket(t *testing.T) {
	initRestartTestLog()
	if err := restartK3sViaSupervisor(filepath.Join(t.TempDir(), "absent.sock")); err == nil {
		t.Fatal("dialing an absent socket must fail")
	}
}

// With no supervisor socket present, recovery must fall back to the signal path
// rather than fail: that is the cluster-init.sh image.
func TestRestartK3sFallsBackToSignal(t *testing.T) {
	initRestartTestLog()
	dir := t.TempDir()
	savedSock, savedFlag, savedSignal := k3sSupervisorSocket, stuckMountK3sStartFlag, signalK3s
	t.Cleanup(func() {
		k3sSupervisorSocket, stuckMountK3sStartFlag, signalK3s = savedSock, savedFlag, savedSignal
	})
	k3sSupervisorSocket = filepath.Join(dir, "absent.sock")
	stuckMountK3sStartFlag = filepath.Join(dir, "kube", "k3s-start")
	signalK3s = func() ([]int, error) { return []int{4242}, nil }

	how, err := restartK3s()
	if err != nil {
		t.Fatalf("fallback must succeed, got %v", err)
	}
	if how != "SIGTERM" {
		t.Errorf("used %q, want SIGTERM", how)
	}
	// The backoff-reset flag is the half of the signal path that is easy to drop
	// silently, so assert it landed.
	if _, err := os.Stat(stuckMountK3sStartFlag); err != nil {
		t.Errorf("manual-start flag not created: %v", err)
	}
}

// When the socket is present it must be preferred, and the signal path must not
// run at all -- terminating k3s behind the daemon's back skips its hooks.
func TestRestartK3sPrefersSupervisor(t *testing.T) {
	initRestartTestLog()
	verbs := make(chan string, 1)
	path := serveSupervisor(t, "OK\n", verbs)
	savedSock, savedSignal := k3sSupervisorSocket, signalK3s
	t.Cleanup(func() { k3sSupervisorSocket, signalK3s = savedSock, savedSignal })
	k3sSupervisorSocket = path
	signaled := false
	signalK3s = func() ([]int, error) { signaled = true; return []int{1}, nil }

	how, err := restartK3s()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if how != "supervisor socket" {
		t.Errorf("used %q, want the supervisor socket", how)
	}
	if signaled {
		t.Error("the signal path ran even though the supervisor socket was present")
	}
	// Non-blocking: an implementation that never dials must fail this test rather
	// than hang it waiting for a verb that is never sent.
	select {
	case got := <-verbs:
		if got != "restart\n" {
			t.Errorf("supervisor asked for %q, want %q", got, "restart\n")
		}
	default:
		t.Error("the supervisor socket was never contacted")
	}
}
