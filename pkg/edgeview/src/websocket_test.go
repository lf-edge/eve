// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/onsi/gomega"
	"golang.org/x/sys/unix"
)

// dialGuard is how long a test dial may take before the test gives up on it,
// well above the shortened timeouts used here.
const dialGuard = 10 * time.Second

// setDialTimeouts shortens the dispatcher dial timeouts for one test.
func setDialTimeouts(t *testing.T, dial, handshake time.Duration) {
	oldDial, oldHandshake := wssDialTimeout, wssHandshakeTimeout
	wssDialTimeout, wssHandshakeTimeout = dial, handshake
	t.Cleanup(func() {
		wssDialTimeout, wssHandshakeTimeout = oldDial, oldHandshake
	})
}

// blackholeAddr returns the address of a local listener whose accept queue is
// full, so that the kernel silently drops any further SYN to it: a TCP
// connect hangs, as it does on an interface which blackholes the dispatcher.
func blackholeAddr(t *testing.T) string {
	g := gomega.NewWithT(t)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	t.Cleanup(func() { _ = unix.Close(fd) })
	g.Expect(unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})).To(gomega.Succeed())
	g.Expect(unix.Listen(fd, 0)).To(gomega.Succeed())
	sa, err := unix.Getsockname(fd)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	addr := fmt.Sprintf("127.0.0.1:%d", sa.(*unix.SockaddrInet4).Port)

	// never accepted: fills the accept queue of the listener
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	t.Cleanup(func() { _ = conn.Close() })
	return addr
}

// silentAddr returns the address of a local listener which accepts TCP
// connections but never answers, so the TLS handshake hangs.
func silentAddr(t *testing.T) string {
	g := gomega.NewWithT(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	g.Expect(err).NotTo(gomega.HaveOccurred())
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	return ln.Addr().String()
}

// timedDial dials addr with the dispatcher dialer built by tlsDial and
// returns how long the dial took. It fails the test if the dial does not
// return within dialGuard, or if it succeeds.
func timedDial(t *testing.T, addr string, idx int) time.Duration {
	g := gomega.NewWithT(t)
	src := []net.IP{net.ParseIP("127.0.0.1")}
	dialer, err := tlsDial(true, "", 0, src, idx)
	g.Expect(err).NotTo(gomega.HaveOccurred())

	result := make(chan error, 1)
	start := time.Now()
	go func() {
		_, _, err := dialer.Dial("wss://"+addr+"/api/v1/edge-view", nil)
		result <- err
	}()
	select {
	case err := <-result:
		g.Expect(err).To(gomega.HaveOccurred())
		return time.Since(start)
	case <-time.After(dialGuard):
		t.Fatalf("dial to %s with source index %d still hanging after %v", addr, idx, dialGuard)
		return 0
	}
}

// TestTLSDialConnectTimeout checks that a TCP connect from a selected source
// interface to a dispatcher address which drops SYNs gives up after
// wssDialTimeout, so the interface walk in setupWebC moves on quickly.
func TestTLSDialConnectTimeout(t *testing.T) {
	g := gomega.NewWithT(t)
	setDialTimeouts(t, 200*time.Millisecond, 5*time.Second)

	elapsed := timedDial(t, blackholeAddr(t), 0)
	g.Expect(elapsed).To(gomega.BeNumerically("<", 2*time.Second),
		"connect should time out after wssDialTimeout, not wssHandshakeTimeout")
}

// TestTLSDialHandshakeTimeout checks that the whole dial is bounded by
// wssHandshakeTimeout, with and without a selected source interface, both
// when the TCP connect hangs and when the TLS handshake hangs.
func TestTLSDialHandshakeTimeout(t *testing.T) {
	setDialTimeouts(t, time.Minute, 300*time.Millisecond)

	for _, tc := range []struct {
		name string
		addr func(*testing.T) string
	}{
		{"connect hangs", blackholeAddr},
		{"TLS handshake hangs", silentAddr},
	} {
		for _, idx := range []int{-1, 0} {
			t.Run(fmt.Sprintf("%s, source index %d", tc.name, idx), func(t *testing.T) {
				g := gomega.NewWithT(t)
				elapsed := timedDial(t, tc.addr(t), idx)
				g.Expect(elapsed).To(gomega.BeNumerically("<", 3*time.Second))
			})
		}
	}
}
