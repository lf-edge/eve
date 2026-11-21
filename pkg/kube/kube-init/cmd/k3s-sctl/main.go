// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// k3s-sctl is the operator-facing CLI client for the kube-init
// daemon. It talks to the daemon's Unix control socket and prints
// the response.
//
// Usage:
//
//	k3s-sctl restart   — graceful k3s restart (runs pre-restart hooks)
//	k3s-sctl status    — one-line status report
//	k3s-sctl stop      — stop the kube-init daemon
//	k3s-sctl graph     — print the resolved deploy-graph edges
//	k3s-sctl break …   — set/clear/list operator breakpoints (local,
//	                     works with the daemon down)
//
// Socket path overridable via K3S_SUPERVISOR_SOCKET for testing.
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

const defaultSocket = "/run/k3s-supervisor.sock"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <restart|status|stop|graph|break>\n", os.Args[0])
		os.Exit(1)
	}

	cmd := os.Args[1]

	// break is handled locally: it only touches files under
	// /persist, and must keep working when the daemon is down —
	// which is precisely when staging a breakpoint matters.
	if cmd == "break" {
		os.Exit(runBreak(os.Args[2:]))
	}
	socketPath := os.Getenv("K3S_SUPERVISOR_SOCKET")
	if socketPath == "" {
		socketPath = defaultSocket
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "k3s-sctl: cannot connect to %s: %v\n",
			socketPath, err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	if _, err := fmt.Fprintln(conn, cmd); err != nil {
		fmt.Fprintf(os.Stderr, "k3s-sctl: write %s: %v\n", socketPath, err)
		os.Exit(1)
	}

	// Read every line the daemon writes until EOF. Multi-line
	// responses (graph) print naturally; single-line responses
	// (status / restart / stop) print exactly one line then EOF.
	scanner := bufio.NewScanner(conn)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) == 0 {
		fmt.Fprintf(os.Stderr, "k3s-sctl: no reply from daemon\n")
		os.Exit(1)
	}
	for _, l := range lines {
		fmt.Println(l)
	}
	// Exit non-zero if the LAST line is an ERR — mirrors the
	// previous single-line convention. Multi-line graph output
	// only starts with ERR when the plan itself failed.
	if strings.HasPrefix(lines[len(lines)-1], "ERR") {
		os.Exit(1)
	}
}
