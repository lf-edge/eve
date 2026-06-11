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
		fmt.Fprintf(os.Stderr, "Usage: %s <restart|status|stop>\n", os.Args[0])
		os.Exit(1)
	}

	cmd := os.Args[1]
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
	defer conn.Close()

	if _, err := fmt.Fprintln(conn, cmd); err != nil {
		fmt.Fprintf(os.Stderr, "k3s-sctl: write %s: %v\n", socketPath, err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		fmt.Fprintf(os.Stderr, "k3s-sctl: no reply from daemon\n")
		os.Exit(1)
	}
	resp := scanner.Text()
	fmt.Println(resp)
	if strings.HasPrefix(resp, "ERR") {
		os.Exit(1)
	}
}
