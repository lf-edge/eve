// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// cluster-status-probe fetches /status from a bootstrap node's cluster-status
// server for cluster-init.sh, authenticating both ways with credentials
// derived from the cluster join token, which it reads from stdin so that it
// does not appear in the process list.
//
// Usage: cluster-status-probe <host> <port> < join-token
//
// On success it prints the trimmed response body and exits 0; on any failure
// it prints the reason to stderr and exits 1.
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const probeTimeout = 2 * time.Second

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: cluster-status-probe <host> <port> < join-token")
		os.Exit(2)
	}
	token, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read join token: %v\n", err)
		os.Exit(1)
	}
	body, err := probe(os.Args[1], os.Args[2], strings.TrimSpace(string(token)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(body)
}

// probe returns the body of https://<host>:<port>/status.
func probe(host, port, joinToken string) (string, error) {
	auth, err := deriveClusterStatusAuth(joinToken)
	if err != nil {
		return "", fmt.Errorf("derive cluster-status credentials: %w", err)
	}
	c := &http.Client{
		Transport: &http.Transport{TLSClientConfig: auth.tlsConfig()},
		Timeout:   probeTimeout,
	}
	return fetchClusterStatus(c, "https://"+net.JoinHostPort(host, port)+"/status",
		auth.authorization)
}

// fetchClusterStatus issues one GET against the status endpoint,
// presenting authorization, and returns the trimmed body. Any read error is surfaced rather than
// silently producing an empty body (which would be indistinguishable
// from a server that legitimately hasn't entered cluster mode yet).
func fetchClusterStatus(c *http.Client, statusURL, authorization string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, statusURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", authorization)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("status endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read status body: %w", err)
	}
	return strings.TrimSpace(string(body)), nil
}
