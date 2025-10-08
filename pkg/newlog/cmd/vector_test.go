// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onsi/gomega"
)

func TestCreateVectorSockets(t *testing.T) {
	t.Parallel()
	g := gomega.NewWithT(t)

	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "vector_socket_test")
	g.Expect(err).To(gomega.BeNil())
	defer os.RemoveAll(tmpDir)

	// Create a socket path in a subdirectory that doesn't exist yet
	nonExistentDir := filepath.Join(tmpDir, "nonexistent")
	sockPath := filepath.Join(nonExistentDir, "test.sock")

	unixListenerChan := make(chan *net.UnixListener, 1)
	backoffPeriod := 100 * time.Millisecond

	go func() {
		unixListener := createVectorSockets(sockPath, backoffPeriod)
		unixListenerChan <- unixListener
	}()

	time.Sleep(2 * backoffPeriod) // Wait to ensure retries happen

	// Verify that the socket was not created yet
	_, err = os.Stat(sockPath)
	g.Expect(os.IsNotExist(err)).To(gomega.BeTrue(), "Socket file should not exist yet")

	// Now create the directory
	err = os.MkdirAll(nonExistentDir, 0755)
	g.Expect(err).To(gomega.BeNil())

	// Wait a bit to let the function succeed
	var unixListener *net.UnixListener
	select {
	case unixListener = <-unixListenerChan:
		// Successfully created the listener
	case <-time.After(10 * backoffPeriod):
		t.Fatal("Timeout waiting for createVectorSockets to succeed")
	}

	// verify that the listener was created
	g.Expect(unixListener).ToNot(gomega.BeNil(), "createVectorSockets should succeed after directory creation")

	// Verify the socket was created
	info, err := os.Stat(sockPath)
	g.Expect(err).To(gomega.BeNil(), "Socket file should be created after directory creation")

	expectedMode := os.FileMode(0666)
	g.Expect(info.Mode().Perm()).To(gomega.Equal(expectedMode), "Socket permissions should be correct")

	// Verify we can connect to the socket
	conn, err := net.Dial("unix", sockPath)
	g.Expect(err).To(gomega.BeNil(), "Should be able to connect to socket")
	conn.Close()

	t.Log("Test passed: socket created successfully and is connectable")
}
