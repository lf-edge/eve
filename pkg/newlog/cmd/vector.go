// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"
)

var (
	uploadSockVectorSource = "/run/devUpload_source.sock"
	keepSockVectorSource   = "/run/devKeep_source.sock"
	uploadSockVectorSink   = "/run/devUpload_sink.sock"
	keepSockVectorSink     = "/run/devKeep_sink.sock"
)

// BufferedSockWriter is a writer that buffers messages and writes them to a unix socket.
// It uses a buffered channel to queue messages and attempts to reconnect if the connection is lost.
type BufferedSockWriter struct {
	path      string
	buffer    chan []byte
	reconnect time.Duration
}

// NewBufferedSockWriter creates a new buffered socket writer that writes to the specified path.
func NewBufferedSockWriter(path string, bufSize int, reconnect time.Duration) *BufferedSockWriter {
	sw := &BufferedSockWriter{
		path:      path,
		buffer:    make(chan []byte, bufSize),
		reconnect: reconnect,
	}
	go sw.run()
	return sw
}

func (sw *BufferedSockWriter) run() {
	for {
		conn, err := net.Dial("unix", sw.path)
		if err != nil {
			log.Errorf("socket connect failed: %v, retrying...", err)
			time.Sleep(sw.reconnect)
			continue
		}

		for msg := range sw.buffer {
			_, err := conn.Write(msg)
			if err != nil {
				log.Errorf("socket write failed: %v, reconnecting...", err)
				conn.Close()
				break // reconnect
			}
		}
	}
}

// Write implements the io.Writer interface for bufferedSockWriter.
func (sw *BufferedSockWriter) Write(p []byte) (int, error) {
	// Don't block forever, drop if buffer full
	select {
	case sw.buffer <- slices.Clone(p): // copy buffer
		return len(p), nil
	default:
		return 0, fmt.Errorf("buffer full, dropping log")
	}
}

// listenOnSocketAndWriteToChan - goroutine to listen on unix sockets for incoming log entries
func listenOnSocketAndWriteToChan(sockPath string, sendToChan chan<- string) {
	// Create unix socket
	os.Remove(sockPath) // Remove any existing socket
	unixAddr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		log.Fatalf("createIncomingSockListener: ResolveUnixAddr failed: %v", err)
	}
	unixListener, err := net.ListenUnix("unix", unixAddr)
	if err != nil {
		log.Fatalf("createIncomingSockListener: ListenUnix failed: %v", err)
	}
	defer unixListener.Close()
	defer os.Remove(sockPath)

	// Set permissions on socket
	if err := os.Chmod(sockPath, 0666); err != nil {
		log.Fatalf("createIncomingSockListener: chmod socket failed: %v", err)
	}

	// Handle socket connections
	for {
		conn, err := unixListener.Accept()
		if err != nil {
			log.Errorf("createIncomingSockListener: upload accept failed: %v", err)
			continue
		}
		go handleIncomingConnection(conn, sendToChan)
	}
}

// handleIncomingConnection processes incoming log entries from unix socket connections
func handleIncomingConnection(conn net.Conn, sendToChan chan<- string) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		logline := scanner.Text()
		if logline == "" {
			continue
		}

		// add newline character to the end of the logline
		if !strings.HasSuffix(logline, "\n") {
			logline += "\n"
		}

		sendToChan <- logline
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("handleIncomingConnection: scanner error for socket: %v", err)
	}
}
