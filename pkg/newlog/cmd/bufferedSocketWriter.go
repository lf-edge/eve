// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"slices"
	"time"
)

// BufferedSockWriter is a writer that buffers messages and writes them to a unix socket.
// It uses a buffered channel to queue messages and attempts to reconnect if the connection is lost.
type BufferedSockWriter struct {
	path            string
	buffer          chan []byte
	reconnect       time.Duration
	msgsDropped     int // count of dropped messages due to full buffer or write errors
	reportWhenCount int // count at which to report num dropped messages
}

// NewBufferedSockWriter creates a new buffered socket writer that writes to the specified path.
func NewBufferedSockWriter(path string, bufSize int, reconnect time.Duration) *BufferedSockWriter {
	sw := &BufferedSockWriter{
		path:            path,
		buffer:          make(chan []byte, bufSize),
		reconnect:       reconnect,
		msgsDropped:     0,
		reportWhenCount: 1, // initial report count
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
				sw.msgsDropped++
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
		sw.msgsDropped++
		return 0, fmt.Errorf("buffer full, dropping log")
	}
}

// ReportDroppedMsgs checks if the number of dropped msgs has reached the report threshold and then grows the threshold exponentially.
func (sw *BufferedSockWriter) ReportDroppedMsgs() int {
	if sw.msgsDropped == sw.reportWhenCount {
		sw.reportWhenCount *= 2 // report every 2x the previous count
		return sw.msgsDropped
	}
	return 0 // no report needed
}
