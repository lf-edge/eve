// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"slices"
	"time"
)

// startupWait is how long after creation Write blocks on a full buffer
// instead of dropping. Vector creates its source sockets only once its
// topology is up, which takes about 20 s on an EVE-k boot, while the services
// and pillar log their startup; the backlog then drains faster than newlogd
// can refill it only if the writer waits. Blocking pushes back on the reader
// of memlogd, whose ring buffer holds those entries meanwhile.
const startupWait = 60 * time.Second

// BufferedSockWriter is a writer that buffers messages and writes them to a unix socket.
// It uses a buffered channel to queue messages and attempts to reconnect if the connection is lost.
type BufferedSockWriter struct {
	path            string
	buffer          chan []byte
	reconnect       time.Duration
	msgsDropped     int       // count of dropped messages due to full buffer or write errors
	reportWhenCount int       // count at which to report num dropped messages
	waitDeadline    time.Time // until then Write blocks on a full buffer
}

// NewBufferedSockWriter creates a new buffered socket writer that writes to the specified path.
func NewBufferedSockWriter(path string, bufSize int, reconnect time.Duration) *BufferedSockWriter {
	return newBufferedSockWriter(path, bufSize, reconnect, startupWait)
}

// newBufferedSockWriter is NewBufferedSockWriter with the startup window in
// which Write blocks as a parameter.
func newBufferedSockWriter(path string, bufSize int, reconnect, waitFor time.Duration) *BufferedSockWriter {
	sw := &BufferedSockWriter{
		path:            path,
		buffer:          make(chan []byte, bufSize),
		reconnect:       reconnect,
		msgsDropped:     0,
		reportWhenCount: 1, // initial report count
		waitDeadline:    time.Now().Add(waitFor),
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

// Write implements the io.Writer interface for bufferedSockWriter. It drops
// the message if the buffer is full, except that during the startup window it
// waits for room until the window ends.
func (sw *BufferedSockWriter) Write(p []byte) (int, error) {
	msg := slices.Clone(p)
	select {
	case sw.buffer <- msg:
		return len(p), nil
	default:
	}
	if wait := time.Until(sw.waitDeadline); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case sw.buffer <- msg:
			return len(p), nil
		case <-timer.C:
		}
	}
	sw.msgsDropped++
	return 0, fmt.Errorf("buffer full, dropping log")
}

// ReportDroppedMsgs checks if the number of dropped msgs has reached the report threshold and then grows the threshold exponentially.
func (sw *BufferedSockWriter) ReportDroppedMsgs() int {
	if sw.msgsDropped == sw.reportWhenCount {
		sw.reportWhenCount *= 2 // report every 2x the previous count
		return sw.msgsDropped
	}
	return 0 // no report needed
}
