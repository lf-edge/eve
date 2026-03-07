// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package reverse provide a limited variant of pubsub where the subscriber
// creates the listener and the publisher connects. Used when the publisher
// is not a long-running agent, and there is only one subscriber.
package reverse

import (
	"io"
	"net"
	"os"
	"path"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
)

// NewSubscriber creates a goroutine which will send strings to the channel
// Returns the channel to the caller
// XXX return chan?
func NewSubscriber(log *base.LogObject, agent string, topic interface{}) <-chan string {
	subChan := make(chan string)
	go startSubscriber(log, agent, topic, subChan)
	return subChan
}

// startSubscriber Creates a socket for the agent and starts listening
func startSubscriber(log *base.LogObject, agent string, topic interface{}, retChan chan<- string) {
	log.Functionf("startSubscriber(%s)", agent)
	sockName := getSocketName(agent, topic)
	dir := path.Dir(sockName)
	if _, err := os.Stat(dir); err != nil {
		log.Functionf("startSubscriber(%s): Create %s\n", agent, dir)
		if err := os.MkdirAll(dir, 0700); err != nil {
			log.Fatalf("startSubscriber(%s): Exception while creating %s. %s",
				agent, dir, err)
		}
	}
	if _, err := os.Stat(sockName); err == nil {
		// This could either be a left-over in the filesystem
		// or some other process (or ourselves) using the same
		// name to publish. Try connect to see if it is the latter.
		_, err := net.Dial("unix", sockName)
		if err == nil {
			log.Fatalf("connectAndRead(%s): Can not publish %s since its already used",
				agent, sockName)
		}
		if err := os.Remove(sockName); err != nil {
			log.Fatalf("connectAndRead(%s): Exception while removing pre-existing sock %s. %s",
				agent, sockName, err)
		}
	}
	listener, err := net.Listen("unix", sockName)
	if err != nil {
		log.Fatalf("connectAndRead(%s): Exception while listening at sock %s. %s",
			agent, sockName, err)
	}
	defer listener.Close()
	for {
		c, err := listener.Accept()
		if err != nil {
			log.Errorf("connectAndRead(%s) failed %s\n", sockName, err)
			continue
		}
		go serveConnection(log, c, retChan)
	}
}

// serveConnection processes a single connection and sends received
// notifications as a string on the retChan
func serveConnection(log *base.LogObject, conn net.Conn, retChan chan<- string) {
	// Ensure the connection is always closed, even if retChan blocks forever.
	defer conn.Close()
	// The reverse subscriber accepts one connection at a time; use a stats-free
	// reader to avoid key collisions when multiple publishers reconnect.
	reader := socketdriver.NewFrameReaderInternal(conn)

	for {
		frame, err := reader.ReadFrame()
		if err != nil {
			if err != io.EOF {
				log.Errorf("serveConnection: Error on read: %s",
					err)
			}
			return
		}
		retChan <- string(frame)
	}
}
