// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
)

var (
	uploadSockVectorSource = "/run/devUpload_source.sock"
	keepSockVectorSource   = "/run/devKeep_source.sock"
	uploadSockVectorSink   = "/run/devUpload_sink.sock"
	keepSockVectorSink     = "/run/devKeep_sink.sock"

	defaultConfigPath   = "/persist/vector/config/vector.yaml.default"
	candidateConfigPath = "/persist/vector/config/vector.yaml.new"
)

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

func writeVectorConfig(text []byte) error {
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(candidateConfigPath), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := fileutils.WriteRename(candidateConfigPath, text); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	log.Noticef("Vector configuration written successfully")
	return nil
}

func handleVectorConfig(config string) error {
	if config == "" {
		log.Noticef("No vector config provided, setting up default configuration")
		// Copy the default vector config from default location
		defaultConfig, err := os.ReadFile(defaultConfigPath)
		if err != nil {
			return fmt.Errorf("failed to read default vector config: %w", err)
		}
		if err := writeVectorConfig(defaultConfig); err != nil {
			return fmt.Errorf("failed to write default vector config: %w", err)
		}
		log.Functionf("wrote default vector config to %s", candidateConfigPath)
	} else {
		// vector.config parameter is in base64 encoded format
		decodedConfig, err := base64.StdEncoding.DecodeString(config)
		if err != nil {
			return fmt.Errorf("failed to decode vector config: %w", err)
		}
		// write the decoded config to vector config file
		if err := writeVectorConfig(decodedConfig); err != nil {
			return fmt.Errorf("failed to write vector config: %w", err)
		}
		log.Functionf("wrote vector config to %s", candidateConfigPath)
	}

	return nil
}
