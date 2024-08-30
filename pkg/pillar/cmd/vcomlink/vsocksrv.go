// Copyright (c) 2018-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vcomlink

import (
	"errors"
	"fmt"
	"io"

	"github.com/lf-edge/eve/pkg/pillar/vcom"
	"golang.org/x/sys/unix"
)

// SocketListener is a function that listens on a socket and returns a file
// descriptor, we use this to abstract the socket creation for testing.
type SocketListener func() (int, error)

func vsockListener() (int, error) {
	// XXX : this rudimentary vsock server, it still can handle multiple VMs
	// but if it gets too complex in the future it can be improved by
	// assigning each vm or service a unique port.
	sock, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return -1, fmt.Errorf("failed to create vsock socket: %v", err)
	}

	addr := &unix.SockaddrVM{
		CID:  unix.VMADDR_CID_HOST,
		Port: hostVPort,
	}
	if err := unix.Bind(sock, addr); err != nil {
		return -1, fmt.Errorf("failed to bind vsock socket: %v", err)
	}
	if err := unix.Listen(sock, backLogSize); err != nil {
		return -1, fmt.Errorf("failed to listen on vsock socket: %v", err)

	}

	log.Noticef("Listening on vsock CID %d, port %d", addr.CID, addr.Port)
	return sock, nil
}

func startVcomServer(listener SocketListener) {
	fd, err := listener()
	if err != nil {
		log.Errorf("failed to listen: %v", err)
		return
	}
	defer unix.Close(fd)

	// Set read timeout and write timeout
	err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: readTimeout})
	if err != nil {
		log.Errorf("Error setting read timeout: %v", err)
		return
	}
	err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Sec: writeTimeout})
	if err != nil {
		log.Errorf("Error setting write timeout: %v", err)
		return
	}

	for {
		conn, _, err := unix.Accept(fd)
		if err != nil {
			// lets be less verbose with non-critical errors
			log.Noticef("failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(fd int) {
	defer unix.Close(fd)

	for {
		buffer, err := read(fd)
		if err != nil {
			// unwrap the error to check if it's an EOF
			if errors.Unwrap(err) == io.EOF {
				return // client disconnected
			}

			log.Noticef("failed to read packet: %v", err)
			respondWithDefaultError(fd)
			return
		}

		channel, err := getChannel(buffer)
		if err != nil {
			log.Noticef("failed to get channel: %v", err)
			respondWithDefaultError(fd)
			return
		}

		var response []byte
		switch channel {
		case uint(vcom.ChannelTpm):
			response, err = handleTPM(buffer)
			if err != nil {
				log.Noticef("failed to handle TPM request: %v", err)
			}
		default:
			err = fmt.Errorf("unknown channel: %d", channel)
		}

		if err == nil {
			err = write(fd, response)
			if err != nil {
				log.Noticef("failed to write response: %v", err)
				return
			}
		} else {
			log.Noticef("failed to handle request: %v", err)
			respondWithDefaultError(fd)
			return
		}
	}
}

func respondWithDefaultError(fd int) {
	data := encodeError("received malformed packet")
	if data != nil {
		_ = write(fd, data)
	}
}

func write(fd int, data []byte) error {
	_, err := unix.Write(fd, data)
	if err != nil {
		return fmt.Errorf("failed to send data: %w", err)
	}

	return nil
}

func read(fd int) ([]byte, error) {
	buf := make([]byte, maxPacketSize)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read bytes: %w", err)
	}
	if n == 0 {
		return nil, io.EOF
	}

	buf = buf[:n]
	return buf, nil
}
