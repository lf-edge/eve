// Copyright (c) 2018-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vcomlink

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/vcom"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const address = "127.0.0.1"
const port = 9999

var fd = 0

func tcpListener() (int, error) {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return -1, fmt.Errorf("failed to create TCP socket: %v", err)
	}

	// Don't wait for TIME_WAIT sockets to be released.
	if err := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return -1, fmt.Errorf("setsockopt SO_REUSEADDR error: %v", err)
	}
	if err := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return -1, fmt.Errorf("setsockopt SO_REUSEPORT error: %v", err)
	}

	addr := unix.SockaddrInet4{
		Port: port,
	}
	if err := unix.Bind(sock, &addr); err != nil {
		unix.Close(sock)
		return -1, fmt.Errorf("failed to bind TCP socket: %v", err)
	}
	if err := unix.Listen(sock, unix.SOMAXCONN); err != nil {
		unix.Close(sock)
		return -1, fmt.Errorf("failed to listen on TCP socket: %v", err)
	}

	return sock, nil
}

func connect() (int, error) {
	ip := net.ParseIP(address).To4()
	if ip == nil {
		return 0, fmt.Errorf("Invalid IP address: %s", address)
	}
	addr := unix.SockaddrInet4{
		Port: port,
		Addr: [4]byte(ip),
	}
	sockfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return 0, fmt.Errorf("Error creating socket: %v", err)
	}
	err = unix.Connect(sockfd, &addr)
	if err != nil {
		return 0, fmt.Errorf("Error connecting to server: %v", err)
	}

	log.Noticef("Listening on TCP Addr %s, port %d", address, addr.Port)
	return sockfd, nil
}

func TestMain(m *testing.M) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "vcomlink_test", os.Getpid())
	res := 1

	if !evetpm.SimTpmAvailable() {
		fmt.Println("TPM not available, skipping test")
		os.Exit(0)
	}

	// make sure TPM is prepare it before running the test.
	err := evetpm.SimTpmWaitForTpmReadyState()
	if err != nil {
		fmt.Printf("Failed to wait for TPM ready state: %v", err)
		os.Exit(1)
	}

	// use sim tpm for testing
	TpmDevicePath = evetpm.SimTpmPath

	// we can't connect to a vsock listener host<->host, so we use a tcp listener
	// for testing.
	go startVcomServer(tcpListener)
	time.Sleep(1 * time.Second)

	sock, err := connect()
	if err != nil {
		fmt.Printf("Failed to connect to server: %v", err)
	} else {
		fd = sock
		res = m.Run()
		unix.Close(fd)
	}

	os.Exit(res)
}

func TestValidTPMRequest(t *testing.T) {
	request := &vcom.TpmRequest{
		Base:    vcom.Base{Channel: int(vcom.ChannelTpm)},
		Request: uint(vcom.RequestTpmGetEk),
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	err = write(fd, data)
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	resp, err := read(fd)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	channel, err := getChannel(resp)
	if err != nil {
		t.Fatalf("Failed to get channel: %v", err)
	}

	if channel != uint(vcom.ChannelTpm) {
		t.Fatalf("Received response channel is not TPM")
	}

	var tpmResponse vcom.TpmResponseEk
	err = json.Unmarshal(resp, &tpmResponse)
	if err != nil {
		t.Fatalf("Failed to unmarshal TpmResponse: %v", err)
	}

	ek, err := getEkPub()
	if err != nil {
		t.Fatalf("Failed to get EK public key: %v", err)
	}

	if tpmResponse.Ek != ek {
		t.Fatalf("Received EK does not match expected EK")
	}

}

func TestInvalidRequest(t *testing.T) {
	request := &vcom.Base{
		Channel: math.MaxUint32,
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	err = write(fd, data)
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	resp, err := read(fd)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	channel, err := getChannel(resp)
	if err != nil {
		t.Fatalf("Failed to get channel: %v", err)
	}

	if channel != uint(vcom.ChannelError) {
		t.Fatalf("Received response channel is not Error")
	}

	var errResponse vcom.Error
	err = json.Unmarshal(resp, &errResponse)
	if err != nil {
		t.Fatalf("Failed to unmarshal errResponse: %v", err)
	}
}
