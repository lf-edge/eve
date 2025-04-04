// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vcomlink

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// VSOCKListener implements the net.Listener interface for vsock.
type VSOCKListener struct {
	fd   int // The vsock socket file descriptor
	addr *unix.SockaddrVM
}

// VSOCKConn represents a connection over a vsock.
type VSOCKConn struct {
	fd   int // File descriptor for the connection
	addr *unix.SockaddrVM
}

// VSOCKAddr represents a vsock address.
type VSOCKAddr struct {
	addr *unix.SockaddrVM
}

// Accept waits for and returns the next connection to the listener.
func (l *VSOCKListener) Accept() (net.Conn, error) {
	connFd, _, err := unix.Accept(l.fd)
	if err != nil {
		return nil, fmt.Errorf("failed to accept connection: %v", err)
	}

	// xxx: should we set the timeout here?
	err = unix.SetsockoptTimeval(connFd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: readTimeout})
	if err != nil {
		return nil, fmt.Errorf("error setting read timeout: %v", err)
	}
	err = unix.SetsockoptTimeval(connFd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Sec: writeTimeout})
	if err != nil {
		return nil, fmt.Errorf("error setting write timeout: %v", err)
	}

	// return the fd wrapped in net.Conn.
	conn := &VSOCKConn{fd: connFd, addr: l.addr}
	return conn, nil
}

// Close closes the vsock listener.
func (l *VSOCKListener) Close() error {
	return unix.Close(l.fd)
}

// Addr returns the local network address of the listener.
func (l *VSOCKListener) Addr() net.Addr {
	return &VSOCKAddr{addr: l.addr}
}

// Read reads data from the vsock connection.
func (c *VSOCKConn) Read(b []byte) (n int, err error) {
	return unix.Read(c.fd, b)
}

// Write writes data to the vsock connection.
func (c *VSOCKConn) Write(b []byte) (n int, err error) {
	return unix.Write(c.fd, b)
}

// Close closes the vsock connection.
func (c *VSOCKConn) Close() error {
	return unix.Close(c.fd)
}

// LocalAddr returns the local address of the vsock connection.
func (c *VSOCKConn) LocalAddr() net.Addr {
	return &VSOCKAddr{}
}

// RemoteAddr returns the remote address of the vsock connection.
func (c *VSOCKConn) RemoteAddr() net.Addr {
	return &VSOCKAddr{addr: c.addr}
}

// Network returns the network type (vsock).
func (a *VSOCKAddr) Network() string {
	return "vsock"
}

// String returns a string representation of the address.
func (a *VSOCKAddr) String() string {
	return fmt.Sprintf("%s:%d:%d", a.Network(), a.addr.CID, a.addr.Port)
}

// SetDeadline sets both the read and write deadlines for the connection.
func (c *VSOCKConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the read deadline for the connection.
func (c *VSOCKConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the write deadline for the connection.
func (c *VSOCKConn) SetWriteDeadline(t time.Time) error {
	return nil
}
