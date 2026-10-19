// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	// DefaultSFTPUsername is the username accepted by evetest's built-in
	// SFTP image server (see GetImageServerIPv4 / GetImageServerSFTPPort).
	// Use it (together with DefaultSFTPPassword) when configuring SFTPStorage.
	DefaultSFTPUsername = "evetest"
	// DefaultSFTPPassword is the password accepted by evetest's built-in
	// SFTP image server.
	DefaultSFTPPassword = "pass123"
)

// runSFTPServer serves rootDir read-only over SFTP on every connection
// accepted from listener, authenticating with DefaultSFTPUsername/Password.
// It returns once listener is closed (e.g. by TestHarness.Close), mirroring
// the plain HTTP image server started alongside it in Init().
func (th *TestHarness) runSFTPServer(listener net.Listener, rootDir string) {
	signer, err := generateSSHHostKey()
	if err != nil {
		th.log.Errorf("Failed to generate SFTP server host key: %v", err)
		return
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(
			conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() == DefaultSFTPUsername &&
				string(password) == DefaultSFTPPassword {
				return nil, nil
			}
			return nil, fmt.Errorf(
				"invalid SFTP credentials for user %q", conn.User())
		},
	}
	config.AddHostKey(signer)

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener closed (harness shutting down) or accept error.
			return
		}
		go th.handleSFTPConn(conn, config, rootDir)
	}
}

// handleSFTPConn performs the SSH handshake for a single incoming connection
// and serves an SFTP subsystem session (read-only, rooted at rootDir) over
// every session channel the client opens.
func (th *TestHarness) handleSFTPConn(
	netConn net.Conn, config *ssh.ServerConfig, rootDir string) {
	defer func() {
		if err := netConn.Close(); err != nil {
			th.log.Warnf("SFTP server: failed to close connection: %v", err)
		}
	}()

	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, config)
	if err != nil {
		th.log.Debugf("SFTP server: SSH handshake failed: %v", err)
		return
	}
	defer func() {
		if err := sshConn.Close(); err != nil {
			th.log.Warnf("SFTP server: failed to close SSH connection: %v", err)
		}
	}()
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			th.log.Warnf("SFTP server: failed to accept channel: %v", err)
			continue
		}
		go func() {
			for req := range requests {
				ok := req.Type == "subsystem" && len(req.Payload) >= 4 &&
					string(req.Payload[4:]) == "sftp"
				if req.WantReply {
					_ = req.Reply(ok, nil)
				}
			}
		}()
		go func() {
			defer func() {
				if err := channel.Close(); err != nil {
					th.log.Warnf("SFTP server: failed to close channel: %v", err)
				}
			}()
			server, err := sftp.NewServer(channel,
				sftp.ReadOnly(),
				sftp.WithServerWorkingDirectory(rootDir))
			if err != nil {
				th.log.Warnf("SFTP server: failed to create session: %v", err)
				return
			}
			defer func() {
				if err := server.Close(); err != nil {
					th.log.Warnf("SFTP server: failed to close session: %v", err)
				}
			}()
			if err := server.Serve(); err != nil && err != io.EOF {
				th.log.Debugf("SFTP server: session ended: %v", err)
			}
		}()
	}
}

// generateSSHHostKey creates an ephemeral Ed25519 SSH host key, used only
// for the lifetime of a single test-harness run.
func generateSSHHostKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}
