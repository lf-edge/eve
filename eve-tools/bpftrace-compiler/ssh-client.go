// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/sftp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type eveSSHClient struct {
	client            *ssh.Client
	sftpClient        *sftp.Client
	sftpClientSession *ssh.Session
	rStdout           io.ReadCloser
}

func (s *eveSSHClient) startSftpClientWithCustomPath(path string) error {
	var err error

	s.sftpClientSession, err = s.client.NewSession()
	if err != nil {
		return err
	}

	sshCommand := path
	rStdout, wStdout := io.Pipe()
	rStdin, wStdin := io.Pipe()

	s.rStdout = rStdout
	s.sftpClientSession.Stdout = wStdout
	s.sftpClientSession.Stdin = rStdin

	err = s.sftpClientSession.Start(sshCommand)
	if err != nil {
		return err
	}

	s.sftpClient, err = sftp.NewClientPipe(rStdout, wStdin)
	if err != nil {
		return err
	}

	return nil
}

func (s *eveSSHClient) startSftpClient() error {
	var err error

	s.sftpClient, err = sftp.NewClient(s.client)

	return err
}

func newSSHClient(host string, privKey string) (*eveSSHClient, error) {
	ret := &eveSSHClient{}

	ret.startSSHClient(host, privKey)
	err := ret.startSftpClient()

	if err != nil || ret.sftpClient == nil {
		err := ret.startSftpClientWithCustomPath("/usr/libexec/sftp-server")
		if err != nil {
			return nil, fmt.Errorf("could not start sftp client: %v", err)
		}
	}

	return ret, nil
}

func (s *eveSSHClient) startSSHClient(sshHost string, privKey string) {
	var err error

	homedir := os.Getenv("HOME")
	if homedir == "" {
		panic("$HOME not set")
	}

	signers := []ssh.Signer{}
	addPrivKey := func(privKeyPath string) {
		key, err := os.ReadFile(privKeyPath)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			log.Fatalf("unable to read private key %s: %v", privKeyPath, err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			log.Fatalf("unable to parse private key: %v", err)
		}

		signers = append(signers, signer)

	}

	if privKey != "" {
		addPrivKey(privKey)
	}

	for _, privKeyFile := range []string{"id_rsa", "id_ecdsa"} {
		privKeyPath := filepath.Join(homedir, ".ssh", privKeyFile)

		addPrivKey(privKeyPath)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("determening home directory failed: %v", err)
	}

	hostKeyCallback, err := knownhosts.New(filepath.Join(homeDir, ".ssh", "known_hosts"))
	if err != nil {
		log.Fatalf("Creating hostkey callback failed: %v", err)
	}
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			err := hostKeyCallback(hostname, remote, key)
			if err != nil {
				log.Warnf("!! could not verify host key: %v, press [RETURN] to cancel or wait 3 seconds to continue", err)
				if waitForKeyFromStdin(3 * time.Second) {
					return fmt.Errorf("user cancelled verifying host")
				}
			}
			return nil
		},
		ClientVersion: "",
		Timeout:       0,
	}

	s.client, err = ssh.Dial("tcp", sshHost, config)
	if err != nil {
		log.Fatalf("could not ssh dial to %s: %v", sshHost, err)
	}
}

func (s *eveSSHClient) close() {
	s.rStdout.Close()
	if s.sftpClient != nil {
		s.sftpClient.Close()
	}
	if s.sftpClientSession != nil {
		s.sftpClientSession.Close()
	}
	s.client.Close()
}

func (s *eveSSHClient) getLinuxkitYaml() []byte {
	sshCommand := "/bin/cat /hostroot/etc/linuxkit-eve-config.yml"

	arch, _, err := s.run(sshCommand)
	if err != nil {
		return []byte{}
	}
	return arch
}

func (s *eveSSHClient) getArch() []byte {
	sshCommand := "/bin/uname -m"

	arch, _, err := s.run(sshCommand)
	if err != nil {
		return []byte{}
	}
	return arch
}

func (s *eveSSHClient) putFile(srcPath, dstPath string) {
	src, err := os.Open(srcPath)
	if err != nil {
		log.Fatalf("could not open source %s: %+v", srcPath, err)
	}
	defer src.Close()

	dst, err := s.sftpClient.Create(dstPath)
	if err != nil {
		log.Fatalf("could not open dest %s: %+v", dstPath, err)
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	if err != nil {
		log.Fatalf("could not copy %s: %+v", dstPath, err)
	}

}

func (s *eveSSHClient) run(sshCommand string) ([]byte, []byte, error) {
	return s.runWithTimeout(sshCommand, 0)
}

func (s *eveSSHClient) runWithTimeout(sshCommand string, timeout time.Duration) ([]byte, []byte, error) {
	session, err := s.client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}

	if timeout != 0 {
		go func() {
			time.Sleep(timeout)
			err := session.Signal(ssh.SIGTERM)
			if err != nil {
				log.Printf("Sending SIGTERM to bpftrace failed: %v", err)
				time.Sleep(time.Second)
				err := session.Signal(ssh.SIGKILL)
				if err != nil {
					log.Printf("Sending SIGKILL to bpftrace failed: %v", err)
				}
			}
			session.Close()
		}()
	} else {
		defer session.Close()
	}
	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer
	session.Stdout = &stdoutBuffer
	session.Stderr = &stderrBuffer
	err = session.Run(sshCommand)
	return stdoutBuffer.Bytes(), stderrBuffer.Bytes(), err
}
