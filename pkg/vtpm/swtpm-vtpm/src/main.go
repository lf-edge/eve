// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/go-tpm/tpm2"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
)

const (
	swtpmPath = "/usr/bin/swtpm"
	// FIX-ME : use constanst from eve types, in another PR
	// TpmdControlSocket is UDS to aks vtpmd to luanch SWTP instances for VMS
	TpmdControlSocket = "/run/swtpm/tpmlaunchd"
	// SwtpmSocketPath is the prefix for the SWTPM socket
	SwtpmSocketPath = "/run/swtpm/%s.sock"
	// SwtpmPidPath is the prefix for the SWTPM pid file
	SwtpmPidPath = "/run/swtpm/%s.pid"

	stateEncryptionKey = "/run/swtpm/binkey"
	swtpmLogPath       = "/run/swtpm/%s.log"
	swtpmStatePath     = "/persist/swtpm/tpm-state-%s"
	maxInstances       = 10
)

var liveInstances = 0

func makeDirs(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	// make sure it has the right permissions, no harm!
	if err := os.Chmod(dir, 0755); err != nil {
		return fmt.Errorf("failed to set permissions for directory: %v", err)
	}

	return nil
}

func runVirtualTpmInstance(id string) error {
	statePath := fmt.Sprintf(swtpmStatePath, id)
	logPath := fmt.Sprintf(swtpmLogPath, id)
	sockPath := fmt.Sprintf(SwtpmSocketPath, id)
	pidPath := fmt.Sprintf(SwtpmPidPath, id)

	if err := makeDirs(statePath); err != nil {
		return fmt.Errorf("failed to create vtpm state directory: %v", err)
	}

	_, err := os.Stat(etpm.TpmDevicePath)
	if err != nil {
		log.Println("TPM is not available, running swtpm without state encryption!")

		cmd := exec.Command(swtpmPath, "socket", "--tpm2",
			"--tpmstate", "dir="+statePath,
			"--ctrl", "type=unixio,path="+sockPath+",terminate",
			"--log", "file="+logPath+",level=20", // FIX-ME: lower the log level, or get rid of it
			"--pid", "file="+pidPath,
			"--daemon")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to run swtpm: %v", err)
		}
	} else {
		log.Println("TPM is available, running swtpm with state encryption!")
		rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
		if err != nil {
			return fmt.Errorf("OpenTPM failed with err: %v", err)
		}
		defer rw.Close()

		key, err := etpm.UnsealDiskKey(etpm.DiskKeySealingPCRs)
		if err != nil {
			return fmt.Errorf("unseal operation failed with err: %v", err)
		}

		if err := ioutil.WriteFile(stateEncryptionKey, key, 0644); err != nil {
			return fmt.Errorf("failed to write key to file: %v", err)
		}

		cmd := exec.Command(swtpmPath, "socket", "--tpm2",
			"--tpmstate", "dir="+statePath,
			"--ctrl", "type=unixio,path="+sockPath+",terminate",
			"--log", "file="+logPath+",level=20", // FIX-ME: lower the log level, or get rid of it
			"--key", "file="+stateEncryptionKey+",format=binary,mode=aes-256-cbc,remove=true",
			"--pid", "file="+pidPath,
			"--daemon")

		if err := cmd.Run(); err != nil {
			// this shall not fail 🧙🏽‍♂️
			_ = os.Remove(stateEncryptionKey)
			return fmt.Errorf("failed to run swtpm: %v", err)
		}
	}

	return nil
}

func main() {
	uds, err := net.Listen("unix", TpmdControlSocket)
	if err != nil {
		log.Fatalf("Failed to create vtpm control socket: %v", err)
	}
	defer uds.Close()

	// make sure we remove the socket file on exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		os.Remove(TpmdControlSocket)
		os.Exit(0)
	}()

	for {
		conn, err := uds.Accept()
		if err != nil {
			log.Printf("Failed to accept connection over vtpmd control socket: %v", err)
			continue
		}

		go handleRequest(conn)
	}
}

func handleRequest(conn net.Conn) {
	defer conn.Close()

	if liveInstances >= maxInstances {
		log.Printf("Error, max number of Virtual TPM instances reached!")
		return
	}

	id, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Printf("Failed to read SWTPM ID from connection: %v", err)
		return
	}
	id = strings.TrimSpace(id)
	if err := runVirtualTpmInstance(id); err != nil {
		log.Printf("Failed to run SWTPM instance: %v", err)
		return
	}

	liveInstances++
}
