// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// This is a simple service that listens on a unix domain socket for a SWTPM ID
// and runs a SWTPM instance with that ID. The service also checks if the TPM is
// available, if it is, it will run SWTPM with state encryption enabled.
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/sirupsen/logrus"
)

const (
	swtpmPath            = "/usr/bin/swtpm"
	stateEncryptionKey   = "/run/swtpm/%s.binkey"
	swtpmLogPath         = "/run/swtpm/%s.log"
	swtpmIsEncryptedPath = "/run/swtpm/%s.encrypted"
	swtpmStatePath       = "/persist/swtpm/tpm-state-%s"
	maxInstances         = 10
	maxIDLen             = 128
)

var (
	liveInstances int
	log           *base.LogObject
)

func makeDirs(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// if path already exist MkdirAll won't check the perms,
	// so make sure it has the right permissions by applying it again.
	if err := os.Chmod(dir, 0755); err != nil {
		return fmt.Errorf("failed to set permissions for directory: %w", err)
	}

	return nil
}

func hwTpmIsAvailable() bool {
	_, err := os.Stat(etpm.TpmDevicePath)
	return err == nil
}

func runSwtpm(id string) error {
	statePath := fmt.Sprintf(swtpmStatePath, id)
	ctrlSockPath := fmt.Sprintf(types.SwtpmCtrlSocketPath, id)
	binKeyPath := fmt.Sprintf(stateEncryptionKey, id)
	pidPath := fmt.Sprintf(types.SwtpmPidPath, id)
	isEncryptedPath := fmt.Sprintf(swtpmIsEncryptedPath, id)
	// swtpm args, if you want to bring back the logging, add the following
	// "--log", "file="+fmt.Sprintf(swtpmLogPath, id)+",level=20"
	swtpmArgs := []string{"socket", "--tpm2",
		"--tpmstate", "dir=" + statePath,
		"--ctrl", "type=unixio,path=" + ctrlSockPath + ",terminate",
		"--pid", "file=" + pidPath,
		"--daemon"}

	if err := makeDirs(statePath); err != nil {
		return fmt.Errorf("failed to create vtpm state directory: %w", err)
	}

	if !hwTpmIsAvailable() {
		log.Noticef("TPM is not available, running swtpm without state encryption!")

		// if swtpm state for app marked as as encrypted, and TPM is not available
		// anymore, fail because this will corrupt the swtpm state.
		if utils.FileExists(log, isEncryptedPath) {
			return fmt.Errorf("state encryption was enabled for app, but TPM is not available")
		}

		cmd := exec.Command(swtpmPath, swtpmArgs...)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to run swtpm: %w", err)
		}
	} else {
		log.Noticef("TPM is available, running swtpm with state encryption")

		key, err := etpm.UnsealDiskKey(etpm.DiskKeySealingPCRs)
		if err != nil {
			return fmt.Errorf("failed to get swtpm state encryption key : %w", err)
		}

		// we are about to write the key to the disk, so mark the app swtpm state
		// as encrypted
		if !utils.FileExists(log, isEncryptedPath) {
			if err := utils.WriteRename(isEncryptedPath, []byte("Y")); err != nil {
				return fmt.Errorf("failed mark the app swtp state as encrypted: %w", err)
			}
		}

		if err := os.WriteFile(binKeyPath, key, 0644); err != nil {
			return fmt.Errorf("failed to write key to file: %w", err)
		}

		swtpmArgs = append(swtpmArgs, "--key", "file="+binKeyPath+",format=binary,mode=aes-256-cbc,remove=true")
		cmd := exec.Command(swtpmPath, swtpmArgs...)
		if err := cmd.Run(); err != nil {
			// this shall not fail 🧙🏽‍♂️
			rmErr := os.Remove(binKeyPath)
			if rmErr != nil {
				return fmt.Errorf("failed to run swtpm: %w, failed to remove key file %w", err, rmErr)
			}
			return fmt.Errorf("failed to run swtpm: %w", err)
		}
	}

	return nil
}

func main() {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "vtpm", os.Getpid())
	if log == nil {
		fmt.Println("Failed to create log object")
		os.Exit(1)
	}

	uds, err := net.Listen("unix", types.VtpmdCtrlSocket)
	if err != nil {
		log.Errorf("failed to create vtpm control socket: %v", err)
		return
	}
	defer uds.Close()

	// make sure we remove the socket file on exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		os.Remove(types.VtpmdCtrlSocket)
		os.Exit(0)
	}()

	for {
		conn, err := uds.Accept()
		if err != nil {
			log.Errorf("failed to accept connection over vtpmd control socket: %v", err)
			continue
		}

		go handleRequest(conn)
	}
}

func handleRequest(conn net.Conn) {
	defer conn.Close()

	if liveInstances >= maxInstances {
		log.Errorf("max number of Virtual TPM instances reached!")
		return
	}

	id, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Errorf("failed to read SWTPM ID from connection: %v", err)
		return
	}

	id = strings.TrimSpace(id)
	if id == "" || len(id) > maxIDLen {
		log.Errorln("invalid SWTPM ID")
		return
	}

	if err := runSwtpm(id); err != nil {
		log.Errorf("failed to run SWTPM instance: %v", err)
		return
	}

	liveInstances++
}
