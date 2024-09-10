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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/sirupsen/logrus"
)

const (
	swtpmPath    = "/usr/bin/swtpm"
	purgeReq     = "purge"
	terminateReq = "terminate"
	launchReq    = "launch"
	maxInstances = 10
	maxIDLen     = 128
	maxWaitTime  = 3 //seconds
)

var (
	liveInstances int
	log           *base.LogObject
	pids          = make(map[string]int, 0)
	// These are defined as vars to be able to mock them in tests
	// XXX : move this to types so we have everything EVE creates in one place.
	stateEncryptionKey   = "/run/swtpm/%s.binkey"
	swtpmIsEncryptedPath = "/persist/swtpm/%s.encrypted"
	swtpmStatePath       = "/persist/swtpm/tpm-state-%s"
	vtpmdCtrlSockPath    = types.VtpmdCtrlSocket
	swtpmCtrlSockPath    = types.SwtpmCtrlSocketPath
	swtpmPidPath         = types.SwtpmPidPath
	isTPMAvailable       = func() bool {
		_, err := os.Stat(etpm.TpmDevicePath)
		return err == nil
	}
	getEncryptionKey = func() ([]byte, error) {
		return etpm.UnsealDiskKey(etpm.DiskKeySealingPCRs)
	}
)

func parseRequest(id string) (string, string, error) {
	id = strings.TrimSpace(id)
	if id == "" || len(id) > maxIDLen {
		return "", "", fmt.Errorf("invalid SWTPM ID received")
	}

	// breake the string and get the request type
	split := strings.Split(id, ";")
	if len(split) != 2 {
		return "", "", fmt.Errorf("invalid SWTPM ID received (no request)")
	}

	if split[1] == "" {
		return "", "", fmt.Errorf("invalid SWTPM ID received (no id)")
	}

	// request, id
	return split[0], split[1], nil
}

func cleanupFiles(id string) {
	statePath := fmt.Sprintf(swtpmStatePath, id)
	ctrlSockPath := fmt.Sprintf(swtpmCtrlSockPath, id)
	pidPath := fmt.Sprintf(swtpmPidPath, id)
	isEncryptedPath := fmt.Sprintf(swtpmIsEncryptedPath, id)
	os.RemoveAll(statePath)
	os.Remove(ctrlSockPath)
	os.Remove(pidPath)
	os.Remove(isEncryptedPath)
}

func makeDirs(dir string) error {
	// This returns nil if the directory already exists.
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

func getSwtpmPid(pidPath string, timeoutSeconds uint) (int, error) {
	startTime := time.Now()
	for {
		if time.Since(startTime).Seconds() >= float64(timeoutSeconds) {
			return 0, fmt.Errorf("timeout reached")
		}

		pidStr, err := os.ReadFile(pidPath)
		if err == nil {
			pid, err := strconv.Atoi(strings.TrimSpace(string(pidStr)))
			if err == nil {
				return pid, nil
			}
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func runSwtpm(id string) (int, error) {
	statePath := fmt.Sprintf(swtpmStatePath, id)
	ctrlSockPath := fmt.Sprintf(swtpmCtrlSockPath, id)
	binKeyPath := fmt.Sprintf(stateEncryptionKey, id)
	pidPath := fmt.Sprintf(swtpmPidPath, id)
	isEncryptedPath := fmt.Sprintf(swtpmIsEncryptedPath, id)
	swtpmArgs := []string{"socket", "--tpm2",
		"--tpmstate", "dir=" + statePath,
		"--ctrl", "type=unixio,path=" + ctrlSockPath + ",terminate",
		"--pid", "file=" + pidPath,
		"--daemon"}

	// If state directory already exists, this call will do nothing.
	if err := makeDirs(statePath); err != nil {
		return 0, fmt.Errorf("failed to create SWTPM state directory: %w", err)
	}

	if !isTPMAvailable() {
		log.Noticef("TPM is not available, starting SWTPM without state encryption!")

		// if SWTPM state for app marked as as encrypted, and TPM is not available
		// anymore, fail because this will corrupt the SWTPM state.
		if utils.FileExists(log, isEncryptedPath) {
			return 0, fmt.Errorf("state encryption was enabled for app, but TPM is no longer available")
		}

		cmd := exec.Command(swtpmPath, swtpmArgs...)
		if err := cmd.Run(); err != nil {
			return 0, fmt.Errorf("failed to start SWTPM: %w", err)
		}
	} else {
		log.Noticef("TPM is available, starting SWTPM with state encryption")

		key, err := getEncryptionKey()
		if err != nil {
			return 0, fmt.Errorf("failed to get SWTPM state encryption key : %w", err)
		}

		// we are about to write the key to the disk, so mark the app SWTPM state
		// as encrypted
		if !utils.FileExists(log, isEncryptedPath) {
			if err := utils.WriteRename(isEncryptedPath, []byte("Y")); err != nil {
				return 0, fmt.Errorf("failed to mark the app SWTPM state as encrypted: %w", err)
			}
		}

		if err := os.WriteFile(binKeyPath, key, 0644); err != nil {
			return 0, fmt.Errorf("failed to write key to file: %w", err)
		}

		swtpmArgs = append(swtpmArgs, "--key", "file="+binKeyPath+",format=binary,mode=aes-256-cbc,remove=true")
		cmd := exec.Command(swtpmPath, swtpmArgs...)
		if err := cmd.Run(); err != nil {
			// this shall not fail 🧙🏽‍♂️
			rmErr := os.Remove(binKeyPath)
			if rmErr != nil {
				return 0, fmt.Errorf("failed to start SWTPM: %w, failed to remove key file %w", err, rmErr)
			}
			return 0, fmt.Errorf("failed to start SWTPM: %w", err)
		}
	}

	pid, err := getSwtpmPid(pidPath, maxWaitTime)
	if err != nil {
		return 0, fmt.Errorf("failed to get SWTPM pid: %w", err)
	}

	// Add to the list.
	pids[id] = pid
	return pid, nil
}

func main() {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "vtpm", os.Getpid())
	if log == nil {
		fmt.Println("Failed to create log object")
		os.Exit(1)
	}

	serviceLoop()
}

func serviceLoop() {
	uds, err := net.Listen("unix", vtpmdCtrlSockPath)
	if err != nil {
		log.Errorf("failed to create vtpm control socket: %v", err)
		return
	}
	defer uds.Close()

	// Make sure we remove the socket file on exit.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		os.Remove(vtpmdCtrlSockPath)
		os.Exit(0)
	}()

	for {
		// xxx : later get peer creds (getpeereid) and check if the caller is
		// the domain manager to avoid any other process from sending requests.
		conn, err := uds.Accept()
		if err != nil {
			log.Errorf("failed to accept connection over vtpmd control socket: %v", err)
			continue
		}

		id, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			log.Errorf("failed to read SWTPM ID from connection: %v", err)
			continue
		}

		// Close the connection as soon as we read the ID,
		// handle one request at a time.
		conn.Close()

		// Don't launch go routines, instead serve requests one by one to avoid
		// using any locks, handle* functions access pids global variable.
		err = handleRequest(id)
		if err != nil {
			log.Errorf("failed to handle request: %v", err)
		}
	}
}

func handleRequest(id string) error {
	request, id, err := parseRequest(id)
	if err != nil {
		return fmt.Errorf("failed to parse request: %w", err)
	}

	switch request {
	case launchReq:
		// Domain manager is requesting to launch a new VM/App, run a new SWTPM
		// instance with the given id.
		return handleLaunch(id)
	case purgeReq:
		// VM/App is being deleted, domain manager is sending a purge request,
		// delete the SWTPM instance and clean up all the files.
		return handlePurge(id)
	case terminateReq:
		// Domain manager is sending a terminate request because it hit an error while
		// starting the app (i.e. qemu crashed), so just remove kill SWTPM instance,
		// remove it's pid for the list and decrease the liveInstances count.
		return handleTerminate(id)
	default:
		return fmt.Errorf("invalid request received")
	}
}

func handleLaunch(id string) error {
	if liveInstances >= maxInstances {
		return fmt.Errorf("max number of vTPM instances reached %d", liveInstances)
	}
	// If we have SWTPM instance with the same id running, it means either the
	// domain got rebooted or something went wrong on the dommain manager side!!
	// it the later case it should have sent a delete request if VM crashed or
	// there was any other VM related errors. Anyway, refuse to launch a new
	// instance with the same id as this might corrupt the state.
	if _, ok := pids[id]; ok {
		return fmt.Errorf("SWTPM instance with id %s already running", id)
	}

	pid, err := runSwtpm(id)
	if err != nil {
		return fmt.Errorf("failed to start SWTPM instance: %v", err)
	}

	log.Noticef("SWTPM instance with id %s is running with pid %d", id, pid)

	liveInstances++
	return nil
}

func handleTerminate(id string) error {
	// We expect the SWTPM to be terminated at this point, but just in case send
	// a term signal.
	pid, ok := pids[id]
	if ok {
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			if err != syscall.ESRCH {
				// This should not happen, but log it just in case.
				log.Errorf("failed to kill SWTPM instance (terminate request): %v", err)
			}
		}
		delete(pids, id)
		liveInstances--
	} else {
		return fmt.Errorf("terminate request failed, SWTPM instance with id %s not found", id)
	}

	return nil
}

func handlePurge(id string) error {
	log.Noticef("Purging SWTPM instance with id: %s", id)
	// we actually expect the SWTPM to be terminated at this point, because qemu
	// either sends CMD_SHUTDOWN through the control socket or in case of qemu
	// crashing, SWTPM terminates itself when the control socket is closed since
	// we run it with the "terminate" flag. but just in case send a term signal
	pid, ok := pids[id]
	if ok {
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			if err != syscall.ESRCH {
				// This should not happen, but log it just in case.
				log.Errorf("failed to kill SWTPM instance (purge request): %v", err)
			}
		}

		delete(pids, id)
		liveInstances--
	}

	// clean up files if exists
	cleanupFiles(id)
	return nil
}
