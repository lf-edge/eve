// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// This is a simple service that listens on a unix domain socket for a SWTPM ID
// and runs a SWTPM instance with that ID. The service also checks if the TPM is
// available, if it is, it will run SWTPM with state encryption enabled.
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	swtpmPath      = "/usr/bin/swtpm"
	maxInstances   = 10
	maxPidWaitTime = 5 //seconds
)

var (
	liveInstances int
	m             sync.Mutex
	log           *base.LogObject
	pids          = make(map[uuid.UUID]int, 0)
	// XXX : move the paths to types so we have everything EVE creates in one place.
	// These are defined as vars to be able to mock them in tests
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

func isAlive(pid int) bool {
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	return true
}

func cleanupFiles(uuid uuid.UUID) {
	id := uuid.String()
	os.RemoveAll(fmt.Sprintf(swtpmStatePath, id))
	os.Remove(fmt.Sprintf(swtpmCtrlSockPath, id))
	os.Remove(fmt.Sprintf(swtpmPidPath, id))
	os.Remove(fmt.Sprintf(swtpmIsEncryptedPath, id))
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

func readPidFile(pidPath string) (int, error) {
	pid := 0
	pidStr, err := os.ReadFile(pidPath)
	if err == nil {
		pid, err = strconv.Atoi(strings.TrimSpace(string(pidStr)))
		if err == nil {
			return pid, nil
		}
	}

	return 0, fmt.Errorf("failed to read pid file: %w", err)
}

func getSwtpmPid(pidPath string, timeoutSeconds uint) (int, error) {
	startTime := time.Now()
	for {
		if time.Since(startTime).Seconds() >= float64(timeoutSeconds) {
			return 0, fmt.Errorf("timeout reached after %d seconds", int(time.Since(startTime).Seconds()))
		}

		if pid, err := readPidFile(pidPath); err == nil {
			return pid, nil
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func runSwtpm(uuid uuid.UUID) (int, error) {
	id := uuid.String()
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
			return 0, fmt.Errorf("state encryption was enabled for SWTPM, but TPM is no longer available")
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

		// we are about to write the key to the disk, so mark the SWTPM state
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

	pid, err := getSwtpmPid(pidPath, maxPidWaitTime)
	if err != nil {
		return 0, fmt.Errorf("failed to get SWTPM pid: %w", err)
	}

	return pid, nil
}

// Domain manager is requesting to launch a new VM/App, run a new SWTPM
// instance with the given id.
func handleLaunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		err := fmt.Sprintf("Method %s not allowed", r.Method)
		http.Error(w, err, http.StatusMethodNotAllowed)
		return
	}

	// pids and liveInstances is shared, take care of them.
	m.Lock()
	defer m.Unlock()

	if liveInstances >= maxInstances {
		err := fmt.Sprintf("vTPM max number of SWTPM instances reached %d", liveInstances)
		http.Error(w, err, http.StatusTooManyRequests)
		return
	}

	reqID := r.URL.Query().Get("id")
	id := uuid.FromStringOrNil(reqID)
	if id == uuid.Nil {
		err := fmt.Sprintf("vTPM launch request failed, id \"%s\" is invalid", reqID)
		http.Error(w, err, http.StatusBadRequest)
		return
	}
	// If we have a record of SWTPM instance with the requested id,
	// check if it's still alive. if it is alive, refuse to launch a new
	// instance with the same id as this might corrupt the state.
	if _, ok := pids[id]; ok {
		pidPath := fmt.Sprintf(swtpmPidPath, id)
		// if pid file does not exist, it means the SWTPM instance gracefully
		// terminated and we can start a new one.
		if _, err := os.Stat(pidPath); err == nil {
			pid, err := getSwtpmPid(pidPath, maxPidWaitTime)
			if err != nil {
				err := fmt.Sprintf("vTPM failed to read pid file of SWTPM with id %s", id)
				http.Error(w, err, http.StatusExpectationFailed)
				return
			}

			// if the SWTPM instance is still alive, we can move on.
			if isAlive(pid) {
				log.Noticef("vTPM SWTPM instance with id %s is already running with pid %d", id, pid)
				w.WriteHeader(http.StatusOK)
				return
			}
		} else if !os.IsNotExist(err) {
			err := fmt.Sprintf("vTPM failed to check pid file of SWTPM with id %s: %v", id, err)
			http.Error(w, err, http.StatusFailedDependency)
			return
		}

		liveInstances--
		delete(pids, id)
	}

	pid, err := runSwtpm(id)
	if err != nil {
		err := fmt.Sprintf("vTPM failed to start SWTPM instance: %v", err)
		http.Error(w, err, http.StatusFailedDependency)
		return
	}

	log.Noticef("vTPM launched SWTPM instance with id: %s, pid: %d", id, pid)

	// Send a success response.
	pids[id] = pid
	liveInstances++
	w.WriteHeader(http.StatusOK)
}

// Domain manager is sending a terminate request because it hit an error while
// starting the app, so just kill SWTPM instance, remove it's pid from the list
// and decrease the liveInstances count.
func handleTerminate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		err := fmt.Sprintf("Method %s not allowed", r.Method)
		http.Error(w, err, http.StatusMethodNotAllowed)
		return
	}

	// pids and liveInstances is shared, take care of it.
	m.Lock()
	defer m.Unlock()

	reqID := r.URL.Query().Get("id")
	id := uuid.FromStringOrNil(reqID)
	if id == uuid.Nil {
		err := fmt.Sprintf("vTPM launch request failed, id \"%s\" is invalid", reqID)
		http.Error(w, err, http.StatusBadRequest)
		return
	}
	pid, ok := pids[id]
	if ok {
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			if err != syscall.ESRCH {
				// This should not happen, but log it just in case.
				log.Errorf("vTPM failed to kill SWTPM instance (terminate request): %v", err)
			}
		}
		delete(pids, id)
		liveInstances--
	} else {
		err := fmt.Sprintf("vTPM terminate request failed, SWTPM instance with id %s not found", id)
		http.Error(w, err, http.StatusNotFound)
		return
	}

	log.Noticef("vTPM terminated SWTPM instance with id: %s, pid: %d", id, pid)

	// send a success response.
	w.WriteHeader(http.StatusOK)
}

// VM/App is being deleted, domain manager is sending a purge request,
// delete the SWTPM instance and clean up all the files.
func handlePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		err := fmt.Sprintf("Method %s not allowed", r.Method)
		http.Error(w, err, http.StatusMethodNotAllowed)
		return
	}

	// pids and liveInstances is shared, take care of it.
	m.Lock()
	defer m.Unlock()

	reqID := r.URL.Query().Get("id")
	id := uuid.FromStringOrNil(reqID)
	if id == uuid.Nil {
		err := fmt.Sprintf("vTPM launch request failed, id \"%s\" is invalid", reqID)
		http.Error(w, err, http.StatusBadRequest)
		return
	}

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

	log.Noticef("vTPM purged SWTPM instance with id: %s, pid: %d", id, pid)

	// clean up the files and send a success response.
	cleanupFiles(id)
	w.WriteHeader(http.StatusOK)
}

func startServing() {
	if _, err := os.Stat(vtpmdCtrlSockPath); err == nil {
		os.Remove(vtpmdCtrlSockPath)
	}
	listener, err := net.Listen("unix", vtpmdCtrlSockPath)
	if err != nil {
		log.Fatalf("Error creating Unix socket: %v", err)
	}
	defer listener.Close()

	os.Chmod(vtpmdCtrlSockPath, 0600)
	mux := http.NewServeMux()
	mux.HandleFunc("/launch", handleLaunch)
	mux.HandleFunc("/terminate", handleTerminate)
	mux.HandleFunc("/purge", handlePurge)

	log.Noticef("vTPM server is listening on Unix socket: %s", vtpmdCtrlSockPath)
	http.Serve(listener, mux)
}

func main() {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "vtpm", os.Getpid())
	if log == nil {
		fmt.Println("Failed to create log object")
		os.Exit(1)
	}

	// this never returns, ideally.
	startServing()
}
