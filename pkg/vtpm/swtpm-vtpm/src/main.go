// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// This is a simple service that listens on a unix domain socket for a SWTPM ID
// and runs a SWTPM instance with that ID. The service also checks if the TPM is
// available, if it is, it will run SWTPM with state encryption enabled.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
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
	"golang.org/x/sys/unix"
)

const (
	swtpmPath          = "/usr/bin/swtpm"
	swtpmLogMaxSize    = 10 * 1024 * 1024 // 10MB
	swtpmLogMaxBackups = 3
	swtpmCtrlTimeout   = 5 * time.Second
)

type swtpmInstance struct {
	pid int
	lf  *logForwarder
}

var (
	maxPidWaitTime = 5  // seconds; overridden in tests
	maxInstances   = 32 // overridden in tests
	liveInstances  int
	m              sync.Mutex
	log            *base.LogObject
	instances      = make(map[uuid.UUID]*swtpmInstance)
	// idLocks serializes launch/terminate/purge for a single id without blocking other ids
	idMu    sync.Mutex
	idLocks = make(map[uuid.UUID]*sync.Mutex)
	// XXX : move the paths to types so we have everything EVE creates in one place.
	// These are defined as vars to be able to mock them in tests
	stateDir             = "/persist/swtpm"
	runDir               = "/run/swtpm"
	stateEncryptionKey   = path.Join(runDir, "%s.binkey")
	stateIsEncryptedPath = path.Join(stateDir, "%s.encrypted")
	workDir              = path.Join(stateDir, "tpm-state-%s")
	instanceLogFifoPath  = path.Join(runDir, "%s-swtpm.log.fifo")
	vtpmdCtrlSockPath    = types.VtpmdCtrlSocket
	swtpmCtrlSockPath    = types.SwtpmCtrlSocketPath
	swtpmPidPath         = types.SwtpmPidPath
	isTPMAvailable       = func() bool {
		_, err := os.Stat(etpm.TpmDevicePath)
		return err == nil
	}
	getEncryptionKey = func() ([]byte, error) {
		if etpm.PCRBankSHA256Enabled() {
			pcrSelection := etpm.GetDiskKeyPolicyPcrOrDefault(types.PolicyPcrFile)
			return etpm.UnsealDiskKeyWithRecovery(log, pcrSelection)
		}

		// call FetchVaultKey directly, we can just call FetchSealedVaultKey
		// and be happy and not care about the SHA256 banks, but FetchSealedVaultKey
		// creates the missing keys if not exist, and we don't want vTPM mess
		// with the keys and TPM state even if the chance is close to zero.
		return etpm.FetchVaultKey(log)
	}
)

func isAlive(pid int) bool {
	if err := syscall.Kill(pid, 0); err != nil {
		return false
	}
	return true
}

// isSwtpm reports whether pid is a live swtpm serving this id. A stale pid
// file or in-memory record can name another process after pid reuse.
func isSwtpm(pid int, id uuid.UUID) bool {
	if pid <= 0 || syscall.Kill(pid, 0) != nil {
		return false
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false
	}
	wantExe, err := filepath.EvalSymlinks(swtpmPath)
	if err != nil || exe != wantExe {
		return false
	}
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	// swtpm is launched with an exact "dir=<workDir>,backup" argv token, and
	// workDir embeds the id, so an exact match identifies this VM's swtpm.
	wantState := "dir=" + fmt.Sprintf(workDir, id.String()) + ",backup"
	for _, arg := range strings.Split(string(cmdline), "\x00") {
		if arg == wantState {
			return true
		}
	}
	return false
}

// Open the pidfd before checking /proc. If the process exits and its numeric
// pid is reused, the fd still refers to the original process and signalling
// it fails with ESRCH instead of signalling the replacement.
func openVerifiedSwtpm(pid int, id uuid.UUID) (int, error) {
	if pid <= 0 {
		return -1, nil
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return -1, nil
	}
	if err != nil {
		return -1, fmt.Errorf("open pidfd for swtpm pid %d: %w", pid, err)
	}
	if !isSwtpm(pid, id) {
		unix.Close(fd)
		return -1, nil
	}
	return fd, nil
}

func signalSwtpm(pid int, id uuid.UUID) (bool, error) {
	fd, err := openVerifiedSwtpm(pid, id)
	if err != nil || fd < 0 {
		return false, err
	}
	defer unix.Close(fd)
	if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return false, nil
		}
		return false, fmt.Errorf("signal swtpm pid %d: %w", pid, err)
	}
	return true, nil
}

// reapSwtpm reaps a terminated daemon inherited through subreaper mode.
// A process which is not our child returns ECHILD immediately.
func reapSwtpm(pid int) {
	if pid <= 0 {
		return
	}
	for i := 0; i < maxPidWaitTime*10; i++ {
		var status syscall.WaitStatus
		waited, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
		if waited == pid || err == syscall.ECHILD {
			return
		}
		if err != nil && err != syscall.EINTR {
			log.Errorf("failed to reap swtpm pid %d: %v", pid, err)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// waitForHealthCheckExit waits for the temporary swtpm to exit and reaps it
// when it became our child through subreaper mode.
func waitForHealthCheckExit(pid int) {
	if pid <= 0 {
		return
	}
	for i := 0; i < maxPidWaitTime*10; i++ {
		waited, err := syscall.Wait4(pid, nil, syscall.WNOHANG, nil)
		if waited == pid || (err == syscall.ECHILD && !isAlive(pid)) {
			return
		}
		if err != nil && err != syscall.ECHILD && err != syscall.EINTR {
			log.Errorf("failed to wait for health-check swtpm pid %d: %v", pid, err)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// lockID acquires the per-id lock and returns its unlock function.
func lockID(id uuid.UUID) func() {
	idMu.Lock()
	l, ok := idLocks[id]
	if !ok {
		l = &sync.Mutex{}
		idLocks[id] = l
	}
	idMu.Unlock()
	l.Lock()
	return l.Unlock
}

func cleanupFiles(uuid uuid.UUID) {
	id := uuid.String()

	// Drop the map entry under m, then do the slow file work and the
	// log-forwarder stop outside the lock.
	m.Lock()
	inst, ok := instances[uuid]
	if ok {
		delete(instances, uuid)
		liveInstances--
	}
	m.Unlock()
	if ok && inst.lf != nil {
		inst.lf.stop()
	}

	os.RemoveAll(fmt.Sprintf(workDir, id))
	os.Remove(fmt.Sprintf(swtpmCtrlSockPath, id))
	os.Remove(fmt.Sprintf(swtpmPidPath, id))
	os.Remove(fmt.Sprintf(stateIsEncryptedPath, id))
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

// checkSwtpmState probes a running swtpm's control socket to decide whether its
// state actually loaded. It returns stateBad=true ONLY when swtpm itself reports
// a failure to initialize its state (a genuine corruption/decrypt signal). Every
// transient or IPC problem is returned as err, so the caller never mistakes a
// hiccup for corruption and destroys good state.
func checkSwtpmState(uuid uuid.UUID) (stateBad bool, err error) {
	id := uuid.String()
	wd := fmt.Sprintf(workDir, id)
	ctrlSockPath := fmt.Sprintf(swtpmCtrlSockPath, id)
	pidPath := fmt.Sprintf(swtpmPidPath, id)

	if _, err := os.Stat(wd); err != nil {
		return false, fmt.Errorf("failed to check SWTPM state directory: %w", err)
	}
	if _, err := os.Stat(ctrlSockPath); err != nil {
		return false, fmt.Errorf("failed to check SWTPM control socket: %w", err)
	}
	if _, err := os.Stat(pidPath); err != nil {
		return false, fmt.Errorf("failed to check SWTPM pid file: %w", err)
	}

	// Open the control socket and send CMD_INIT. Bound every step so a hung
	// swtpm cannot block us indefinitely.
	con, err := net.DialTimeout("unix", ctrlSockPath, swtpmCtrlTimeout)
	if err != nil {
		return false, fmt.Errorf("failed to connect to SWTPM control socket: %w", err)
	}
	defer con.Close()
	if err := con.SetDeadline(time.Now().Add(swtpmCtrlTimeout)); err != nil {
		return false, fmt.Errorf("failed to set SWTPM control deadline: %w", err)
	}

	// CMD_INIT = 0x00 00 00 02 + flags
	cmd := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00}
	if _, err := con.Write(cmd); err != nil {
		return false, fmt.Errorf("failed to send CMD_INIT command to SWTPM: %w", err)
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(con, resp); err != nil {
		return false, fmt.Errorf("failed to read response from SWTPM: %w", err)
	}
	// expected response is 0x00 00 00 00
	if code := binary.BigEndian.Uint32(resp); code != 0 {
		return true, nil
	}
	return false, nil
}

func writeSwtpmKey(path string, key []byte) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove stale SWTPM key file: %w", err)
	}
	return os.WriteFile(path, key, 0600)
}

func runSwtpm(uuid uuid.UUID) (int, *logForwarder, error) {
	id := uuid.String()
	wd := fmt.Sprintf(workDir, id)
	ctrlSockPath := fmt.Sprintf(swtpmCtrlSockPath, id)
	binKeyPath := fmt.Sprintf(stateEncryptionKey, id)
	pidPath := fmt.Sprintf(swtpmPidPath, id)
	isEncryptedPath := fmt.Sprintf(stateIsEncryptedPath, id)
	fifoPath := fmt.Sprintf(instanceLogFifoPath, id)
	logPath := path.Join(wd, "swtpm.log")

	if err := makeDirs(wd); err != nil {
		return 0, nil, fmt.Errorf("failed to create SWTPM state directory: %w", err)
	}
	if err := makeDirs(path.Dir(fifoPath)); err != nil {
		return 0, nil, fmt.Errorf("failed to create SWTPM run directory: %w", err)
	}

	// create a log forwarder for this SWTPM instance
	lf, err := newLogForwarder(fifoPath, logPath)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create log forwarder: %w", err)
	}

	swtpmArgs := []string{"socket", "--tpm2",
		"--tpmstate", "dir=" + wd + ",backup",
		"--ctrl", "type=unixio,path=" + ctrlSockPath + ",terminate",
		"--pid", "file=" + pidPath,
		"--log", "level=3,file=" + lf.fifoPath,
		"--daemon"}

	if !isTPMAvailable() {
		log.Noticef("TPM is not available, starting SWTPM without state encryption!")
		// if SWTPM state for app marked as as encrypted, and TPM is not available
		// anymore, fail because this might corrupt the SWTPM state.
		if utils.FileExists(log, isEncryptedPath) {
			lf.stop()
			return 0, nil, fmt.Errorf("state encryption was enabled for SWTPM, but TPM is no longer available")
		}

		cmd := exec.Command(swtpmPath, swtpmArgs...)
		if err := cmd.Run(); err != nil {
			lf.stop()
			return 0, nil, fmt.Errorf("failed to start SWTPM: %w", err)
		}
	} else {
		log.Noticef("TPM is available, starting SWTPM with state encryption")

		key, err := getEncryptionKey()
		if err != nil {
			lf.stop()
			return 0, nil, fmt.Errorf("failed to get SWTPM state encryption key : %w", err)
		}

		// we are about to write the key to the disk, so mark the SWTPM state
		// as encrypted
		if !utils.FileExists(log, isEncryptedPath) {
			if err := utils.WriteRename(isEncryptedPath, []byte("Y")); err != nil {
				lf.stop()
				return 0, nil, fmt.Errorf("failed to mark the app SWTPM state as encrypted: %w", err)
			}
		}

		if err := writeSwtpmKey(binKeyPath, key); err != nil {
			lf.stop()
			return 0, nil, fmt.Errorf("failed to write key to file: %w", err)
		}

		swtpmArgs = append(swtpmArgs, "--key", "file="+binKeyPath+",format=binary,mode=aes-256-cbc,remove=true")
		cmd := exec.Command(swtpmPath, swtpmArgs...)
		if err := cmd.Run(); err != nil {
			// this shall not fail 🧙🏽‍♂️
			rmErr := os.Remove(binKeyPath)
			lf.stop()
			if rmErr != nil {
				return 0, nil, fmt.Errorf("failed to start SWTPM: %w, failed to remove key file %w", err, rmErr)
			}
			return 0, nil, fmt.Errorf("failed to start SWTPM: %w", err)
		}
	}

	pid, err := getSwtpmPid(pidPath, uint(maxPidWaitTime))
	if err != nil {
		lf.stop()
		return 0, nil, fmt.Errorf("failed to get SWTPM pid: %w", err)
	}

	return pid, lf, nil
}

// Domain manager is requesting to launch a new VM/App, run a new SWTPM
// instance with the given id.
func handleLaunch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		err := fmt.Sprintf("Method %s not allowed", r.Method)
		http.Error(w, err, http.StatusMethodNotAllowed)
		return
	}

	reqID := r.URL.Query().Get("id")
	id := uuid.FromStringOrNil(reqID)
	if id == uuid.Nil {
		err := fmt.Sprintf("vTPM launch request failed, id \"%s\" is invalid", reqID)
		http.Error(w, err, http.StatusBadRequest)
		return
	}

	// Serialize on this id so launch/terminate/purge for the same VM cannot
	// interleave, while other VMs run in parallel.
	unlock := lockID(id)
	defer unlock()

	// If we have a record of an SWTPM instance with this id and it is still
	// alive, reuse it; otherwise drop the stale record.
	m.Lock()
	inst, ok := instances[id]
	m.Unlock()
	if ok {
		pidPath := fmt.Sprintf(swtpmPidPath, id)
		// if pid file does not exist, it means the SWTPM instance gracefully
		// terminated and we can start a new one.
		if _, err := os.Stat(pidPath); err == nil {
			pid, err := getSwtpmPid(pidPath, uint(maxPidWaitTime))
			if err != nil {
				err := fmt.Sprintf("vTPM failed to read pid file of SWTPM with id %s", id)
				http.Error(w, err, http.StatusExpectationFailed)
				return
			}
			if isSwtpm(pid, id) {
				log.Noticef("vTPM SWTPM instance with id %s is already running with pid %d", id, inst.pid)
				w.WriteHeader(http.StatusOK)
				return
			}
		} else if !os.IsNotExist(err) {
			err := fmt.Sprintf("vTPM failed to check pid file of SWTPM with id %s: %v", id, err)
			http.Error(w, err, http.StatusFailedDependency)
			return
		}

		if inst.lf != nil {
			inst.lf.stop()
		}
		m.Lock()
		delete(instances, id)
		liveInstances--
		m.Unlock()
	}

	// Reserve a slot up front so concurrent launches for other ids honour the
	// cap; roll it back on any failure below.
	m.Lock()
	if liveInstances >= maxInstances {
		m.Unlock()
		err := fmt.Sprintf("vTPM max number of SWTPM instances reached %d", liveInstances)
		http.Error(w, err, http.StatusTooManyRequests)
		return
	}
	liveInstances++
	m.Unlock()
	launched := false
	defer func() {
		if !launched {
			m.Lock()
			liveInstances--
			m.Unlock()
		}
	}()

	// Run SWTPM for the health check first, if there is no backup state or
	// both normal state and backup are corrupted, we do a state reset with a warning.
	pid, lf, err := runSwtpm(id)
	if err != nil {
		err := fmt.Sprintf("vTPM failed to start SWTPM instance for health check: %v", err)
		http.Error(w, err, http.StatusFailedDependency)
		return
	}

	// check SWTPM health
	stateBad, checkErr := checkSwtpmState(id)
	waitForHealthCheckExit(pid)

	// The health-check run is done; stop its log forwarder before the next run.
	lf.stop()

	switch {
	case checkErr != nil:
		// A transient/IPC problem, not proof of corruption. Don't destroy state,
		// fail the launch and let the caller retry .
		err := fmt.Sprintf("vTPM health check for id %s failed transiently: %v", id, checkErr)
		log.Error(err)
		http.Error(w, err, http.StatusFailedDependency)
		return
	case stateBad:
		// swtpm reported it could not initialize the state (both the primary and
		// the ,backup copy are unusable). Preserve the bytes for recovery rather
		// then continue with fresh state so the guest can still boot.
		log.Errorf("SWTPM state for id %s is unrecoverable; preserving it and starting fresh", id)
		isEncryptedPath := fmt.Sprintf(stateIsEncryptedPath, id)
		if utils.FileExists(log, isEncryptedPath) {
			os.Remove(isEncryptedPath)
		}
		wd := fmt.Sprintf(workDir, id)
		corrupt := fmt.Sprintf("%s.corrupt-%d", wd, time.Now().Unix())
		if err := os.Rename(wd, corrupt); err != nil {
			err := fmt.Sprintf("failed to preserve corrupt SWTPM state directory: %v", err)
			http.Error(w, err, http.StatusFailedDependency)
			return
		}
		log.Errorf("preserved corrupt SWTPM state for id %s at %s", id, corrupt)
	default:
		log.Noticef("SWTPM instance state with id %s is healthy", id)
	}

	// Run SWTPM again, since we run SWTPM with the "terminate" flag, it will
	// terminate itself when the control socket is closed in checkSwtpmState.
	// in any case, this should work.
	pid, lf, err = runSwtpm(id)
	if err != nil {
		err := fmt.Sprintf("vTPM failed to start SWTPM instance: %v", err)
		http.Error(w, err, http.StatusFailedDependency)
		return
	}

	log.Noticef("vTPM launched SWTPM instance with id: %s, pid: %d", id, pid)

	// Record the instance (the slot was already reserved above).
	m.Lock()
	instances[id] = &swtpmInstance{pid: pid, lf: lf}
	m.Unlock()
	launched = true
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

	reqID := r.URL.Query().Get("id")
	id := uuid.FromStringOrNil(reqID)
	if id == uuid.Nil {
		err := fmt.Sprintf("vTPM launch request failed, id \"%s\" is invalid", reqID)
		http.Error(w, err, http.StatusBadRequest)
		return
	}

	unlock := lockID(id)
	defer unlock()

	m.Lock()
	inst, ok := instances[id]
	m.Unlock()
	if !ok {
		err := fmt.Sprintf("vTPM terminate request failed, SWTPM instance with id %s not found", id)
		http.Error(w, err, http.StatusNotFound)
		return
	}

	if _, err := signalSwtpm(inst.pid, id); err != nil {
		http.Error(w, fmt.Sprintf("vTPM failed to signal SWTPM instance: %v", err), http.StatusFailedDependency)
		return
	}
	go reapSwtpm(inst.pid)
	m.Lock()
	delete(instances, id)
	liveInstances--
	m.Unlock()
	if inst.lf != nil {
		inst.lf.stop()
	}

	log.Noticef("vTPM terminated SWTPM instance with id: %s, pid: %d", id, inst.pid)

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

	reqID := r.URL.Query().Get("id")
	id := uuid.FromStringOrNil(reqID)
	if id == uuid.Nil {
		err := fmt.Sprintf("vTPM launch request failed, id \"%s\" is invalid", reqID)
		http.Error(w, err, http.StatusBadRequest)
		return
	}

	unlock := lockID(id)
	defer unlock()

	// we actually expect the SWTPM to be terminated at this point, because qemu
	// either sends CMD_SHUTDOWN through the control socket or in case of qemu
	// crashing, SWTPM terminates itself when the control socket is closed since
	// we run it with the "terminate" flag. but just in case send a term signal
	m.Lock()
	inst, ok := instances[id]
	m.Unlock()
	if ok {
		if _, err := signalSwtpm(inst.pid, id); err != nil {
			http.Error(w, fmt.Sprintf("failed to signal SWTPM instance: %v", err), http.StatusFailedDependency)
			return
		}
		go reapSwtpm(inst.pid)
		log.Noticef("vTPM purged SWTPM instance with id: %s, pid: %d", id, inst.pid)
	}

	// clean up the files and send a success response.
	cleanupFiles(id)
	w.WriteHeader(http.StatusOK)
}

func listenUnix(socketPath string) (net.Listener, error) {
	oldMask := syscall.Umask(0o077)
	defer syscall.Umask(oldMask)
	return net.Listen("unix", socketPath)
}

func startServing() {
	if _, err := os.Stat(vtpmdCtrlSockPath); err == nil {
		os.Remove(vtpmdCtrlSockPath)
	}
	listener, err := listenUnix(vtpmdCtrlSockPath)
	if err != nil {
		log.Fatalf("Error creating Unix socket: %v", err)
	}
	defer listener.Close()

	if err := os.Chmod(vtpmdCtrlSockPath, 0o600); err != nil {
		log.Fatalf("failed to restrict vtpmd control socket permissions: %v", err)
	}

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
	// swtpm double-forks with --daemon. Adopt its daemon child so vtpmd can
	// reap it instead of leaving a zombie under the container's PID 1 shell.
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		log.Warnf("vTPM failed to set child subreaper: %v", err)
	}

	// this never returns, ideally.
	startServing()
}
