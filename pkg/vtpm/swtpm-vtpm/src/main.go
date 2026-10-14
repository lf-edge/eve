// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// This is a simple service that listens on a unix domain socket for a SWTPM ID
// and runs a SWTPM instance with that ID. The service also checks if the TPM is
// available, if it is, it will run SWTPM with state encryption enabled.
package main

import (
	"bytes"
	"context"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	utils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	swtpmPath            = "/usr/bin/swtpm"
	swtpmIoctlPath       = "/usr/bin/swtpm_ioctl"
	swtpmLogMaxSize      = 10 * 1024 * 1024 // 10MB
	swtpmLogMaxBackups   = 3
	swtpmCtrlTimeout     = 5 * time.Second
	maxCorruptStates     = 10
	protectedStateMarker = ".pcr-protected"
)

type swtpmInstance struct {
	pid int
	lf  *logForwarder
}

type instanceLock struct {
	mu   sync.Mutex
	refs int
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
	idLocks = make(map[uuid.UUID]*instanceLock)
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
	sha256PCRAvailable = etpm.PCRBankSHA256Enabled
	// Read the legacy key without FetchVaultKey's generate-on-miss behavior.
	getLegacyEncryptionKey = func() ([]byte, error) {
		rw, err := tpm2.OpenTPM(etpm.TpmDevicePath)
		if err != nil {
			return nil, err
		}
		defer rw.Close()
		return tpm2.NVReadEx(rw, etpm.TpmDiskKeyHdl, tpm2.HandleOwner, etpm.EmptyPassword, 0)
	}
	invokeSwtpmIoctl     = swtpmIoctl
	probeSwtpmState      = checkSwtpmState
	renameStateDir       = os.Rename
	writeProtectedMarker = func(statePath string) error {
		return utils.WriteRename(filepath.Join(statePath, protectedStateMarker), []byte("Y"))
	}
	getEncryptionKey = func() ([]byte, error) {
		if sha256PCRAvailable() {
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
	return isSwtpmAt(pid, fmt.Sprintf(workDir, id.String()))
}

func isSwtpmAt(pid int, statePath string) bool {
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
	wantState := "dir=" + statePath + ",backup"
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
	return openVerifiedSwtpmAt(pid, fmt.Sprintf(workDir, id.String()))
}

func openVerifiedSwtpmAt(pid int, statePath string) (int, error) {
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
	if !isSwtpmAt(pid, statePath) {
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

// waitSwtpmExit waits on a pidfd so state is not reused or deleted while the
// daemon is still running. A pidfd cannot switch to a replacement process.
func waitSwtpmExit(pid int, id uuid.UUID) error {
	return waitSwtpmExitAt(pid, fmt.Sprintf(workDir, id.String()))
}

func waitSwtpmExitAt(pid int, statePath string) error {
	fd, err := openVerifiedSwtpmAt(pid, statePath)
	if err != nil || fd < 0 {
		if err == nil && pid > 0 {
			// The daemon may already have exited but still be our zombie.
			_, _ = syscall.Wait4(pid, nil, syscall.WNOHANG, nil)
		}
		return err
	}
	defer unix.Close(fd)
	return waitPidfdExit(pid, fd)
}

func waitPidfdExit(pid, fd int) error {
	deadline := time.Now().Add(time.Duration(maxPidWaitTime) * time.Second)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("swtpm pid %d did not exit", pid)
		}
		pollMillis := int(remaining.Milliseconds())
		if pollMillis < 1 {
			pollMillis = 1
		}
		n, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, pollMillis)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("wait for swtpm pid %d: %w", pid, err)
		}
		if n > 0 {
			// In subreaper mode this is our child; elsewhere ECHILD is expected.
			_, err := syscall.Wait4(pid, nil, syscall.WNOHANG, nil)
			if err != nil && err != syscall.ECHILD && err != syscall.EINTR {
				return fmt.Errorf("reap swtpm pid %d: %w", pid, err)
			}
			return nil
		}
	}
}

func stopSwtpmAndWait(pid int, id uuid.UUID) error {
	return stopSwtpmAndWaitAt(pid, fmt.Sprintf(workDir, id.String()))
}

func stopSwtpmAndWaitAt(pid int, statePath string) error {
	fd, err := openVerifiedSwtpmAt(pid, statePath)
	if err != nil || fd < 0 {
		return err
	}
	defer unix.Close(fd)
	if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("signal swtpm pid %d: %w", pid, err)
	}
	return waitPidfdExit(pid, fd)
}

func forceStopSwtpmAt(pid int, statePath string) error {
	fd, err := openVerifiedSwtpmAt(pid, statePath)
	if err != nil || fd < 0 {
		return err
	}
	defer unix.Close(fd)
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("force-stop SWTPM pid %d: %w", pid, err)
	}
	return waitPidfdExit(pid, fd)
}

// stopHealthCheckSwtpm waits for the normal control-socket termination. If the
// probe failed before connecting, signal the daemon ourselves. A daemon that
// still does not exit is force-stopped before its state can be reused.
func stopHealthCheckSwtpm(pid int, id uuid.UUID, probeErr error) error {
	var err error
	if probeErr == nil {
		err = waitSwtpmExit(pid, id)
	} else {
		err = stopSwtpmAndWait(pid, id)
	}
	if err == nil {
		return nil
	}
	if forceErr := forceStopSwtpmAt(pid, fmt.Sprintf(workDir, id.String())); forceErr != nil {
		return errors.Join(err, forceErr)
	}
	return err
}

// preserveCorruptStates sets aside the failed state and retains only the ten
// newest saved copies for this VM. If preservation fails, discard the corrupt
// active directory so the caller can still start swtpm with fresh state. An
// empty result means no copy was preserved; an error means fresh state could
// not be made available.
func preserveCorruptStates(workDir string, stamp int64) (string, error) {
	newest := fmt.Sprintf("%s.corrupt-%d", workDir, stamp)
	if err := os.Rename(workDir, newest); err != nil {
		log.Warnf("failed to preserve corrupt SWTPM state directory: %v", err)
		if err := os.RemoveAll(workDir); err != nil {
			return "", fmt.Errorf("remove corrupt SWTPM state after failed preservation: %w", err)
		}
		return "", nil
	}
	if err := pruneCorruptStates(workDir, newest); err != nil {
		log.Warnf("failed to prune old corrupt SWTPM state: %v", err)
	}
	return newest, nil
}

// pruneCorruptStates protects the new copy even if another entry has a
// timestamp in the future.
func pruneCorruptStates(workDir, newest string) error {
	entries, err := os.ReadDir(filepath.Dir(workDir))
	if err != nil {
		return fmt.Errorf("list preserved SWTPM states: %w", err)
	}
	type savedState struct {
		path  string
		stamp int64
	}
	prefix := filepath.Base(workDir) + ".corrupt-"
	var states []savedState
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		stamp, err := strconv.ParseInt(strings.TrimPrefix(entry.Name(), prefix), 10, 64)
		if err != nil {
			continue
		}
		states = append(states, savedState{
			path:  filepath.Join(filepath.Dir(workDir), entry.Name()),
			stamp: stamp,
		})
	}
	sort.Slice(states, func(i, j int) bool {
		if states[i].stamp == states[j].stamp {
			return states[i].path < states[j].path
		}
		return states[i].stamp < states[j].stamp
	})
	remaining := len(states)
	for _, state := range states {
		if remaining <= maxCorruptStates {
			break
		}
		if state.path == newest {
			continue
		}
		if err := os.RemoveAll(state.path); err != nil {
			return fmt.Errorf("remove old SWTPM state %s: %w", state.path, err)
		}
		remaining--
	}
	return nil
}

// lockID acquires the per-id lock and returns its unlock function.
func lockID(id uuid.UUID) func() {
	idMu.Lock()
	l, ok := idLocks[id]
	if !ok {
		l = &instanceLock{}
		idLocks[id] = l
	}
	l.refs++
	idMu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		idMu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(idLocks, id)
		}
		idMu.Unlock()
	}
}

func cleanupFiles(uuid uuid.UUID) error {
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

	var cleanupErr error
	if err := os.RemoveAll(fmt.Sprintf(workDir, id)); err != nil {
		cleanupErr = errors.Join(cleanupErr, err)
	}
	if err := cleanupMigrationStages(uuid); err != nil {
		cleanupErr = errors.Join(cleanupErr, err)
	}
	for _, file := range []string{
		fmt.Sprintf(swtpmCtrlSockPath, id),
		fmt.Sprintf(swtpmPidPath, id),
		fmt.Sprintf(stateIsEncryptedPath, id),
	} {
		if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	return cleanupErr
}

func migrationStageRoot(id uuid.UUID) string {
	return filepath.Join(filepath.Dir(fmt.Sprintf(workDir, id.String())), ".vtpm-migrate-"+id.String())
}

func migrationRunRoot(id uuid.UUID) string {
	return filepath.Join(runDir, ".vtpm-migrate-"+id.String())
}

func cleanupMigrationStages(id uuid.UUID) error {
	stageRoot := migrationStageRoot(id)
	runtimeRoot := migrationRunRoot(id)
	for _, process := range []struct{ name, state string }{
		{"legacy", fmt.Sprintf(workDir, id.String())},
		{"protected", filepath.Join(stageRoot, "state")},
	} {
		pid, err := readPidFile(filepath.Join(runtimeRoot, process.name+".pid"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s migration pid: %w", process.name, err)
		}
		if err := forceStopSwtpmAt(pid, process.state); err != nil {
			return fmt.Errorf("stop %s migration SWTPM before cleanup: %w", process.name, err)
		}
	}
	return errors.Join(os.RemoveAll(stageRoot), os.RemoveAll(runtimeRoot))
}

// recoverMigrationStage repairs an interruption between the two directory
// renames. Before the new directory is active, the old state is authoritative.
func recoverMigrationStage(id uuid.UUID) error {
	active := fmt.Sprintf(workDir, id.String())
	stageRoot := migrationStageRoot(id)
	legacy := filepath.Join(stageRoot, "legacy")
	if _, err := os.Stat(active); errors.Is(err, os.ErrNotExist) {
		if _, legacyErr := os.Stat(legacy); legacyErr == nil {
			if err := os.Rename(legacy, active); err != nil {
				return fmt.Errorf("restore legacy SWTPM state after interrupted migration: %w", err)
			}
		} else if !errors.Is(legacyErr, os.ErrNotExist) {
			return fmt.Errorf("check interrupted SWTPM migration: %w", legacyErr)
		}
	} else if err != nil {
		return fmt.Errorf("check active SWTPM state during migration recovery: %w", err)
	}
	if err := cleanupMigrationStages(id); err != nil {
		return fmt.Errorf("remove interrupted SWTPM migration files: %w", err)
	}
	return nil
}

func makeDirs(dir string, mode os.FileMode) error {
	// This returns nil if the directory already exists.
	if err := os.MkdirAll(dir, mode); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// if path already exist MkdirAll won't check the perms,
	// so make sure it has the right permissions by applying it again.
	if err := os.Chmod(dir, mode); err != nil {
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
// state actually loaded. It returns stateBad=true when swtpm reports a state
// initialization failure, which can also mean an incorrect encryption key.
// Transport and IPC problems are returned as err.
func checkSwtpmState(uuid uuid.UUID) (stateBad bool, err error) {
	id := uuid.String()
	return checkSwtpmStateAt(fmt.Sprintf(workDir, id), fmt.Sprintf(swtpmCtrlSockPath, id), fmt.Sprintf(swtpmPidPath, id))
}

func checkSwtpmStateAt(wd, ctrlSockPath, pidPath string) (stateBad bool, err error) {

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
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

type swtpmRunOptions struct {
	stateDir     string
	ctrlPath     string
	pidPath      string
	fifoPath     string
	keyPath      string
	key          []byte
	migrationKey []byte
	terminate    bool
	incoming     bool
}

func migrationSwtpmOptions(id uuid.UUID, name, stateDir string) swtpmRunOptions {
	opts := swtpmOptions(id)
	opts.stateDir = stateDir
	runtimeRoot := migrationRunRoot(id)
	opts.ctrlPath = filepath.Join(runtimeRoot, name+".ctrl")
	opts.pidPath = filepath.Join(runtimeRoot, name+".pid")
	opts.fifoPath = filepath.Join(runtimeRoot, name+".fifo")
	opts.keyPath = filepath.Join(runtimeRoot, name+".key")
	return opts
}

func swtpmOptions(id uuid.UUID) swtpmRunOptions {
	s := id.String()
	return swtpmRunOptions{
		stateDir:  fmt.Sprintf(workDir, s),
		ctrlPath:  fmt.Sprintf(swtpmCtrlSockPath, s),
		pidPath:   fmt.Sprintf(swtpmPidPath, s),
		fifoPath:  fmt.Sprintf(instanceLogFifoPath, s),
		keyPath:   fmt.Sprintf(stateEncryptionKey, s),
		terminate: true,
	}
}

func runSwtpm(id uuid.UUID) (int, *logForwarder, error) {
	if !isTPMAvailable() {
		return runSwtpmWithKey(id, nil)
	}
	key, err := getEncryptionKey()
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get SWTPM state encryption key: %w", err)
	}
	return runSwtpmWithKey(id, key)
}

func runSwtpmWithKey(id uuid.UUID, key []byte) (int, *logForwarder, error) {
	opts := swtpmOptions(id)
	opts.key = key
	marker := fmt.Sprintf(stateIsEncryptedPath, id.String())
	if key == nil {
		if utils.FileExists(log, marker) {
			return 0, nil, fmt.Errorf("state encryption was enabled for SWTPM, but TPM is no longer available")
		}
		log.Noticef("TPM is not available, starting SWTPM without state encryption!")
	} else if !utils.FileExists(log, marker) {
		if err := utils.WriteRename(marker, []byte("Y")); err != nil {
			return 0, nil, fmt.Errorf("failed to mark the app SWTPM state as encrypted: %w", err)
		}
	}
	return startSwtpm(opts)
}

func startSwtpm(opts swtpmRunOptions) (int, *logForwarder, error) {
	if err := makeDirs(opts.stateDir, 0700); err != nil {
		return 0, nil, fmt.Errorf("failed to create SWTPM state directory: %w", err)
	}
	if err := makeDirs(path.Dir(opts.fifoPath), 0755); err != nil {
		return 0, nil, fmt.Errorf("failed to create SWTPM run directory: %w", err)
	}
	lf, err := newLogForwarder(opts.fifoPath, path.Join(opts.stateDir, "swtpm.log"))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create log forwarder: %w", err)
	}
	ctrl := "type=unixio,path=" + opts.ctrlPath + ",mode=0600"
	if opts.terminate {
		ctrl += ",terminate"
	}
	args := []string{"socket", "--tpm2",
		"--tpmstate", "dir=" + opts.stateDir + ",backup",
		"--ctrl", ctrl,
		"--pid", "file=" + opts.pidPath,
		"--log", "level=3,file=" + lf.fifoPath,
		"--daemon"}
	if opts.incoming {
		args = append(args, "--migration", "incoming")
	}
	var keyFiles []string
	defer func() {
		for _, file := range keyFiles {
			_ = os.Remove(file)
		}
	}()
	if opts.key != nil {
		if err := writeSwtpmKey(opts.keyPath, opts.key); err != nil {
			lf.stop()
			return 0, nil, fmt.Errorf("failed to write SWTPM key: %w", err)
		}
		keyFiles = append(keyFiles, opts.keyPath)
		args = append(args, "--key", "file="+opts.keyPath+",format=binary,mode=aes-256-cbc,remove=true")
	}
	if opts.migrationKey != nil {
		migrationKeyPath := opts.keyPath + ".migration"
		if err := writeSwtpmKey(migrationKeyPath, opts.migrationKey); err != nil {
			lf.stop()
			return 0, nil, fmt.Errorf("failed to write SWTPM migration key: %w", err)
		}
		keyFiles = append(keyFiles, migrationKeyPath)
		args = append(args, "--migration-key", "file="+migrationKeyPath+",format=binary,mode=aes-256-cbc,remove=true")
	}
	if err := exec.Command(swtpmPath, args...).Run(); err != nil {
		lf.stop()
		return 0, nil, fmt.Errorf("failed to start SWTPM: %w", err)
	}
	pid, err := getSwtpmPid(opts.pidPath, uint(maxPidWaitTime))
	if err != nil {
		lf.stop()
		return 0, nil, fmt.Errorf("failed to get SWTPM pid: %w", err)
	}
	return pid, lf, nil
}

func swtpmIoctl(ctrlPath string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), swtpmCtrlTimeout)
	defer cancel()
	argv := append([]string{"--unix", ctrlPath}, args...)
	out, err := exec.CommandContext(ctx, swtpmIoctlPath, argv...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("swtpm_ioctl %v: %w: %s", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// tryLegacyAndMigrate checks whether the existing state belongs to the legacy
// key. On success it exports an encrypted migration blob and imports it into a
// separate state directory using the PCR-protected key. The original directory
// stays active until the new state has passed its own health check.
func tryLegacyAndMigrate(id uuid.UUID, legacyKey, protectedKey []byte) (bool, error) {
	stageRoot := migrationStageRoot(id)
	runtimeRoot := migrationRunRoot(id)
	opts := migrationSwtpmOptions(id, "legacy", fmt.Sprintf(workDir, id.String()))
	if err := os.Mkdir(stageRoot, 0700); err != nil {
		return false, fmt.Errorf("create state migration directory: %w", err)
	}
	if err := os.Mkdir(runtimeRoot, 0700); err != nil {
		_ = os.Remove(stageRoot)
		return false, fmt.Errorf("create SWTPM migration runtime directory: %w", err)
	}
	keepStageRoot := false
	stopMigrationProcess := func(pid *int, statePath string) error {
		if *pid <= 0 {
			return nil
		}
		err := stopSwtpmAndWaitAt(*pid, statePath)
		if err == nil {
			*pid = 0
			return nil
		}
		if forceErr := forceStopSwtpmAt(*pid, statePath); forceErr != nil {
			keepStageRoot = true
			return errors.Join(err, forceErr)
		}
		*pid = 0
		return err
	}
	defer func() {
		if keepStageRoot {
			return
		}
		if err := cleanupMigrationStages(id); err != nil {
			log.Warnf("failed to remove SWTPM migration files for id %s: %v", id, err)
		}
	}()
	blob := filepath.Join(stageRoot, "permanent.blob")
	newState := filepath.Join(stageRoot, "state")

	opts.key = legacyKey
	opts.migrationKey = protectedKey
	opts.terminate = false
	pid, lf, err := startSwtpm(opts)
	if err != nil {
		return false, fmt.Errorf("start SWTPM with legacy key: %w", err)
	}
	defer func() {
		if pid > 0 {
			stoppingPID := pid
			if err := stopMigrationProcess(&pid, opts.stateDir); err != nil {
				log.Errorf("failed to stop legacy-key SWTPM pid %d: %v", stoppingPID, err)
			}
		}
		if lf != nil {
			lf.stop()
		}
	}()
	bad, err := checkSwtpmStateAt(opts.stateDir, opts.ctrlPath, opts.pidPath)
	if err != nil {
		return false, fmt.Errorf("probe SWTPM with legacy key: %w", err)
	}
	if bad {
		if err := stopMigrationProcess(&pid, opts.stateDir); err != nil {
			return false, err
		}
		return false, nil
	}
	if err := invokeSwtpmIoctl(opts.ctrlPath, "--save", "permanent", blob); err != nil {
		return false, fmt.Errorf("export legacy SWTPM state: %w", err)
	}
	if err := stopMigrationProcess(&pid, opts.stateDir); err != nil {
		return false, err
	}
	lf.stop()
	lf = nil

	newOpts := migrationSwtpmOptions(id, "protected", newState)
	newOpts.key = protectedKey
	newOpts.migrationKey = protectedKey
	newOpts.terminate = false
	newOpts.incoming = true
	newPID, newLF, err := startSwtpm(newOpts)
	if err != nil {
		return false, fmt.Errorf("start protected SWTPM for state import: %w", err)
	}
	defer func() {
		if newPID > 0 {
			stoppingPID := newPID
			if err := stopMigrationProcess(&newPID, newState); err != nil {
				log.Errorf("failed to stop state-import SWTPM pid %d: %v", stoppingPID, err)
			}
		}
		if newLF != nil {
			newLF.stop()
		}
	}()
	if err := invokeSwtpmIoctl(newOpts.ctrlPath, "--load", "permanent", blob); err != nil {
		return false, fmt.Errorf("import protected SWTPM state: %w", err)
	}
	if err := invokeSwtpmIoctl(newOpts.ctrlPath, "-i"); err != nil {
		return false, fmt.Errorf("initialize imported SWTPM state: %w", err)
	}
	if err := invokeSwtpmIoctl(newOpts.ctrlPath, "-s"); err != nil {
		return false, fmt.Errorf("save imported SWTPM state: %w", err)
	}
	if err := stopMigrationProcess(&newPID, newState); err != nil {
		return false, err
	}
	newLF.stop()
	newLF = nil

	// A second load verifies that the committed files can be read with the
	// protected key, not merely imported into a running TPM.
	newOpts.migrationKey = nil
	newOpts.incoming = false
	newOpts.terminate = true
	newPID, newLF, err = startSwtpm(newOpts)
	if err != nil {
		return false, fmt.Errorf("verify protected SWTPM state: %w", err)
	}
	bad, err = checkSwtpmStateAt(newState, newOpts.ctrlPath, newOpts.pidPath)
	waitErr := waitSwtpmExitAt(newPID, newState)
	if waitErr == nil {
		newPID = 0
	} else {
		waitErr = errors.Join(waitErr, stopMigrationProcess(&newPID, newState))
	}
	newLF.stop()
	newLF = nil
	if err != nil || bad || waitErr != nil {
		return false, fmt.Errorf("verify protected SWTPM state: bad=%t probe=%v wait=%v", bad, err, waitErr)
	}
	if err := writeProtectedMarker(newState); err != nil {
		return false, fmt.Errorf("mark protected SWTPM state: %w", err)
	}
	legacy := filepath.Join(stageRoot, "legacy")
	if err := renameStateDir(opts.stateDir, legacy); err != nil {
		return false, fmt.Errorf("set aside legacy SWTPM state: %w", err)
	}
	if err := renameStateDir(newState, opts.stateDir); err != nil {
		if rollbackErr := renameStateDir(legacy, opts.stateDir); rollbackErr != nil {
			keepStageRoot = true
			return false, fmt.Errorf("activate protected SWTPM state: %w; restore legacy state: %v", err, rollbackErr)
		}
		return false, fmt.Errorf("activate protected SWTPM state: %w", err)
	}
	log.Noticef("migrated SWTPM state for id %s from legacy to PCR-protected key", id)
	return true, nil
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
	if err := recoverMigrationStage(id); err != nil {
		http.Error(w, fmt.Sprintf("failed to clear stale SWTPM migration state: %v", err), http.StatusFailedDependency)
		return
	}

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
	protectedMode := isTPMAvailable() && sha256PCRAvailable()
	statePath := fmt.Sprintf(workDir, id.String())
	_, markerErr := os.Stat(filepath.Join(statePath, protectedStateMarker))
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		http.Error(w, fmt.Sprintf("failed to check PCR-protected state marker: %v", markerErr), http.StatusFailedDependency)
		return
	}
	protectedBefore := markerErr == nil
	if protectedBefore && !protectedMode {
		http.Error(w, "PCR-protected SWTPM state requires the protected TPM key", http.StatusFailedDependency)
		return
	}
	var protectedKey []byte
	if protectedMode {
		var err error
		protectedKey, err = getEncryptionKey()
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to get PCR-protected SWTPM key: %v", err), http.StatusFailedDependency)
			return
		}
	}
	launch := func() (int, *logForwarder, error) {
		if protectedMode {
			return runSwtpmWithKey(id, protectedKey)
		}
		return runSwtpm(id)
	}
	encryptedBefore := utils.FileExists(log, fmt.Sprintf(stateIsEncryptedPath, id.String()))

	// Run SWTPM for the health check first, if there is no backup state or
	// both normal state and backup are corrupted, we do a state reset with a warning.
	pid, lf, err := launch()
	if err != nil {
		err := fmt.Sprintf("vTPM failed to start SWTPM instance for health check: %v", err)
		http.Error(w, err, http.StatusFailedDependency)
		return
	}

	// check SWTPM health
	stateBad, checkErr := probeSwtpmState(id)
	stopErr := stopHealthCheckSwtpm(pid, id, checkErr)

	// The health-check run is done; stop its log forwarder before the next run.
	lf.stop()
	if stopErr != nil {
		http.Error(w, fmt.Sprintf("vTPM health-check process did not stop: %v", stopErr), http.StatusFailedDependency)
		return
	}

	switch {
	case checkErr != nil:
		// A transient/IPC problem, not proof of corruption. Don't destroy state,
		// fail the launch and let the caller retry .
		err := fmt.Sprintf("vTPM health check for id %s failed transiently: %v", id, checkErr)
		log.Error(err)
		http.Error(w, err, http.StatusFailedDependency)
		return
	case stateBad:
		if protectedBefore {
			http.Error(w, "PCR-protected SWTPM state could not be loaded; state preserved", http.StatusFailedDependency)
			return
		}
		if protectedMode && encryptedBefore {
			legacyKey, err := getLegacyEncryptionKey()
			if err != nil {
				http.Error(w, fmt.Sprintf("failed to read legacy SWTPM key; state preserved: %v", err), http.StatusFailedDependency)
				return
			}
			if !bytes.Equal(legacyKey, protectedKey) {
				loaded, err := tryLegacyAndMigrate(id, legacyKey, protectedKey)
				if err != nil {
					http.Error(w, fmt.Sprintf("failed to migrate legacy SWTPM state; state preserved: %v", err), http.StatusFailedDependency)
					return
				}
				if loaded {
					break
				}
			}
		}
		// swtpm reported it could not initialize the state (both the primary and
		// the ,backup copy are unusable). Preserve the bytes for recovery rather
		// then continue with fresh state so the guest can still boot.
		log.Errorf("SWTPM state for id %s is unrecoverable; preserving it and starting fresh", id)
		isEncryptedPath := fmt.Sprintf(stateIsEncryptedPath, id)
		if utils.FileExists(log, isEncryptedPath) {
			os.Remove(isEncryptedPath)
		}
		wd := fmt.Sprintf(workDir, id)
		corrupt, err := preserveCorruptStates(wd, time.Now().UnixNano())
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to clear corrupt SWTPM state: %v", err), http.StatusFailedDependency)
			return
		}
		if corrupt != "" {
			log.Errorf("preserved corrupt SWTPM state for id %s at %s", id, corrupt)
		}
	default:
		log.Noticef("SWTPM instance state with id %s is healthy", id)
	}

	// Run SWTPM again, since we run SWTPM with the "terminate" flag, it will
	// terminate itself when the control socket is closed in checkSwtpmState.
	// in any case, this should work.
	pid, lf, err = launch()
	if err != nil {
		err := fmt.Sprintf("vTPM failed to start SWTPM instance: %v", err)
		http.Error(w, err, http.StatusFailedDependency)
		return
	}
	if protectedMode {
		if err := writeProtectedMarker(statePath); err != nil {
			_ = stopSwtpmAndWait(pid, id)
			lf.stop()
			http.Error(w, fmt.Sprintf("failed to mark PCR-protected SWTPM state: %v", err), http.StatusFailedDependency)
			return
		}
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
		if err := stopSwtpmAndWait(inst.pid, id); err != nil {
			http.Error(w, fmt.Sprintf("failed to stop SWTPM before purge: %v", err), http.StatusFailedDependency)
			return
		}
		log.Noticef("vTPM purged SWTPM instance with id: %s, pid: %d", id, inst.pid)
	}

	// clean up the files and send a success response.
	if err := cleanupFiles(id); err != nil {
		http.Error(w, fmt.Sprintf("failed to remove SWTPM files: %v", err), http.StatusFailedDependency)
		return
	}
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
