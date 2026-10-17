// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const baseDir = "/tmp/swtpm/test"

var client = &http.Client{}

func TestMain(m *testing.M) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "vtpm", os.Getpid())
	maxPidWaitTime = 15
	maxInstances = 3
	os.MkdirAll(baseDir, 0755)
	runDir = baseDir + "/run"
	if err := os.MkdirAll(runDir, 0700); err != nil {
		panic(err)
	}

	stateEncryptionKey = baseDir + "/%s.binkey"
	stateIsEncryptedPath = baseDir + "/%s.encrypted"
	workDir = baseDir + "/tpm-state-%s"
	instanceLogFifoPath = baseDir + "/%s.log.fifo"
	swtpmCtrlSockPath = baseDir + "/%s.ctrl.sock"
	swtpmPidPath = baseDir + "/%s.pid"
	vtpmdCtrlSockPath = baseDir + "/vtpmd.ctrl.sock"

	client = &http.Client{
		Transport: UnixSocketTransport(vtpmdCtrlSockPath),
		Timeout:   60 * time.Second,
	}

	go startServing()
	time.Sleep(1 * time.Second)
	os.Exit(m.Run())
}

func TestSignalSwtpmRejectsForgedCommandLine(t *testing.T) {
	id := generateUUID()
	wantState := "dir=" + fmt.Sprintf(workDir, id.String()) + ",backup"
	// A different executable can carry the same state argument. Checking argv
	// alone would signal it as though it were this VM's swtpm.
	cmd := exec.Command("/bin/sh", "-c", "while :; do sleep 1; done", "swtpm", wantState)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	processFD, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = unix.Close(processFD)
	}()

	fd, err := openVerifiedSwtpm(cmd.Process.Pid, id)
	if err != nil {
		t.Fatal(err)
	}
	if fd >= 0 {
		_ = unix.Close(fd)
		t.Fatal("accepted a non-swtpm executable")
	}
	sent, err := signalSwtpm(cmd.Process.Pid, id)
	if err != nil || sent {
		t.Fatalf("signalSwtpm = (%v, %v), want (false, nil)", sent, err)
	}
	pollFD := []unix.PollFd{{Fd: int32(processFD), Events: unix.POLLIN}}
	if n, err := unix.Poll(pollFD, 100); err != nil || n != 0 {
		t.Fatalf("unrelated process exited after signal attempt: poll=%d, err=%v", n, err)
	}
}

func TestOpenVerifiedSwtpm(t *testing.T) {
	id := generateUUID()
	isTPMAvailable = func() bool { return false }
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("launch: %v: %s", err, body)
	}
	defer func() {
		if body, _, err := sendPurgeRequest(id); err != nil {
			t.Errorf("purge: %v: %s", err, body)
		}
	}()

	m.Lock()
	pid := instances[id].pid
	m.Unlock()
	fd, err := openVerifiedSwtpm(pid, id)
	if err != nil || fd < 0 {
		t.Fatalf("openVerifiedSwtpm(%d, %s) = (%d, %v)", pid, id, fd, err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.PidfdSendSignal(fd, 0, nil, 0); err != nil {
		t.Fatalf("verified pidfd is not live: %v", err)
	}
	otherID := generateUUID()
	otherFD, err := openVerifiedSwtpm(pid, otherID)
	if err != nil || otherFD >= 0 {
		if otherFD >= 0 {
			_ = unix.Close(otherFD)
		}
		t.Fatalf("accepted swtpm belonging to another VM: fd=%d, err=%v", otherFD, err)
	}
}

func TestWriteSwtpmKeyPermissions(t *testing.T) {
	for _, stale := range []bool{false, true} {
		name := "new"
		if stale {
			name = "stale"
		}
		t.Run(name, func(t *testing.T) {
			keyPath := t.TempDir() + "/key"
			if stale {
				if err := os.WriteFile(keyPath, []byte("old"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(keyPath, 0644); err != nil {
					t.Fatal(err)
				}
			}
			key := []byte("new key material")
			if err := writeSwtpmKey(keyPath, key); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(keyPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != 0600 {
				t.Fatalf("key file mode = %04o, want 0600", got)
			}
			if got, err := os.ReadFile(keyPath); err != nil || string(got) != string(key) {
				t.Fatalf("key file contents = %q, err = %v", got, err)
			}
		})
	}
	t.Run("stale removal fails", func(t *testing.T) {
		keyPath := t.TempDir() + "/key"
		if err := os.Mkdir(keyPath, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath+"/keep", []byte("keep"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := writeSwtpmKey(keyPath, []byte("secret")); err == nil {
			t.Fatal("expected an error when stale path cannot be removed")
		}
	})
}

func TestWriteSwtpmKeyDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, keyPath); err != nil {
		t.Fatal(err)
	}
	if err := writeSwtpmKey(keyPath, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(victim)
	if err != nil || string(data) != "keep" {
		t.Fatalf("symlink target changed: %q, err %v", data, err)
	}
}

func TestStateDirectoryIsPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := makeDirs(dir, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("state directory mode is %o, want 0700", info.Mode().Perm())
	}
}

func TestIDLocksAreReclaimed(t *testing.T) {
	id := generateUUID()
	release := lockID(id)
	release()
	idMu.Lock()
	_, exists := idLocks[id]
	idMu.Unlock()
	if exists {
		t.Fatal("unused per-ID lock was retained")
	}
}

func TestEncryptedStateResetsWithWrongKey(t *testing.T) {
	id := generateUUID()
	oldTPM, oldKey, oldPCR := isTPMAvailable, getEncryptionKey, sha256PCRAvailable
	t.Cleanup(func() {
		isTPMAvailable, getEncryptionKey, sha256PCRAvailable = oldTPM, oldKey, oldPCR
		_, _, _ = sendPurgeRequest(id)
		_ = cleanupFiles(id)
		corruptDirs, _ := filepath.Glob(fmt.Sprintf(workDir, id.String()) + ".corrupt-*")
		for _, dir := range corruptDirs {
			_ = os.RemoveAll(dir)
		}
	})
	isTPMAvailable = func() bool { return true }
	sha256PCRAvailable = func() bool { return false }
	key := make([]byte, 32)
	getEncryptionKey = func() ([]byte, error) { return key, nil }
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("launch: %v: %s", err, body)
	}
	if body, _, err := sendTerminateRequest(id); err != nil {
		t.Fatalf("terminate: %v: %s", err, body)
	}
	state := fmt.Sprintf(workDir, id.String())
	marker := fmt.Sprintf(stateIsEncryptedPath, id.String())
	original, err := os.ReadFile(filepath.Join(state, "tpm2-00.permall"))
	if err != nil {
		t.Fatal(err)
	}
	key[0] = 1
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("wrong key launch did not reset state: %v: %s", err, body)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("fresh state is not marked encrypted: %v", err)
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("fresh state missing: %v", err)
	}
	corruptDirs, err := filepath.Glob(state + ".corrupt-*")
	if err != nil || len(corruptDirs) != 1 {
		t.Fatalf("expected one preserved old state, got %v: %v", corruptDirs, err)
	}
	preserved, err := os.ReadFile(filepath.Join(corruptDirs[0], "tpm2-00.permall"))
	if err != nil || string(preserved) != string(original) {
		t.Fatalf("old encrypted state was not preserved: err=%v", err)
	}
}

func prepareLegacyStateForMigration(t *testing.T, id uuid.UUID) ([]byte, []byte, func()) {
	t.Helper()
	legacyKey := make([]byte, 32)
	protectedKey := make([]byte, 32)
	if _, err := rand.Read(legacyKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(protectedKey); err != nil {
		t.Fatal(err)
	}
	oldTPM, oldPCR, oldGetKey, oldLegacy := isTPMAvailable, sha256PCRAvailable, getEncryptionKey, getLegacyEncryptionKey
	protectedMode := false
	isTPMAvailable = func() bool { return true }
	sha256PCRAvailable = func() bool { return protectedMode }
	getEncryptionKey = func() ([]byte, error) {
		if protectedMode {
			return protectedKey, nil
		}
		return legacyKey, nil
	}
	getLegacyEncryptionKey = func() ([]byte, error) { return legacyKey, nil }
	t.Cleanup(func() {
		_, _, _ = sendPurgeRequest(id)
		_ = cleanupFiles(id)
		corruptDirs, _ := filepath.Glob(fmt.Sprintf(workDir, id.String()) + ".corrupt-*")
		for _, dir := range corruptDirs {
			_ = os.RemoveAll(dir)
		}
		isTPMAvailable, sha256PCRAvailable, getEncryptionKey, getLegacyEncryptionKey = oldTPM, oldPCR, oldGetKey, oldLegacy
	})
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("create legacy state: %v: %s", err, body)
	}
	conn := simulateVMAttach(t, id)
	_ = conn.Close()
	m.Lock()
	pid := instances[id].pid
	m.Unlock()
	fd, err := openVerifiedSwtpm(pid, id)
	if err != nil || fd < 0 {
		t.Fatalf("open legacy SWTPM pidfd: fd=%d err=%v", fd, err)
	}
	if body, _, err := sendTerminateRequest(id); err != nil {
		_ = unix.Close(fd)
		t.Fatalf("terminate legacy instance: %v: %s", err, body)
	}
	if err := waitPidfdExit(pid, fd); err != nil {
		_ = unix.Close(fd)
		t.Fatalf("wait for legacy SWTPM shutdown: %v", err)
	}
	_ = unix.Close(fd)
	return legacyKey, protectedKey, func() { protectedMode = true }
}

func TestLegacyEncryptedStateMigratesToProtectedKey(t *testing.T) {
	id := generateUUID()
	legacyKey, protectedKey, enableProtected := prepareLegacyStateForMigration(t, id)
	state := fmt.Sprintf(workDir, id.String())
	oldState, err := os.ReadFile(filepath.Join(state, "tpm2-00.permall"))
	if err != nil {
		t.Fatal(err)
	}
	// Establish the migration precondition using the same saved state: the
	// protected key cannot load it, while the legacy key still can.
	for _, probe := range []struct {
		name    string
		key     []byte
		wantBad bool
	}{
		{name: "protected", key: protectedKey, wantBad: true},
		{name: "legacy", key: legacyKey, wantBad: false},
	} {
		opts := swtpmOptions(id)
		opts.key = probe.key
		pid, lf, err := startSwtpm(opts)
		if err != nil {
			t.Fatalf("start pre-migration probe with %s key: %v", probe.name, err)
		}
		bad, probeErr := checkSwtpmState(id)
		waitErr := waitSwtpmExit(pid, id)
		lf.stop()
		if probeErr != nil || bad != probe.wantBad || waitErr != nil {
			t.Fatalf("pre-migration %s key: bad=%t, probe=%v, wait=%v; want bad=%t", probe.name, bad, probeErr, waitErr, probe.wantBad)
		}
	}
	enableProtected()
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("migrate legacy state: %v: %s", err, body)
	}
	for _, dir := range []string{migrationStageRoot(id), migrationRunRoot(id)} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("migration directory %s remains: %v", dir, err)
		}
	}
	if body, _, err := sendTerminateRequest(id); err != nil {
		t.Fatalf("terminate migrated instance: %v: %s", err, body)
	}
	newState, err := os.ReadFile(filepath.Join(state, "tpm2-00.permall"))
	if err != nil || bytes.Equal(oldState, newState) {
		t.Fatalf("state was not re-encrypted: err=%v", err)
	}
	// The old key must no longer decrypt the active files.
	opts := swtpmOptions(id)
	opts.key = legacyKey
	pid, lf, err := startSwtpm(opts)
	if err != nil {
		t.Fatal(err)
	}
	bad, probeErr := checkSwtpmState(id)
	waitErr := waitSwtpmExit(pid, id)
	lf.stop()
	if probeErr != nil || !bad || waitErr != nil {
		t.Fatalf("old key loaded migrated state: bad=%t probe=%v wait=%v", bad, probeErr, waitErr)
	}
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("reload with protected key: %v: %s", err, body)
	}
}

func TestLegacyMigrationFailurePreservesState(t *testing.T) {
	id := generateUUID()
	_, _, enableProtected := prepareLegacyStateForMigration(t, id)
	oldIoctl := invokeSwtpmIoctl
	t.Cleanup(func() { invokeSwtpmIoctl = oldIoctl })
	invokeSwtpmIoctl = func(ctrl string, args ...string) error {
		if len(args) > 0 && args[0] == "--load" {
			return fmt.Errorf("injected import failure")
		}
		return oldIoctl(ctrl, args...)
	}
	enableProtected()
	if body, status, err := sendLaunchRequest(id); err == nil || status != http.StatusFailedDependency {
		t.Fatalf("expected migration failure: status=%d err=%v body=%s", status, err, body)
	}
	// The original state is still loadable with the legacy key.
	sha256PCRAvailable = func() bool { return false }
	getEncryptionKey = func() ([]byte, error) { return getLegacyEncryptionKey() }
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("legacy state lost after migration failure: %v: %s", err, body)
	}
}

func TestProtectedKeyFailureWithoutLegacyKeyPreservesState(t *testing.T) {
	id := generateUUID()
	_, _, enableProtected := prepareLegacyStateForMigration(t, id)
	oldLegacy := getLegacyEncryptionKey
	t.Cleanup(func() { getLegacyEncryptionKey = oldLegacy })
	getLegacyEncryptionKey = func() ([]byte, error) { return nil, fmt.Errorf("injected TPM NV read failure") }
	enableProtected()
	if body, status, err := sendLaunchRequest(id); err == nil || status != http.StatusFailedDependency {
		t.Fatalf("expected legacy-key lookup failure: status=%d err=%v body=%s", status, err, body)
	}
	if _, err := os.Stat(filepath.Join(fmt.Sprintf(workDir, id.String()), "tpm2-00.permall")); err != nil {
		t.Fatalf("original state lost: %v", err)
	}
}

func TestBothEncryptionKeysFailPreservesCorruptState(t *testing.T) {
	id := generateUUID()
	_, _, enableProtected := prepareLegacyStateForMigration(t, id)
	state := fmt.Sprintf(workDir, id.String())
	for _, name := range []string{"tpm2-00.permall", "tpm2-00.permall.bak"} {
		if err := os.WriteFile(filepath.Join(state, name), []byte("corrupted data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	enableProtected()
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("start fresh after both keys failed: %v: %s", err, body)
	}
	corruptDirs, err := filepath.Glob(state + ".corrupt-*")
	if err != nil || len(corruptDirs) != 1 {
		t.Fatalf("expected one preserved corrupt state, got %v: %v", corruptDirs, err)
	}
	for _, name := range []string{"tpm2-00.permall", "tpm2-00.permall.bak"} {
		data, err := os.ReadFile(filepath.Join(corruptDirs[0], name))
		if err != nil || string(data) != "corrupted data" {
			t.Fatalf("old state %s was not preserved: %q, err=%v", name, data, err)
		}
	}
}

func TestMigrationNeverFallsBackToLegacyKeyAgain(t *testing.T) {
	id := generateUUID()
	_, _, enableProtected := prepareLegacyStateForMigration(t, id)
	enableProtected()
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("migrate legacy state: %v: %s", err, body)
	}
	if body, _, err := sendTerminateRequest(id); err != nil {
		t.Fatalf("terminate migrated instance: %v: %s", err, body)
	}
	state := fmt.Sprintf(workDir, id.String())
	if _, err := os.Stat(filepath.Join(state, protectedStateMarker)); err != nil {
		t.Fatalf("migration marker missing: %v", err)
	}
	oldGetKey, oldLegacy, oldPCR := getEncryptionKey, getLegacyEncryptionKey, sha256PCRAvailable
	t.Cleanup(func() { getEncryptionKey, getLegacyEncryptionKey, sha256PCRAvailable = oldGetKey, oldLegacy, oldPCR })
	legacyCalls := 0
	getLegacyEncryptionKey = func() ([]byte, error) {
		legacyCalls++
		return nil, fmt.Errorf("legacy fallback must not run")
	}
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	getEncryptionKey = func() ([]byte, error) { return wrongKey, nil }
	if body, status, err := sendLaunchRequest(id); err == nil || status != http.StatusFailedDependency {
		t.Fatalf("expected protected-key failure: status=%d err=%v body=%s", status, err, body)
	}
	if legacyCalls != 0 {
		t.Fatalf("legacy key retried %d times after migration", legacyCalls)
	}
	if _, err := os.Stat(filepath.Join(state, protectedStateMarker)); err != nil {
		t.Fatalf("migrated state marker lost: %v", err)
	}
	// Removing SHA-256 PCR support must also leave protected state untouched.
	sha256PCRAvailable = func() bool { return false }
	if body, status, err := sendLaunchRequest(id); err == nil || status != http.StatusFailedDependency {
		t.Fatalf("expected no-PCR failure: status=%d err=%v body=%s", status, err, body)
	}
	if legacyCalls != 0 {
		t.Fatalf("legacy key retried without PCR support")
	}
}

func TestMigrationMarkerFailureLeavesLegacyStateActive(t *testing.T) {
	id := generateUUID()
	_, _, enableProtected := prepareLegacyStateForMigration(t, id)
	oldWrite := writeProtectedMarker
	t.Cleanup(func() { writeProtectedMarker = oldWrite })
	writeProtectedMarker = func(string) error { return fmt.Errorf("injected marker write failure") }
	enableProtected()
	if body, status, err := sendLaunchRequest(id); err == nil || status != http.StatusFailedDependency {
		t.Fatalf("expected migration marker failure: status=%d err=%v body=%s", status, err, body)
	}
	state := fmt.Sprintf(workDir, id.String())
	if _, err := os.Stat(filepath.Join(state, protectedStateMarker)); !os.IsNotExist(err) {
		t.Fatalf("protected marker appeared before migration: %v", err)
	}
	sha256PCRAvailable = func() bool { return false }
	getEncryptionKey = func() ([]byte, error) { return getLegacyEncryptionKey() }
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("legacy state lost after marker failure: %v: %s", err, body)
	}
}

func TestMigrationSecondRenameFailureRestoresLegacyState(t *testing.T) {
	id := generateUUID()
	_, _, enableProtected := prepareLegacyStateForMigration(t, id)
	oldRename := renameStateDir
	t.Cleanup(func() { renameStateDir = oldRename })
	active := fmt.Sprintf(workDir, id.String())
	renameStateDir = func(oldPath, newPath string) error {
		if oldPath == filepath.Join(migrationStageRoot(id), "state") && newPath == active {
			return fmt.Errorf("injected second rename failure")
		}
		return oldRename(oldPath, newPath)
	}
	enableProtected()
	if body, status, err := sendLaunchRequest(id); err == nil || status != http.StatusFailedDependency {
		t.Fatalf("expected migration rename failure: status=%d err=%v body=%s", status, err, body)
	}
	if _, err := os.Stat(filepath.Join(active, "tpm2-00.permall")); err != nil {
		t.Fatalf("legacy state was not restored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(active, protectedStateMarker)); !os.IsNotExist(err) {
		t.Fatalf("legacy state unexpectedly marked protected: %v", err)
	}
	sha256PCRAvailable = func() bool { return false }
	getEncryptionKey = func() ([]byte, error) { return getLegacyEncryptionKey() }
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("legacy state could not load after rollback: %v: %s", err, body)
	}
}

func TestRecoverMigrationStopsStagedSwtpmBeforeCleanup(t *testing.T) {
	id := generateUUID()
	stageRoot := migrationStageRoot(id)
	runtimeRoot := migrationRunRoot(id)
	stageState := filepath.Join(stageRoot, "state")
	if err := os.Mkdir(stageRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(runtimeRoot, 0700); err != nil {
		t.Fatal(err)
	}
	opts := migrationSwtpmOptions(id, "protected", stageState)
	opts.terminate = false
	pid, lf, err := startSwtpm(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = forceStopSwtpmAt(pid, stageState)
		lf.stop()
		_ = cleanupMigrationStages(id)
	})
	fd, err := openVerifiedSwtpmAt(pid, stageState)
	if err != nil || fd < 0 {
		t.Fatalf("open staged SWTPM pidfd: fd=%d err=%v", fd, err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := recoverMigrationStage(id); err != nil {
		t.Fatalf("recover migration with a running staged SWTPM: %v", err)
	}
	if err := waitPidfdExit(pid, fd); err != nil {
		t.Fatalf("staged SWTPM survived recovery: %v", err)
	}
	if _, err := os.Stat(migrationStageRoot(id)); !os.IsNotExist(err) {
		t.Fatalf("staged directory was not removed: %v", err)
	}
	if _, err := os.Stat(runtimeRoot); !os.IsNotExist(err) {
		t.Fatalf("migration runtime directory was not removed: %v", err)
	}
}

func TestMigrationKeepsKeyPathsOffPersistentStorage(t *testing.T) {
	id := generateUUID()
	stageRoot := migrationStageRoot(id)
	runtimeRoot := migrationRunRoot(id)
	opts := migrationSwtpmOptions(id, "legacy", fmt.Sprintf(workDir, id.String()))
	for _, path := range []string{opts.keyPath, opts.keyPath + ".migration", opts.ctrlPath, opts.pidPath, opts.fifoPath} {
		if filepath.Dir(path) != runtimeRoot {
			t.Fatalf("migration runtime path %s is not under %s", path, runtimeRoot)
		}
		if strings.HasPrefix(path, stageRoot+string(os.PathSeparator)) {
			t.Fatalf("migration runtime path %s is under persistent state", path)
		}
	}
}

func TestRecoverInterruptedKeyMigration(t *testing.T) {
	for _, tc := range []struct {
		name          string
		activePresent bool
		activePolicy  bool
		legacyPresent bool
	}{
		{"before first rename", true, false, false},
		{"between renames", false, false, true},
		{"after second rename", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldWork := workDir
			workDir = filepath.Join(t.TempDir(), "tpm-state-%s")
			t.Cleanup(func() { workDir = oldWork })
			id := generateUUID()
			active := fmt.Sprintf(workDir, id.String())
			stageRoot := migrationStageRoot(id)
			runtimeRoot := migrationRunRoot(id)
			if err := os.Mkdir(stageRoot, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(runtimeRoot, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(runtimeRoot, "stale"), []byte("stale"), 0600); err != nil {
				t.Fatal(err)
			}
			newState := filepath.Join(stageRoot, "state")
			if err := os.Mkdir(newState, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(newState, protectedStateMarker), []byte("Y"), 0600); err != nil {
				t.Fatal(err)
			}
			if tc.activePresent {
				if err := os.Mkdir(active, 0700); err != nil {
					t.Fatal(err)
				}
				if tc.activePolicy {
					if err := os.WriteFile(filepath.Join(active, protectedStateMarker), []byte("Y"), 0600); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(filepath.Join(active, "old"), []byte("legacy"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.legacyPresent {
				legacy := filepath.Join(stageRoot, "legacy")
				if err := os.Mkdir(legacy, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(legacy, "old"), []byte("legacy"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := recoverMigrationStage(id); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(stageRoot); !os.IsNotExist(err) {
				t.Fatalf("migration staging directory remains: %v", err)
			}
			if _, err := os.Stat(runtimeRoot); !os.IsNotExist(err) {
				t.Fatalf("migration runtime directory remains: %v", err)
			}
			file := "old"
			if tc.activePolicy {
				file = protectedStateMarker
			}
			if _, err := os.Stat(filepath.Join(active, file)); err != nil {
				t.Fatalf("active state not recovered: %v", err)
			}
		})
	}
}

func TestPurgeWaitsForSwtpmExit(t *testing.T) {
	id := generateUUID()
	oldTPM := isTPMAvailable
	t.Cleanup(func() { isTPMAvailable = oldTPM; _ = cleanupFiles(id) })
	isTPMAvailable = func() bool { return false }
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("launch: %v: %s", err, body)
	}
	ctrlInfo, err := os.Stat(fmt.Sprintf(swtpmCtrlSockPath, id.String()))
	if err != nil {
		t.Fatal(err)
	}
	if ctrlInfo.Mode().Perm() != 0600 {
		t.Fatalf("swtpm control socket mode is %o, want 0600", ctrlInfo.Mode().Perm())
	}
	pid, err := readPidFile(fmt.Sprintf(swtpmPidPath, id.String()))
	if err != nil {
		t.Fatal(err)
	}
	if body, _, err := sendPurgeRequest(id); err != nil {
		t.Fatalf("purge: %v: %s", err, body)
	}
	if isSwtpm(pid, id) {
		t.Fatal("purge returned while swtpm was still running")
	}
}

func TestPurgePreservesStateWhenSwtpmCannotStop(t *testing.T) {
	id := generateUUID()
	oldTPM, oldWait := isTPMAvailable, maxPidWaitTime
	t.Cleanup(func() { isTPMAvailable, maxPidWaitTime = oldTPM, oldWait; _ = cleanupFiles(id) })
	isTPMAvailable = func() bool { return false }
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("launch: %v: %s", err, body)
	}
	pid, err := readPidFile(fmt.Sprintf(swtpmPidPath, id.String()))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Kill(pid, syscall.SIGCONT) }()
	maxPidWaitTime = 1
	if body, status, err := sendPurgeRequest(id); err == nil || status != http.StatusFailedDependency {
		t.Fatalf("purge of stopped swtpm: status=%d err=%v body=%s", status, err, body)
	}
	if _, err := os.Stat(fmt.Sprintf(workDir, id.String())); err != nil {
		t.Fatalf("state removed while swtpm was still alive: %v", err)
	}
	if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	maxPidWaitTime = oldWait
	if body, _, err := sendPurgeRequest(id); err != nil {
		t.Fatalf("retry purge: %v: %s", err, body)
	}
}

func TestPurgeReportsCleanupFailure(t *testing.T) {
	id := generateUUID()
	oldCtrl := swtpmCtrlSockPath
	root := t.TempDir()
	swtpmCtrlSockPath = filepath.Join(root, "%s.ctrl")
	t.Cleanup(func() { swtpmCtrlSockPath = oldCtrl })
	blocked := fmt.Sprintf(swtpmCtrlSockPath, id.String())
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "keep"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handlePurge(w, httptest.NewRequest(http.MethodGet, "/purge?id="+id.String(), nil))
	if w.Code != http.StatusFailedDependency {
		t.Fatalf("purge returned %d after cleanup failure: %s", w.Code, w.Body.String())
	}
}

func TestCheckSwtpmStateReplies(t *testing.T) {
	oldWork, oldCtrl, oldPid := workDir, swtpmCtrlSockPath, swtpmPidPath
	dir := t.TempDir()
	workDir = filepath.Join(dir, "state-%s")
	swtpmCtrlSockPath = filepath.Join(dir, "%s.sock")
	swtpmPidPath = filepath.Join(dir, "%s.pid")
	t.Cleanup(func() { workDir, swtpmCtrlSockPath, swtpmPidPath = oldWork, oldCtrl, oldPid })
	for _, tc := range []struct {
		name    string
		reply   []byte
		bad     bool
		wantErr bool
	}{
		{"fragmented success", []byte{0, 0, 0, 0}, false, false},
		{"state failure", []byte{0, 0, 0, 1}, true, false},
		{"short response", []byte{0, 0, 0}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := generateUUID()
			if err := os.MkdirAll(fmt.Sprintf(workDir, id.String()), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fmt.Sprintf(swtpmPidPath, id.String()), []byte("123"), 0600); err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("unix", fmt.Sprintf(swtpmCtrlSockPath, id.String()))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			done := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					done <- err
					return
				}
				defer func() { _ = conn.Close() }()
				cmd := make([]byte, 8)
				_, err = io.ReadFull(conn, cmd)
				if err == nil {
					for _, b := range tc.reply {
						_, err = conn.Write([]byte{b})
						if err != nil {
							break
						}
					}
				}
				done <- err
			}()
			bad, err := checkSwtpmState(id)
			if bad != tc.bad || (err != nil) != tc.wantErr {
				t.Fatalf("bad=%v err=%v", bad, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLogForwarderStopWithIdleFIFO(t *testing.T) {
	for _, withWriter := range []bool{false, true} {
		name := "no writer"
		if withWriter {
			name = "idle writer"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			lf, err := newLogForwarder(filepath.Join(dir, "swtpm.fifo"), filepath.Join(dir, "swtpm.log"))
			if err != nil {
				t.Fatal(err)
			}
			var writer *os.File
			if withWriter {
				// O_RDWR keeps a writer present even while the forwarder reopens
				// the read end, without blocking this test on FIFO open ordering.
				writer, err = os.OpenFile(lf.fifoPath, os.O_RDWR|syscall.O_NONBLOCK, 0)
				if err != nil {
					lf.stop()
					t.Fatal(err)
				}
				defer func() { _ = writer.Close() }()
				time.Sleep(50 * time.Millisecond)
			}
			stopped := make(chan struct{})
			go func() {
				lf.stop()
				close(stopped)
			}()
			select {
			case <-stopped:
			case <-time.After(2 * time.Second):
				if writer != nil {
					_ = writer.Close() // release a blocked read before failing the test
				}
				t.Fatal("log forwarder did not stop promptly")
			}
		})
	}
}

func TestReapSwtpm(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	reapSwtpm(pid)
	if waited, err := syscall.Wait4(pid, nil, syscall.WNOHANG, nil); waited != -1 || err != syscall.ECHILD {
		t.Fatalf("wait after reap = (%d, %v), want (-1, ECHILD)", waited, err)
	}

	// A PID outside our child set must return promptly rather than polling
	// through the full timeout.
	start := time.Now()
	reapSwtpm(os.Getpid())
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("reaping a non-child took %v", elapsed)
	}
}

func TestHealthCheckProbeFailureStopsSwtpm(t *testing.T) {
	id := generateUUID()
	oldProbe, oldTPM := probeSwtpmState, isTPMAvailable
	t.Cleanup(func() {
		probeSwtpmState, isTPMAvailable = oldProbe, oldTPM
		_, _, _ = sendPurgeRequest(id)
	})
	isTPMAvailable = func() bool { return false }
	var pid, fd int
	probeSwtpmState = func(id uuid.UUID) (bool, error) {
		var err error
		pid, err = readPidFile(fmt.Sprintf(swtpmPidPath, id.String()))
		if err != nil {
			return false, err
		}
		fd, err = openVerifiedSwtpm(pid, id)
		if err != nil || fd < 0 {
			return false, fmt.Errorf("open health-check pidfd: fd=%d err=%v", fd, err)
		}
		return false, fmt.Errorf("injected failure before control-socket connect")
	}
	body, status, err := sendLaunchRequest(id)
	if err == nil || status != http.StatusFailedDependency {
		t.Fatalf("expected health-check failure: status=%d err=%v body=%s", status, err, body)
	}
	if fd < 0 || pid <= 0 {
		t.Fatalf("health-check process was not captured: pid=%d fd=%d", pid, fd)
	}
	defer func() { _ = unix.Close(fd) }()
	if n, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 100); err != nil || n != 1 {
		t.Fatalf("health-check SWTPM survived failed probe: poll=%d err=%v", n, err)
	}
	probeSwtpmState = oldProbe
	if body, _, err := sendLaunchRequest(id); err != nil {
		t.Fatalf("launch after failed health check: %v: %s", err, body)
	}
}

func TestHealthCheckTimeoutForceStopsSwtpm(t *testing.T) {
	id := generateUUID()
	oldTimeout := maxPidWaitTime
	maxPidWaitTime = 1
	t.Cleanup(func() { maxPidWaitTime = oldTimeout })
	opts := swtpmOptions(id)
	opts.terminate = false
	pid, lf, err := startSwtpm(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer lf.stop()
	t.Cleanup(func() { _ = forceStopSwtpmAt(pid, opts.stateDir); _ = cleanupFiles(id) })
	fd, err := openVerifiedSwtpm(pid, id)
	if err != nil || fd < 0 {
		t.Fatalf("open health-check pidfd: fd=%d err=%v", fd, err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := stopHealthCheckSwtpm(pid, id, nil); err == nil {
		t.Fatal("expected health-check timeout before force-stop")
	}
	if n, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 100); err != nil || n != 1 {
		t.Fatalf("health-check SWTPM survived timeout: poll=%d err=%v", n, err)
	}
}

func TestPreserveCorruptStates(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "tpm-state-vm")
	if err := os.Mkdir(workDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "failed-state"), []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	for stamp := 1; stamp <= 11; stamp++ {
		if err := os.Mkdir(fmt.Sprintf("%s.corrupt-%d", workDir, stamp), 0700); err != nil {
			t.Fatal(err)
		}
	}
	otherVM := workDir + "-other.corrupt-0"
	if err := os.Mkdir(otherVM, 0700); err != nil {
		t.Fatal(err)
	}
	invalid := workDir + ".corrupt-unknown"
	if err := os.Mkdir(invalid, 0700); err != nil {
		t.Fatal(err)
	}
	symlink := workDir + ".corrupt-0"
	if err := os.Symlink(otherVM, symlink); err != nil {
		t.Fatal(err)
	}

	preserved, err := preserveCorruptStates(workDir, 12)
	if err != nil || preserved == "" {
		t.Fatalf("failed to preserve corrupt state: path=%q, err=%v", preserved, err)
	}
	if data, err := os.ReadFile(filepath.Join(preserved, "failed-state")); err != nil || string(data) != "keep me" {
		t.Fatalf("new corrupt state was not preserved: %q, %v", data, err)
	}
	for stamp := 1; stamp <= 11; stamp++ {
		_, err := os.Stat(fmt.Sprintf("%s.corrupt-%d", workDir, stamp))
		if stamp <= 2 && !os.IsNotExist(err) {
			t.Errorf("old state %d remains: %v", stamp, err)
		}
		if stamp > 2 && err != nil {
			t.Errorf("retained state %d is missing: %v", stamp, err)
		}
	}
	for _, path := range []string{otherVM, invalid, symlink} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("unrelated path %s was removed: %v", path, err)
		}
	}
	if got, err := preserveCorruptStates(filepath.Join(t.TempDir(), "missing", "state"), 42); got != "" || err != nil {
		t.Fatalf("preserveCorruptStates on missing directory = (%q, %v), want (empty, nil)", got, err)
	}
}

func TestPreserveCorruptStatesFailedRenameStartsFresh(t *testing.T) {
	workDir := filepath.Join(t.TempDir(), "tpm-state-vm")
	if err := os.Mkdir(workDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "corrupt"), []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	existing := workDir + ".corrupt-42"
	if err := os.Mkdir(existing, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(existing, "previous"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	path, err := preserveCorruptStates(workDir, 42)
	if err != nil || path != "" {
		t.Fatalf("failed preservation = (%q, %v), want (empty, nil)", path, err)
	}
	if _, err := os.Stat(workDir); !os.IsNotExist(err) {
		t.Fatalf("corrupt active state still exists: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(existing, "previous")); err != nil || string(data) != "keep" {
		t.Fatalf("earlier preserved state changed: %q, %v", data, err)
	}
	if err := os.Mkdir(workDir, 0700); err != nil {
		t.Fatalf("fresh state directory cannot be created: %v", err)
	}
}

func TestListenUnix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := listenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("created file mode %v, want a socket", info.Mode())
	}
	if got := info.Mode().Perm() & 0o077; got != 0 {
		t.Fatalf("socket was created with group/other permissions %03o", got)
	}

	// A failed Listen must restore the caller's umask too.
	previousMask := syscall.Umask(0o022)
	defer syscall.Umask(previousMask)
	_, err = listenUnix(filepath.Join(t.TempDir(), "missing", "control.sock"))
	if err == nil {
		t.Fatal("expected Listen to fail for a missing parent directory")
	}
	gotMask := syscall.Umask(0o022)
	if gotMask != 0o022 {
		t.Fatalf("umask after failed Listen = %03o, want 022", gotMask)
	}
}

func generateUUID() uuid.UUID {
	id, _ := uuid.NewV4()
	return id
}

func UnixSocketTransport(socketPath string) *http.Transport {
	return &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
}

func makeRequest(client *http.Client, endpoint, id string) (string, int, error) {
	url := fmt.Sprintf("http://unix/%s?id=%s", endpoint, id)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", -1, fmt.Errorf("error when creating request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", -1, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", -1, fmt.Errorf("error when reading response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return string(body), resp.StatusCode, fmt.Errorf("received status code %d \n", resp.StatusCode)
	}

	return string(body), resp.StatusCode, nil
}

func sendLaunchRequest(id uuid.UUID) (string, int, error) {
	return makeRequest(client, "launch", id.String())
}

func sendPurgeRequest(id uuid.UUID) (string, int, error) {
	return makeRequest(client, "purge", id.String())
}

func sendTerminateRequest(id uuid.UUID) (string, int, error) {
	return makeRequest(client, "terminate", id.String())
}

func simulateVMAttach(t *testing.T, id uuid.UUID) net.Conn {
	t.Helper()
	sockPath := fmt.Sprintf(swtpmCtrlSockPath, id.String())

	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		t.Fatalf("simulateVMAttach: resolve: %v", err)
	}
	ctrl, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatalf("simulateVMAttach: dial ctrl: %v", err)
	}

	// CMD_INIT = 0x02, flags = 0
	if _, err := ctrl.Write([]byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00}); err != nil {
		ctrl.Close()
		t.Fatalf("simulateVMAttach: CMD_INIT write: %v", err)
	}
	buf := make([]byte, 4)
	ctrl.Read(buf)

	// Create a socketpair: fds[0] goes to swtpm, fds[1] is our data channel.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		ctrl.Close()
		t.Fatalf("simulateVMAttach: socketpair: %v", err)
	}

	// CMD_SET_DATAFD = 0x10; pass fds[0] to swtpm via SCM_RIGHTS.
	oob := syscall.UnixRights(fds[0])
	if _, _, err := ctrl.WriteMsgUnix([]byte{0x00, 0x00, 0x00, 0x10}, oob, nil); err != nil {
		syscall.Close(fds[0])
		syscall.Close(fds[1])
		ctrl.Close()
		t.Fatalf("simulateVMAttach: CMD_SET_DATAFD: %v", err)
	}
	syscall.Close(fds[0]) // swtpm owns this end now
	ctrl.Read(buf)

	// Open our end of the data channel and send TPM2_Startup(SU_CLEAR).
	// tag=0x8001, size=12, cc=TPM2_CC_Startup=0x144, startupType=SU_CLEAR=0x0000
	dataFile := os.NewFile(uintptr(fds[1]), "tpm-data")
	dataConn, err := net.FileConn(dataFile)
	dataFile.Close()
	if err != nil {
		ctrl.Close()
		t.Fatalf("simulateVMAttach: FileConn: %v", err)
	}
	defer dataConn.Close()
	startup := []byte{0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00}
	if _, err := dataConn.Write(startup); err != nil {
		ctrl.Close()
		t.Fatalf("simulateVMAttach: TPM2_Startup write: %v", err)
	}
	dataConn.Read(make([]byte, 1024))

	time.Sleep(500 * time.Millisecond)
	return ctrl
}

func swtpmSupportsBackup() bool {
	out, err := exec.Command(swtpmPath, "socket", "--tpm2", "--print-capabilities").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "tpmstate-dir-backend-opt-backup")
}

func testLaunchAndPurge(t *testing.T, id uuid.UUID) {
	// test logic :
	// 1. send launch request
	// 2. check number of live instances, it should be 1
	// 3. send purge request
	// 4. check number of live instances, it should be 0
	b, _, err := sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	if liveInstances != 1 {
		t.Fatalf("expected liveInstances to be 1, got %d", liveInstances)
	}

	b, _, err = sendPurgeRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	if liveInstances != 0 {
		t.Fatalf("expected liveInstances to be 0, got %d", liveInstances)
	}
}

func testExhaustSwtpmInstances(t *testing.T) {
	ids := make([]uuid.UUID, 0)
	for i := 0; i < maxInstances; i++ {
		id := generateUUID()
		b, _, err := sendLaunchRequest(id)
		if err != nil {
			t.Fatalf("failed to send request: %v, body : %s", err, b)
		}
		defer func() { _ = cleanupFiles(id) }()
		ids = append(ids, id)
	}
	time.Sleep(5 * time.Second)

	// this should have no effect as we have reached max instances
	b, res, err := sendLaunchRequest(generateUUID())
	if res != http.StatusTooManyRequests {
		t.Fatalf("expected status code to be %d, got %d, err : %v, body: %s", http.StatusTooManyRequests, res, err, b)
	}

	if liveInstances != maxInstances {
		t.Errorf("expected liveInstances to be %d, got %d", maxInstances, liveInstances)
	}

	b, _, err = sendPurgeRequest(ids[0])
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	if liveInstances != maxInstances-1 {
		t.Errorf("expected liveInstances to be %d, got %d", maxInstances-1, liveInstances)
	}

	// clean up
	for i := 1; i < maxInstances; i++ {
		b, _, err := sendPurgeRequest(ids[i])
		if err != nil {
			t.Fatalf("failed to send request: %v, body : %s", err, b)
		}
		time.Sleep(1 * time.Second)
	}
}

func TestLaunchAndPurgeWithoutStateEncryption(t *testing.T) {
	id := generateUUID()
	defer func() { _ = cleanupFiles(id) }()
	isTPMAvailable = func() bool {
		return false
	}

	testLaunchAndPurge(t, id)
}

func TestLaunchAndPurgeWithStateEncryption(t *testing.T) {
	id := generateUUID()
	defer func() { _ = cleanupFiles(id) }()
	isTPMAvailable = func() bool {
		return true
	}
	getEncryptionKey = func() ([]byte, error) {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		return key, nil
	}

	testLaunchAndPurge(t, id)
}

func TestExhaustSwtpmInstancesWithoutStateEncryption(t *testing.T) {
	isTPMAvailable = func() bool {
		return false
	}

	testExhaustSwtpmInstances(t)
}

func TestExhaustSwtpmInstancesWithStateEncryption(t *testing.T) {
	isTPMAvailable = func() bool {
		return true
	}
	getEncryptionKey = func() ([]byte, error) {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		return key, nil
	}

	testExhaustSwtpmInstances(t)
}

func TestSwtpmStateChange(t *testing.T) {
	id := generateUUID()
	defer func() { _ = cleanupFiles(id) }()
	isTPMAvailable = func() bool {
		return true
	}
	getEncryptionKey = func() ([]byte, error) {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		return key, nil
	}

	// this mark the instance to be encrypted
	b, _, err := sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	b, _, err = sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// disable the TPM
	isTPMAvailable = func() bool {
		return false
	}

	// this should fail since this instance was marked as encrypted and now TPM is not available anymore
	b, _, err = sendLaunchRequest(id)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	t.Logf("expected error: %v, body: %s", err, b)

	if liveInstances > 1 {
		t.Fatalf("expected liveInstances to be 1, got %d", liveInstances)
	}

	b, _, err = sendPurgeRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
}

func TestSwtpmStateBackupWithStateEncryption(t *testing.T) {
	if !swtpmSupportsBackup() {
		t.Skip("swtpm does not support tpmstate-dir-backend-opt-backup")
	}
	oldPCR := sha256PCRAvailable
	sha256PCRAvailable = func() bool { return false }
	t.Cleanup(func() { sha256PCRAvailable = oldPCR })
	id := generateUUID()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	defer func() { _ = cleanupFiles(id) }()
	isTPMAvailable = func() bool {
		return true
	}
	getEncryptionKey = func() ([]byte, error) {
		return key, nil
	}

	b, _, err := sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// get the normal and backup state file path
	normalState := fmt.Sprintf(workDir, id.String()) + "/tpm2-00.permall"
	backupState := fmt.Sprintf(workDir, id.String()) + "/tpm2-00.permall.bak"

	// trigger state change to get both normal and backup state file
	vmConn := simulateVMAttach(t, id)
	vmConn.Close()

	b, _, err = sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// check for backup file to be present (swtpm writes backup on shutdown)
	if _, err := os.Stat(backupState); os.IsNotExist(err) {
		t.Fatalf("backup file %s does not exist", backupState)
	}

	// corrup the normal state file, by writing some data
	f1, err := os.OpenFile(normalState, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer f1.Close()
	_, err = f1.Write([]byte("corrupted data"))
	if err != nil {
		t.Fatalf("failed to write to file: %v", err)
	}

	// this should succeed since we have a backup state file
	b, _, err = sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// trigger again
	vmConn = simulateVMAttach(t, id)
	vmConn.Close()

	b, _, err = sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// remove the normal state file
	if err := os.Remove(normalState); err != nil {
		t.Fatalf("failed to remove file: %v", err)
	}

	// this should succeed since we have backup file
	b, _, err = sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// trigger again
	vmConn = simulateVMAttach(t, id)
	vmConn.Close()

	b, _, err = sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// corrup both normal and backup state file, by writing some data
	f2, err := os.OpenFile(normalState, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer f2.Close()
	_, err = f2.Write([]byte("corrupted data"))
	if err != nil {
		t.Fatalf("failed to write to file: %v", err)
	}
	f3, err := os.OpenFile(backupState, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer f3.Close()
	_, err = f3.Write([]byte("corrupted data"))
	if err != nil {
		t.Fatalf("failed to write to file: %v", err)
	}

	// The failed encrypted state is set aside and a fresh instance starts.
	b, _, err = sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	corruptDirs, err := filepath.Glob(fmt.Sprintf(workDir, id.String()) + ".corrupt-*")
	if err != nil || len(corruptDirs) != 1 {
		t.Fatalf("expected one preserved corrupt state, got %v: %v", corruptDirs, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(corruptDirs[0]) })
	preserved, err := os.ReadFile(filepath.Join(corruptDirs[0], "tpm2-00.permall"))
	if err != nil || string(preserved) != "corrupted data" {
		t.Fatalf("corrupt encrypted state was not preserved: %q, err %v", preserved, err)
	}

	b, _, err = sendPurgeRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
}

func TestSwtpmStateBackup(t *testing.T) {
	if !swtpmSupportsBackup() {
		t.Skip("swtpm does not support tpmstate-dir-backend-opt-backup")
	}
	id := generateUUID()
	defer func() { _ = cleanupFiles(id) }()
	isTPMAvailable = func() bool {
		return false
	}

	b, _, err := sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// get the normal and backup state file path
	normalState := fmt.Sprintf(workDir, id.String()) + "/tpm2-00.permall"
	backupState := fmt.Sprintf(workDir, id.String()) + "/tpm2-00.permall.bak"

	// trigger state change to get both normal and backup state file
	vmConn := simulateVMAttach(t, id)
	vmConn.Close()

	b, _, err = sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// check for backup file to be present (swtpm writes backup on shutdown)
	if _, err := os.Stat(backupState); os.IsNotExist(err) {
		t.Fatalf("backup file %s does not exist", backupState)
	}

	// corrup the normal state file, by writing some data
	f1, err := os.OpenFile(normalState, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer f1.Close()
	_, err = f1.Write([]byte("corrupted data"))
	if err != nil {
		t.Fatalf("failed to write to file: %v", err)
	}

	// this should succeed since we have backup file
	b, _, err = sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// trigger again
	vmConn = simulateVMAttach(t, id)
	vmConn.Close()

	b, _, err = sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// remove the normal state file
	if err := os.Remove(normalState); err != nil {
		t.Fatalf("failed to remove file: %v", err)
	}

	// this should succeed since we have backup file
	b, _, err = sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// trigger again
	vmConn = simulateVMAttach(t, id)
	vmConn.Close()

	b, _, err = sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// corrup both normal and backup state file, by writing some data
	f2, err := os.OpenFile(normalState, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer f2.Close()
	_, err = f2.Write([]byte("corrupted data"))
	if err != nil {
		t.Fatalf("failed to write to file: %v", err)
	}
	f3, err := os.OpenFile(backupState, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer f3.Close()
	_, err = f3.Write([]byte("corrupted data"))
	if err != nil {
		t.Fatalf("failed to write to file: %v", err)
	}

	// this should succeed since we reset the SWTPM state if both files are corrupted
	b, _, err = sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	b, _, err = sendPurgeRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
}

func TestDeleteRequest(t *testing.T) {
	id := generateUUID()
	defer func() { _ = cleanupFiles(id) }()

	// this doesn't matter
	isTPMAvailable = func() bool {
		return false
	}

	b, _, err := sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}

	b, _, err = sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	if liveInstances != 0 {
		t.Fatalf("expected liveInstances to be 0, got %d", liveInstances)
	}
}

func TestSwtpmAbruptTerminationRequest(t *testing.T) {
	// this test verify that if swtpm is terminated without vTPM notice,
	// no stale id is left in the vtpm internal bookkeeping and vtpm
	// can launch new instance with the same id.
	// test logic :
	// 1. send launch request
	// 2. read swtpm pid file and terminate it
	// 3. send launch request again, this should not fail
	id := generateUUID()
	defer func() { _ = cleanupFiles(id) }()

	// this doesn't matter
	isTPMAvailable = func() bool {
		return false
	}

	b, _, err := sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}

	pid, err := readPidFile(fmt.Sprintf(swtpmPidPath, id))
	if err != nil {
		t.Fatalf("failed to read pid file: %v", err)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatalf("failed to kill process: %v", err)

	}

	// this should not fail
	b, _, err = sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}

	b, _, err = sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	if liveInstances != 0 {
		t.Fatalf("expected liveInstances to be 0, got %d", liveInstances)
	}
}

func TestLaunchWithRealTPMEncryption(t *testing.T) {
	// This test exercises UnsealDiskKeyWithRecovery from vtpm standpoint, maybe not
	// necessarily becuse it is being tested in etpm tests, but better safe than sorry!
	//
	// We must end up here by tests/tpm/prep-and-test.sh, this test
	// seals a key into the TPM NV storage, then launches an swtpm instance with
	// encryption enabled. If getEncryptionKey (UnsealDiskKeyWithRecovery) fails,
	// the launch request will fail, catching any regressions in key retrieval.
	if !etpm.SimTpmAvailable() {
		t.Skip("swtpm simulator not available, skipping")
	}

	if err := etpm.SimTpmWaitForTpmReadyState(); err != nil {
		t.Fatalf("swtpm not ready: %v", err)
	}

	id := generateUUID()
	defer func() { _ = cleanupFiles(id) }()

	origTpmPath := etpm.TpmDevicePath
	etpm.TpmDevicePath = etpm.SimTpmPath
	isTPMAvailable = func() bool { return true }
	binKeyPath := fmt.Sprintf(stateEncryptionKey, id.String())
	isEncryptedPath := fmt.Sprintf(stateIsEncryptedPath, id.String())
	defer func() { etpm.TpmDevicePath = origTpmPath }()

	// Seal a key into TPM NV storage so UnsealDiskKeyWithRecovery can retrieve it
	sealedKey := []byte("test-vtpm-encryption-key-32bytes")
	if err := etpm.SealDiskKey(log, sealedKey, etpm.DefaultDiskKeySealingPCRs); err != nil {
		t.Fatalf("failed to seal key into TPM: %v", err)
	}

	// Launch should succeed: runSwtpm calls getEncryptionKey which calls
	// UnsealDiskKeyWithRecovery to retrieve the sealed key from the TPM.
	t.Log("Step 1: launching swtpm with TPM encryption key")
	b, code, err := sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("launch with TPM encryption failed (status %d): %v, body: %s", code, err, b)
	}
	time.Sleep(1 * time.Second)

	if liveInstances != 1 {
		t.Fatalf("expected liveInstances to be 1, got %d", liveInstances)
	}

	// Verify the encryption key file was consumed by swtpm (remove=true flag)
	if _, err := os.Stat(binKeyPath); !os.IsNotExist(err) {
		t.Fatalf("encryption key file %s should have been removed by swtpm after reading", binKeyPath)
	}
	t.Log("  - encryption key file was consumed by swtpm (remove=true)")

	// Verify the encrypted marker file exists with the correct content
	markerContent, err := os.ReadFile(isEncryptedPath)
	if err != nil {
		t.Fatalf("failed to read encrypted marker file: %v", err)
	}
	if string(markerContent) != "Y" {
		t.Fatalf("encrypted marker file should contain 'Y', got %q", string(markerContent))
	}
	t.Log("  - encrypted marker file exists with content 'Y'")

	// Terminate (not purge!) to keep the encrypted marker file and state intact
	b, _, err = sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to terminate: %v, body: %s", err, b)
	}
	time.Sleep(1 * time.Second)

	// Disable the TPM and try to launch again. Since the state is marked as
	// encrypted, vtpm must refuse to launch without a TPM to unseal the key.
	isTPMAvailable = func() bool { return false }

	b, code, err = sendLaunchRequest(id)
	if err == nil {
		t.Fatalf("launch without TPM should have failed for encrypted state, but succeeded")
	}
	t.Logf("  - launch without TPM correctly rejected (status %d): %s", code, b)

	isTPMAvailable = func() bool { return true }
	b, _, err = sendPurgeRequest(id)
	if err != nil {
		t.Fatalf("failed to purge: %v, body: %s", err, b)
	}
	time.Sleep(1 * time.Second)

	if liveInstances != 0 {
		t.Fatalf("expected liveInstances to be 0, got %d", liveInstances)
	}
}

func TestSwtpmMultipleLaucnhRequest(t *testing.T) {
	// this test verify that if swtpm is launched multiple times with the same id,
	// only one instance is created and other requests are ignored.
	// test logic :
	// 1. send launch request multiple times, it all should succeed
	// 2. clean up
	id := generateUUID()
	defer func() { _ = cleanupFiles(id) }()

	// this doesn't matter
	isTPMAvailable = func() bool {
		return false
	}

	for i := 0; i < 5; i++ {
		b, _, err := sendLaunchRequest(id)
		if err != nil {
			t.Fatalf("failed to send request: %v, body : %s", err, b)
		}
	}

	pid, err := readPidFile(fmt.Sprintf(swtpmPidPath, id))
	if err != nil {
		t.Fatalf("failed to read pid file: %v", err)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatalf("failed to kill process: %v", err)

	}

	b, _, err := sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

	if liveInstances != 0 {
		t.Fatalf("expected liveInstances to be 0, got %d", liveInstances)
	}
}
