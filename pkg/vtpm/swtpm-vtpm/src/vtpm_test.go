// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const baseDir = "/tmp/swtpm/test"

var client = &http.Client{}

func TestMain(m *testing.M) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "vtpm", os.Getpid())
	maxPidWaitTime = 15
	maxInstances = 3
	os.MkdirAll(baseDir, 0755)

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
	m.Run()
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
		defer cleanupFiles(id)
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
	defer cleanupFiles(id)
	isTPMAvailable = func() bool {
		return false
	}

	testLaunchAndPurge(t, id)
}

func TestLaunchAndPurgeWithStateEncryption(t *testing.T) {
	id := generateUUID()
	defer cleanupFiles(id)
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
	defer cleanupFiles(id)
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
	id := generateUUID()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	defer cleanupFiles(id)
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

func TestSwtpmStateBackup(t *testing.T) {
	if !swtpmSupportsBackup() {
		t.Skip("swtpm does not support tpmstate-dir-backend-opt-backup")
	}
	id := generateUUID()
	defer cleanupFiles(id)
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
	defer cleanupFiles(id)

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
	defer cleanupFiles(id)

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
	defer cleanupFiles(id)

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
	defer cleanupFiles(id)

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
