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
	"path"
	"syscall"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const baseDir = "/tmp/swtpm/test"

var client = &http.Client{}

func TestMain(m *testing.M) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "vtpm", os.Getpid())
	os.MkdirAll(baseDir, 0755)

	stateEncryptionKey = baseDir + "/%s.binkey"
	swtpmIsEncryptedPath = baseDir + "/%s.encrypted"
	swtpmStatePath = baseDir + "/tpm-state-%s"
	swtpmCtrlSockPath = baseDir + "/%s.ctrl.sock"
	swtpmPidPath = baseDir + "/%s.pid"
	vtpmdCtrlSockPath = baseDir + "/vtpmd.ctrl.sock"

	client = &http.Client{
		Transport: UnixSocketTransport(vtpmdCtrlSockPath),
		Timeout:   5 * time.Second,
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
	for i := 0; i < maxInstances; i++ {
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

func TestSwtpmStateBakcupWithStateEncryption(t *testing.T) {
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
	normalState := path.Join(fmt.Sprintf(swtpmStatePath, id.String(), "tpm2-00.permall"))
	backupState := path.Join(fmt.Sprintf(swtpmStatePath, id.String(), "tpm2-00.permall.bak"))

	// check for backup file to be present
	if _, err := os.Stat(backupState); os.IsNotExist(err) {
		t.Fatalf("backup file %s does not exist", backupState)
	}

	b, _, err = sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

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

func TestSwtpmStateBakcup(t *testing.T) {
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
	normalState := path.Join(fmt.Sprintf(swtpmStatePath, id.String(), "tpm2-00.permall"))
	backupState := path.Join(fmt.Sprintf(swtpmStatePath, id.String(), "tpm2-00.permall.bak"))

	// check for backup file to be present
	if _, err := os.Stat(backupState); os.IsNotExist(err) {
		t.Fatalf("backup file %s does not exist", backupState)
	}

	b, _, err = sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to send request: %v, body : %s", err, b)
	}
	time.Sleep(1 * time.Second)

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
