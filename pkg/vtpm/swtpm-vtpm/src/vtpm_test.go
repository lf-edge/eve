// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/sirupsen/logrus"
)

const baseDir = "/tmp/swtpm/test"

func TestMain(m *testing.M) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "vtpm", os.Getpid())
	os.MkdirAll(baseDir, 0755)

	stateEncryptionKey = baseDir + "/%s.binkey"
	swtpmIsEncryptedPath = baseDir + "/%s.encrypted"
	swtpmStatePath = baseDir + "/tpm-state-%s"
	swtpmCtrlSockPath = baseDir + "/%s.ctrl.sock"
	swtpmPidPath = baseDir + "/%s.pid"
	vtpmdCtrlSockPath = baseDir + "/vtpmd.ctrl.sock"

	go serviceLoop()
	defer func() {
		_ = os.Remove(vtpmdCtrlSockPath)
	}()

	time.Sleep(1 * time.Second)
	m.Run()
}

func sendLaunchRequest(id string) error {
	conn, err := net.Dial("unix", vtpmdCtrlSockPath)
	if err != nil {
		return fmt.Errorf("failed to connect to vTPM control socket: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(fmt.Sprintf("%s;%s\n", launchReq, id)))
	if err != nil {
		return fmt.Errorf("failed to write to vTPM control socket: %w", err)
	}

	return nil
}

func sendPurgeRequest(id string) error {
	conn, err := net.Dial("unix", vtpmdCtrlSockPath)
	if err != nil {
		return fmt.Errorf("failed to connect to vTPM control socket: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(fmt.Sprintf("%s;%s\n", purgeReq, id)))
	if err != nil {
		return fmt.Errorf("failed to write to vTPM control socket: %w", err)
	}

	time.Sleep(1 * time.Second)
	return nil
}

func sendTerminateRequest(id string) error {
	conn, err := net.Dial("unix", vtpmdCtrlSockPath)
	if err != nil {
		return fmt.Errorf("failed to connect to vTPM control socket: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(fmt.Sprintf("%s;%s\n", terminateReq, id)))
	if err != nil {
		return fmt.Errorf("failed to write to vTPM control socket: %w", err)
	}

	time.Sleep(1 * time.Second)
	return nil
}

func testLaunchAndPurge(t *testing.T, id string) {
	// test logic :
	// 1. send launch request
	// 2. check number of live instances, it should be 1
	// 3. send purge request
	// 4. check number of live instances, it should be 0
	err := sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to handle request: %v", err)
	}
	time.Sleep(1 * time.Second)

	if liveInstances != 1 {
		t.Fatalf("expected liveInstances to be 1, got %d", liveInstances)
	}

	err = sendPurgeRequest(id)
	if err != nil {
		t.Fatalf("failed to handle request: %v", err)
	}

	if liveInstances != 0 {
		t.Fatalf("expected liveInstances to be 0, got %d", liveInstances)
	}
}

func testExhaustSwtpmInstances(t *testing.T, id string) {
	for i := 0; i < maxInstances; i++ {
		err := sendLaunchRequest(fmt.Sprintf("%s-%d", id, i))
		if err != nil {
			t.Errorf("failed to send request: %v", err)
		}
	}
	time.Sleep(5 * time.Second)

	// this should have no effect as we have reached max instances
	err := sendLaunchRequest(id)
	if err != nil {
		t.Errorf("failed to send request: %v", err)
	}

	if liveInstances != maxInstances {
		t.Errorf("expected liveInstances to be %d, got %d", maxInstances, liveInstances)
	}

	err = sendPurgeRequest(fmt.Sprintf("%s-0", id))
	if err != nil {
		t.Errorf("failed to handle request: %v", err)
	}

	if liveInstances != maxInstances-1 {
		t.Errorf("expected liveInstances to be %d, got %d", maxInstances-1, liveInstances)
	}

	// clean up
	for i := 0; i < maxInstances; i++ {
		err := sendPurgeRequest(fmt.Sprintf("%s-%d", id, i))
		if err != nil {
			t.Errorf("failed to handle request: %v", err)
		}
	}
}

func TestLaunchAndPurgeWithoutStateEncryption(t *testing.T) {
	id := "test"
	defer cleanupFiles(id)
	isTPMAvailable = func() bool {
		return false
	}

	testLaunchAndPurge(t, id)
}

func TestLaunchAndPurgeWithStateEncryption(t *testing.T) {
	id := "test"
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
	id := "test"
	defer cleanupFiles(id)
	isTPMAvailable = func() bool {
		return false
	}

	testExhaustSwtpmInstances(t, id)
}

func TestExhaustSwtpmInstancesWithStateEncryption(t *testing.T) {
	id := "test"
	defer cleanupFiles(id)
	isTPMAvailable = func() bool {
		return true
	}
	getEncryptionKey = func() ([]byte, error) {
		key := make([]byte, 32)
		_, _ = rand.Read(key)
		return key, nil
	}

	testExhaustSwtpmInstances(t, id)
}

func TestSwtpmStateChange(t *testing.T) {
	id := "test"
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
	err := sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to handle request: %v", err)
	}
	time.Sleep(1 * time.Second)

	// disable the TPM
	isTPMAvailable = func() bool {
		return false
	}

	// this should fail since this id was marked as encrypted
	err = sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to handle request: %v", err)
	}
	if liveInstances > 1 {
		t.Fatalf("expected liveInstances to be 1, got %d", liveInstances)
	}

	err = sendPurgeRequest(id)
	if err != nil {
		t.Fatalf("failed to handle request: %v", err)
	}
}

func TestDeleteRequest(t *testing.T) {
	id := "test"
	defer cleanupFiles(id)

	// this doesn't matter
	isTPMAvailable = func() bool {
		return false
	}

	err := sendLaunchRequest(id)
	if err != nil {
		t.Fatalf("failed to handle request: %v", err)
	}

	err = sendTerminateRequest(id)
	if err != nil {
		t.Fatalf("failed to handle request: %v", err)
	}

	if liveInstances != 0 {
		t.Fatalf("expected liveInstances to be 0, got %d", liveInstances)
	}
}
