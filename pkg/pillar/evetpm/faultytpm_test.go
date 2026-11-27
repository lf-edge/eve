// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	tpmHeaderSize = 10
	// tpmRCNVUnavailable is TPM_RC_NV_UNAVAILABLE (TPM_RC_WARN + 0x023) as it
	// appears on the wire. TPM_RC_RETRY would be the obvious choice, but go-tpm
	// retries that one itself and never hands it to the caller.
	tpmRCNVUnavailable = 0x923
	// tpmRCSymmetricParam1 is TPM_RC_SYMMETRIC on parameter 1, a format-1
	// error: a definite answer that a retry would repeat.
	tpmRCSymmetricParam1 = 0x1d6
	// tpmRCFailure is TPM_RC_FAILURE, a format-0 error: the TPM is in failure
	// mode, which says nothing about the feature probed.
	tpmRCFailure = 0x101
	// cmdTestParms is TPM_CC_TestParms, which the legacy go-tpm API lacks.
	cmdTestParms tpmutil.Command = 0x18a
)

// faultyTPM relays TPM commands to the simulator, except that it answers the
// first faults commands with code cmd itself, with response code rc. With
// NV_ReadPublic and TPM_RC_NV_UNAVAILABLE that is a TPM briefly unable to say
// whether a disk key exists while every other command, sealing included,
// still works: the state in which a TPM error taken for an absent key
// replaces the vault key.
type faultyTPM struct {
	path     string
	cmd      tpmutil.Command
	rc       uint32
	mu       sync.Mutex
	faults   int
	injected int
}

func startFaultyTPM(t *testing.T, cmd tpmutil.Command, rc uint32, faults int) *faultyTPM {
	t.Helper()
	dir, err := os.MkdirTemp("", "faultytpm")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &faultyTPM{path: filepath.Join(dir, "tpm.sock"), cmd: cmd, rc: rc, faults: faults}
	ln, err := net.Listen("unix", f.path)
	if err != nil {
		t.Fatalf("listen on %s failed: %v", f.path, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.relay(conn)
		}
	}()
	return f
}

// Injected returns how many faults were answered so far.
func (f *faultyTPM) Injected() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.injected
}

func (f *faultyTPM) takeFault() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.injected >= f.faults {
		return false
	}
	f.injected++
	return true
}

func (f *faultyTPM) relay(client net.Conn) {
	defer client.Close()
	for {
		cmd, err := readTPMFrame(client)
		if err != nil {
			return
		}
		var rsp []byte
		if tpmutil.Command(binary.BigEndian.Uint32(cmd[6:10])) == f.cmd && f.takeFault() {
			rsp = make([]byte, tpmHeaderSize)
			binary.BigEndian.PutUint16(rsp[0:2], uint16(tpm2.TagNoSessions))
			binary.BigEndian.PutUint32(rsp[2:6], tpmHeaderSize)
			binary.BigEndian.PutUint32(rsp[6:10], f.rc)
		} else if rsp, err = simTPMCommand(cmd); err != nil {
			return
		}
		// The go-tpm emulator transport takes a response in a single Read.
		if _, err := client.Write(rsp); err != nil {
			return
		}
	}
}

// simTPMCommand sends one command to the simulator and returns its response,
// on a connection of its own as the simulator expects.
func simTPMCommand(cmd []byte) ([]byte, error) {
	conn, err := net.Dial("unix", SimTpmPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write(cmd); err != nil {
		return nil, err
	}
	return readTPMFrame(conn)
}

// readTPMFrame reads one command or response: a header whose bytes 2-5 give
// the size of the whole frame, then the rest of it.
func readTPMFrame(r io.Reader) ([]byte, error) {
	hdr := make([]byte, tpmHeaderSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(hdr[2:6])
	if size < tpmHeaderSize || size > 1<<16 {
		return nil, fmt.Errorf("bad TPM frame size %d", size)
	}
	frame := make([]byte, size)
	copy(frame, hdr)
	if _, err := io.ReadFull(r, frame[tpmHeaderSize:]); err != nil {
		return nil, err
	}
	return frame, nil
}

// sealTestDiskKey seals a random disk key into the simulator and returns it.
// It also marks the SHA-256 PCR bank as supported: the real check first asks
// IsTpmEnabled, which needs a device certificate a test host does not have,
// and without it FetchSealedVaultKey takes the legacy key path instead.
func sealTestDiskKey(t *testing.T) []byte {
	t.Helper()
	savedBankStatus := pcrBank256Status
	pcrBank256Status = PCRBank256StatusSupported
	t.Cleanup(func() { pcrBank256Status = savedBankStatus })
	extendFirmwareAnchorPCRs(t)
	key, err := GetRandom(vaultKeyLength)
	if err != nil {
		t.Fatalf("GetRandom failed: %v", err)
	}
	if err := SealDiskKey(logger, key, DefaultDiskKeySealingPCRs); err != nil {
		t.Fatalf("SealDiskKey failed: %v", err)
	}
	return key
}

func useTPMPath(t *testing.T, path string) {
	t.Helper()
	saved := TpmDevicePath
	TpmDevicePath = path
	t.Cleanup(func() { TpmDevicePath = saved })
}

func TestFetchSealedVaultKeyRetriesTPMError(t *testing.T) {
	if !SimTpmAvailable() {
		t.Skip("TPM is not available, skipping the test.")
	}
	want := sealTestDiskKey(t)

	faults := tpmProbeAttempts - 1
	tpm := startFaultyTPM(t, tpm2.CmdReadPublicNV, tpmRCNVUnavailable, faults)
	useTPMPath(t, tpm.path)
	got, err := FetchSealedVaultKey(logger)
	if err != nil {
		t.Fatalf("FetchSealedVaultKey failed: %v", err)
	}
	if n := tpm.Injected(); n != faults {
		t.Fatalf("injected %d NV_ReadPublic faults, want %d", n, faults)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("FetchSealedVaultKey returned a different key than the one sealed: a TPM error was taken for an absent key")
	}
}

func TestFetchSealedVaultKeyFailsOnPersistentTPMError(t *testing.T) {
	if !SimTpmAvailable() {
		t.Skip("TPM is not available, skipping the test.")
	}
	want := sealTestDiskKey(t)

	tpm := startFaultyTPM(t, tpm2.CmdReadPublicNV, tpmRCNVUnavailable, math.MaxInt)
	useTPMPath(t, tpm.path)
	if _, err := FetchSealedVaultKey(logger); err == nil {
		t.Fatalf("FetchSealedVaultKey succeeded although the TPM never answered NV_ReadPublic")
	}
	if tpm.Injected() == 0 {
		t.Fatalf("no NV_ReadPublic fault was injected")
	}

	TpmDevicePath = SimTpmPath
	got, err := UnsealDiskKey(logger, DefaultDiskKeySealingPCRs)
	if err != nil {
		t.Fatalf("UnsealDiskKey failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the sealed disk key was replaced")
	}
}

// A TPM that holds a sealed disk key has a SHA-256 bank, so a "no bank" answer
// must not lead FetchSealedVaultKey to the legacy key.
func TestFetchSealedVaultKeyRefusesLegacyKeyOnSealedTPM(t *testing.T) {
	if !SimTpmAvailable() {
		t.Skip("TPM is not available, skipping the test.")
	}
	want := sealTestDiskKey(t)
	pcrBank256Status = PCRBank256StatusNotSupported

	if key, err := FetchSealedVaultKey(logger); err == nil {
		t.Fatalf("FetchSealedVaultKey returned a key (%d bytes) on a TPM that holds a sealed key but reports no SHA-256 bank", len(key))
	}

	got, err := UnsealDiskKey(logger, DefaultDiskKeySealingPCRs)
	if err != nil {
		t.Fatalf("UnsealDiskKey failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the sealed disk key was replaced")
	}
}

// writeTestLegacyDiskKey writes a random legacy disk key into the simulator
// and returns it.
func writeTestLegacyDiskKey(t *testing.T) []byte {
	t.Helper()
	key, err := GetRandom(vaultKeyLength)
	if err != nil {
		t.Fatalf("GetRandom failed: %v", err)
	}
	if err := writeDiskKey(key); err != nil {
		t.Fatalf("writeDiskKey failed: %v", err)
	}
	return key
}

func TestFetchVaultKeyRetriesTPMError(t *testing.T) {
	if !SimTpmAvailable() {
		t.Skip("TPM is not available, skipping the test.")
	}
	want := writeTestLegacyDiskKey(t)

	faults := tpmProbeAttempts - 1
	tpm := startFaultyTPM(t, tpm2.CmdReadPublicNV, tpmRCNVUnavailable, faults)
	useTPMPath(t, tpm.path)
	got, err := FetchVaultKey(logger)
	if err != nil {
		t.Fatalf("FetchVaultKey failed: %v", err)
	}
	if n := tpm.Injected(); n != faults {
		t.Fatalf("injected %d NV_ReadPublic faults, want %d", n, faults)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("FetchVaultKey returned a different key than the one written: a TPM error was taken for an absent key")
	}
}

func TestFetchVaultKeyFailsOnPersistentTPMError(t *testing.T) {
	if !SimTpmAvailable() {
		t.Skip("TPM is not available, skipping the test.")
	}
	want := writeTestLegacyDiskKey(t)

	tpm := startFaultyTPM(t, tpm2.CmdReadPublicNV, tpmRCNVUnavailable, math.MaxInt)
	useTPMPath(t, tpm.path)
	if _, err := FetchVaultKey(logger); err == nil {
		t.Fatalf("FetchVaultKey succeeded although the TPM never answered NV_ReadPublic")
	}

	TpmDevicePath = SimTpmPath
	got, err := readDiskKey()
	if err != nil {
		t.Fatalf("readDiskKey failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the legacy disk key was replaced")
	}
}

func TestProbePCRBankSHA256(t *testing.T) {
	if !SimTpmAvailable() {
		t.Skip("TPM is not available, skipping the test.")
	}
	tests := []struct {
		name    string
		rc      uint32
		faults  int
		want    bool
		wantErr bool
	}{
		{"transient warning", tpmRCNVUnavailable, tpmProbeAttempts - 1, true, false},
		{"persistent warning", tpmRCNVUnavailable, math.MaxInt, false, true},
		{"TPM error", tpmRCSymmetricParam1, 1, false, false},
		{"transient failure mode", tpmRCFailure, tpmProbeAttempts - 1, true, false},
		{"persistent failure mode", tpmRCFailure, math.MaxInt, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpm := startFaultyTPM(t, tpm2.CmdPCRRead, tt.rc, tt.faults)
			useTPMPath(t, tpm.path)
			got, err := retryTPMProbe(logger, "checking for the SHA-256 PCR bank", probePCRBankSHA256)
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Fatalf("got %t, %v; want %t, error %t", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestTPMSupportsAES128CFB(t *testing.T) {
	if !SimTpmAvailable() {
		t.Skip("TPM is not available, skipping the test.")
	}
	tests := []struct {
		name    string
		rc      uint32
		faults  int
		want    bool
		wantErr bool
	}{
		{"transient warning", tpmRCNVUnavailable, tpmProbeAttempts - 1, true, false},
		{"persistent warning", tpmRCNVUnavailable, math.MaxInt, false, true},
		{"TPM error", tpmRCSymmetricParam1, 1, false, false},
		{"transient failure mode", tpmRCFailure, tpmProbeAttempts - 1, true, false},
		{"persistent failure mode", tpmRCFailure, math.MaxInt, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpm := startFaultyTPM(t, cmdTestParms, tt.rc, tt.faults)
			useTPMPath(t, tpm.path)
			got, err := tpmSupportsAES128CFB(logger)
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Fatalf("got %t, %v; want %t, error %t", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestSealDiskKeyFailsWhenAESProbeFails(t *testing.T) {
	if !SimTpmAvailable() {
		t.Skip("TPM is not available, skipping the test.")
	}
	want := sealTestDiskKey(t)

	tpm := startFaultyTPM(t, cmdTestParms, tpmRCNVUnavailable, math.MaxInt)
	useTPMPath(t, tpm.path)
	key, err := GetRandom(vaultKeyLength)
	if err != nil {
		t.Fatalf("GetRandom failed: %v", err)
	}
	if err := SealDiskKey(logger, key, DefaultDiskKeySealingPCRs); err == nil {
		t.Fatalf("SealDiskKey succeeded although the TPM never answered TestParms")
	}

	TpmDevicePath = SimTpmPath
	got, err := UnsealDiskKey(logger, DefaultDiskKeySealingPCRs)
	if err != nil {
		t.Fatalf("UnsealDiskKey failed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the sealed disk key was replaced")
	}
}
