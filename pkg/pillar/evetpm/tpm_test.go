// Copyright (c) 2020-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// unit-tests for evetpm package
package evetpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/pkg/pillar/base"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/sirupsen/logrus"
)

var log = base.NewSourceLogObject(logrus.StandardLogger(), "evetpm", os.Getpid())

func TestMain(m *testing.M) {
	log.Tracef("Setup test environment")

	// setup variables
	TpmDevicePath = SimTpmPath
	measurementLogFile = "/tmp/eve-tpm/binary_bios_measurement"
	measurefsTpmEventLog = "/tmp/eve-tpm/measurefs_tpm_event_log"
	savedSealingPcrsFile = "/tmp/eve-tpm/sealingpcrs"
	measurementLogSealSuccess = "/tmp/eve-tpm/tpm_measurement_seal_success"
	measurementLogUnsealFail = "/tmp/eve-tpm/tpm_measurement_unseal_fail"

	if !SimTpmAvailable() {
		log.Warnf("TPM is not available, skipping the test.")
		os.Exit(0)
	}

	// for some reason TPM might return RCRetry for the first
	// few operations, so we need to wait for it to become ready.
	if err := SimTpmWaitForTpmReadyState(); err != nil {
		log.Fatalf("Failed to wait for TPM ready state: %v", err)
	}

	m.Run()
}

func TestDriveSessionKey(t *testing.T) {
	_, err := os.Stat(TpmDevicePath)
	if err != nil {
		t.Skip("TPM is not available, skipping the test.")
	}

	ecdhPublicKeyFile := "/tmp/eve-tpm/ec_key_leading_zero.cert"
	pub, err := GetPublicKeyFromCert(ecdhPublicKeyFile)
	if err != nil {
		t.Fatalf("GetPublicKeyFromCert failed with err: %v", err)
	}

	eccPublicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Expected ecdsa.PublicKey, got %T", pub)
	}

	fmt.Printf("X : %064x\nY : %064x\n", eccPublicKey.X.Bytes(), eccPublicKey.Y.Bytes())

	key, err := deriveSessionKey(eccPublicKey.X, eccPublicKey.Y, eccPublicKey)
	if err != nil {
		t.Fatalf("deriveSessionKey failed with err: %v", err)
	}

	fmt.Printf("Derived session key: %x\n", key)
	if len(key) != 32 {
		t.Fatalf("Expected session key length to be 32 bytes, got %d bytes", len(key))
	}
}

func TestSealUnseal(t *testing.T) {
	_, err := os.Stat(TpmDevicePath)
	if err != nil {
		t.Skip("TPM is not available, skipping the test.")
	}

	dataToSeal := []byte("secret")
	if err := SealDiskKey(log, dataToSeal, DiskKeySealingPCRs); err != nil {
		t.Fatalf("Seal operation failed with err: %v", err)
	}

	unsealedData, err := UnsealDiskKey(DiskKeySealingPCRs)
	if err != nil {
		t.Fatalf("Unseal operation failed with err: %v", err)
	}
	if !reflect.DeepEqual(dataToSeal, unsealedData) {
		t.Fatalf("Seal/Unseal operation failed, want %v, but got %v", dataToSeal, unsealedData)
	}
}

func TestSealUnsealMismatchReport(t *testing.T) {
	_, err := os.Stat(TpmDevicePath)
	if err != nil {
		t.Skip("TPM is not available, skipping the test.")
	}

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		t.Fatalf("OpenTPM failed with err: %v", err)
	}
	defer rw.Close()

	dataToSeal := []byte("secret")
	if err := SealDiskKey(log, dataToSeal, DiskKeySealingPCRs); err != nil {
		t.Fatalf("Seal operation failed with err: %v", err)
	}

	pcrIndexes := [3]int{1, 7, 8}
	pcrValue := bytes.Repeat([]byte{0xF}, sha256.Size)
	for _, pcr := range pcrIndexes {
		if err = tpm2.PCRExtend(rw, tpmutil.Handle(pcr), tpm2.AlgSHA256, pcrValue, ""); err != nil {
			t.Fatalf("Failed to extend PCR %d: %s", pcr, err)
		}
	}

	_, err = UnsealDiskKey(DiskKeySealingPCRs)
	if err == nil {
		t.Fatalf("Expected error from UnsealDiskKey, got nil")
	}

	if !strings.Contains(err.Error(), "[1 7 8]") {
		t.Fatalf("UnsealDiskKey expected to report mismatching PCR indexes, got : %v", err)
	}
}

func TestSealUnsealTpmEventLogCollect(t *testing.T) {
	_, err := os.Stat(TpmDevicePath)
	if err != nil {
		t.Skip("TPM is not available, skipping the test.")
	}

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		t.Fatalf("OpenTPM failed with err: %v", err)
	}
	defer rw.Close()

	// this should write tpm event log to measurementLogSealSuccess file
	dataToSeal := []byte("secret")
	if err := SealDiskKey(log, dataToSeal, DiskKeySealingPCRs); err != nil {
		t.Fatalf("Seal operation failed with err: %v", err)
	}

	// this should cause UnsealDiskKey to fail
	pcrValue := bytes.Repeat([]byte{0xF}, sha256.Size)
	if err = tpm2.PCRExtend(rw, tpmutil.Handle(1), tpm2.AlgSHA256, pcrValue, ""); err != nil {
		t.Fatalf("Failed to extend PCR[1]: %v", err)
	}

	// this should fail and result in saving creating measurementLogUnsealFail
	_, err = UnsealDiskKey(DiskKeySealingPCRs)
	if err == nil {
		t.Fatalf("Expected error from UnsealDiskKey, got nil")
	}

	if !fileutils.FileExists(nil, measurementLogSealSuccess) {
		t.Fatalf("TPM measurement log \"%s\" not found, expected to exist", measurementLogSealSuccess)
	}
	if !fileutils.FileExists(nil, measurementLogUnsealFail) {
		t.Fatalf("TPM measurement log \"%s\" not found, expected to exist", measurementLogUnsealFail)
	}

	// this should trigger backing up previously saved tpm event logs
	if err := SealDiskKey(log, dataToSeal, DiskKeySealingPCRs); err != nil {
		t.Fatalf("Seal operation failed with err: %v", err)
	}

	// a new measurementLogSealSuccess file should exist
	if !fileutils.FileExists(nil, measurementLogSealSuccess) {
		t.Fatalf("TPM measurement log \"%s\" not found, Expected to be copied", measurementLogSealSuccess)
	}

	// measurementLogUnsealFail file shouldn't exist because SealDiskKey
	// will do a clean up.
	if fileutils.FileExists(nil, measurementLogUnsealFail) {
		t.Fatalf("TPM measurement log \"%s\" found, Expected to not exist", measurementLogUnsealFail)
	}

	// backed up measurement logs both should exist
	prevSealSuccess := fmt.Sprintf("%s-backup", measurementLogSealSuccess)
	prevSealFail := fmt.Sprintf("%s-backup", measurementLogUnsealFail)
	if !fileutils.FileExists(nil, prevSealSuccess) {
		t.Fatalf("TPM measurement log \"%s\" not found, Expected to be backed up", prevSealSuccess)
	}
	if !fileutils.FileExists(nil, prevSealFail) {
		t.Fatalf("TPM measurement log \"%s\" not found, Expected to be backed up", prevSealFail)
	}
}
