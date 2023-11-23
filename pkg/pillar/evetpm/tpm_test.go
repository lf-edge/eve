// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// unit-tests for evetpm

package evetpm

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/pkg/pillar/base"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/sirupsen/logrus"
)

var log = base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)

func TestMain(m *testing.M) {
	log.Tracef("Setup test environment")

	// setup variables
	TpmDevicePath = "/tmp/eve-tpm/srv.sock"
	measurementLogFile = "/tmp/eve-tpm/binary_bios_measurement"
	measurefsTpmEventLog = "/tmp/eve-tpm/measurefs_tpm_event_log"
	savedSealingPcrsFile = "/tmp/eve-tpm/sealingpcrs"
	measurementLogSealSuccess = "/tmp/eve-tpm/tpm_measurement_seal_success"
	measurementLogUnsealFail = "/tmp/eve-tpm/tpm_measurement_unseal_fail"

	// check if we are running under the correct context and we end up here
	// from tests/tpm/prep-and-test.sh.
	_, err := os.Stat(TpmDevicePath)
	if err != nil {
		log.Warnf("Neither TPM device nor swtpm is available, skipping the test.")
		return
	}

	// for some reason unknown to me, TPM might return RCRetry for the first
	// few operations, so we need to wait for it to become ready.
	if err := waitForTpmReadyState(); err != nil {
		log.Fatalf("Failed to wait for TPM ready state: %v", err)
	}

	m.Run()
}

func waitForTpmReadyState() error {
	for i := 0; i < 10; i++ {
		if err := SealDiskKey(log, []byte("secret"), DiskKeySealingPCRs); err != nil {
			// this is RCRetry, so retry
			if strings.Contains(err.Error(), "code 0x22") {
				time.Sleep(100 * time.Millisecond)
				continue
			} else {
				return fmt.Errorf("Something is wrong with the TPM : %w", err)
			}
		} else {
			return nil
		}
	}

	return fmt.Errorf("TPM did't become ready after 10 attempts, failing the test")
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
