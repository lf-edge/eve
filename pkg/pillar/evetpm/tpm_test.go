// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// unit-tests for evetpm

package evetpm

import (
	"bytes"
	"crypto/sha256"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/pkg/pillar/base"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/sirupsen/logrus"
)

var log = base.NewSourceLogObject(logrus.StandardLogger(), "test", 1234)

func TestSealUnseal(t *testing.T) {
	_, err := os.Stat(TpmDevicePath)
	if err != nil {
		t.Skip("TPM is not available, skipping the test.")
	}

	dataToSeal := []byte("secret")
	if err := SealDiskKey(log, dataToSeal, DiskKeySealingPCRs); err != nil {
		t.Errorf("Seal operation failed with err: %v", err)
		return
	}
	unsealedData, err := UnsealDiskKey(DiskKeySealingPCRs)
	if err != nil {
		t.Errorf("Unseal operation failed with err: %v", err)
		return
	}
	if !reflect.DeepEqual(dataToSeal, unsealedData) {
		t.Errorf("Seal/Unseal operation failed, want %v, but got %v", dataToSeal, unsealedData)
	}
}

func TestSealUnsealMismatchReport(t *testing.T) {
	_, err := os.Stat(TpmDevicePath)
	if err != nil {
		t.Skip("TPM is not available, skipping the test.")
	}

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		t.Errorf("OpenTPM failed with err: %v", err)
		return
	}
	defer rw.Close()

	dataToSeal := []byte("secret")
	if err := SealDiskKey(log, dataToSeal, DiskKeySealingPCRs); err != nil {
		t.Errorf("Seal operation failed with err: %v", err)
		return
	}

	pcrIndexes := [3]int{1, 7, 8}
	pcrValue := bytes.Repeat([]byte{0xF}, sha256.Size)
	for _, pcr := range pcrIndexes {
		if err = tpm2.PCRExtend(rw, tpmutil.Handle(pcr), tpm2.AlgSHA256, pcrValue, ""); err != nil {
			t.Errorf("Failed to extend PCR %d: %s", pcr, err)
			return
		}
	}

	_, err = UnsealDiskKey(DiskKeySealingPCRs)
	if err == nil {
		t.Errorf("Expected error from UnsealDiskKey, got nil")
		return
	}

	if !strings.Contains(err.Error(), "[1 7 8]") {
		t.Errorf("UnsealDiskKey expected to report mismatching PCR indexes, got : %v", err)
		return
	}
}

func TestSealUnsealTpmEventLogCollect(t *testing.T) {
	_, err := os.Stat(TpmDevicePath)
	if err != nil {
		t.Skip("TPM is not available, skipping the test.")
	}

	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		t.Errorf("OpenTPM failed with err: %v", err)
		return
	}
	defer rw.Close()

	// this should write the save the first event log
	dataToSeal := []byte("secret")
	if err := SealDiskKey(log, dataToSeal, DiskKeySealingPCRs); err != nil {
		t.Errorf("Seal operation failed with err: %v", err)
		return
	}

	// this won't write to event log, but still triggers saving it on unseal.
	pcrValue := bytes.Repeat([]byte{0xF}, sha256.Size)
	if err = tpm2.PCRExtend(rw, tpmutil.Handle(1), tpm2.AlgSHA256, pcrValue, ""); err != nil {
		t.Errorf("Failed to extend PCR[1]: %v", err)
		return
	}

	// this should fail and result in saving the second tpm event log
	_, err = UnsealDiskKey(DiskKeySealingPCRs)
	if err == nil {
		t.Errorf("Expected error from UnsealDiskKey, got nil")
		return
	}

	// just check for tpm0
	sealSuccess := getLogCopyPath(measurementLogSealSuccess, 0)
	sealFail := getLogCopyPath(measurementLogUnsealFail, 0)
	if !fileutils.FileExists(nil, sealSuccess) {
		t.Errorf("TPM measurement log \"%s\" not found, Expected to be copied", sealSuccess)
		return
	}
	if !fileutils.FileExists(nil, sealFail) {
		t.Errorf("TPM measurement log \"%s\" not found, Expected to be copied", sealFail)
		return
	}

	// this should trigger collecting previous tpm event logs
	if err := SealDiskKey(log, dataToSeal, DiskKeySealingPCRs); err != nil {
		t.Errorf("Seal operation failed with err: %v", err)
		return
	}

	// current measurement log should exist
	if !fileutils.FileExists(nil, sealSuccess) {
		t.Errorf("TPM measurement log \"%s\" not found, Expected to be copied", sealSuccess)
		return
	}
	// this shouldn't exist because SealDiskKey will do a clean up
	if fileutils.FileExists(nil, sealFail) {
		t.Errorf("TPM measurement log \"%s\" found, Expected to not exist", sealFail)
		return
	}

	// backed up measurement logs both should exist
	prevSealSuccess := getLogBackupPath(sealSuccess)
	prevSealFail := getLogBackupPath(sealFail)
	if !fileutils.FileExists(nil, prevSealSuccess) {
		t.Errorf("TPM measurement log \"%s\" not found, Expected to be backed up", prevSealSuccess)
		return
	}
	if !fileutils.FileExists(nil, prevSealFail) {
		t.Errorf("TPM measurement log \"%s\" not found, Expected to be backed up", prevSealFail)
		return
	}
}
