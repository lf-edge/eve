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
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	fileutils "github.com/lf-edge/eve/pkg/pillar/utils/file"
	"github.com/sirupsen/logrus"
)

var log = base.NewSourceLogObject(logrus.StandardLogger(), "evetpm", os.Getpid())

func TestMain(m *testing.M) {
	log.Tracef("Setup test environment")

	// setup variables
	TpmDevicePath = SimTpmPath
	types.TpmMeasurementLogFile = "/tmp/eve-tpm/binary_bios_measurement"
	types.TpmMeasurefsEventLog = "/tmp/eve-tpm/measurefs_tpm_event_log"
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

	// Get PCR selection used for sealing/unsealing
	pcrSelection := GetDiskKeySealingPCRs(nil, PcrPolicyIndexesFile)

	dataToSeal := []byte("secret")
	if err := SealDiskKey(log, dataToSeal, pcrSelection); err != nil {
		t.Fatalf("Seal operation failed with err: %v", err)
	}

	unsealedData, err := UnsealDiskKey(pcrSelection)
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

	// Get PCR selection used for sealing/unsealing
	pcrSelection := GetDiskKeySealingPCRs(nil, PcrPolicyIndexesFile)

	dataToSeal := []byte("secret")
	if err := SealDiskKey(log, dataToSeal, pcrSelection); err != nil {
		t.Fatalf("Seal operation failed with err: %v", err)
	}

	pcrIndexes := [3]int{1, 7, 8}
	pcrValue := bytes.Repeat([]byte{0xF}, sha256.Size)
	for _, pcr := range pcrIndexes {
		if err = tpm2.PCRExtend(rw, tpmutil.Handle(pcr), tpm2.AlgSHA256, pcrValue, ""); err != nil {
			t.Fatalf("Failed to extend PCR %d: %s", pcr, err)
		}
	}

	_, err = UnsealDiskKey(pcrSelection)
	if err == nil {
		t.Fatalf("Expected error from UnsealDiskKey, got nil")
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

	// Get PCR selection used for sealing/unsealing
	pcrSelection := GetDiskKeySealingPCRs(nil, PcrPolicyIndexesFile)

	// this should write tpm event log to measurementLogSealSuccess file
	dataToSeal := []byte("secret")
	if err := SealDiskKey(log, dataToSeal, pcrSelection); err != nil {
		t.Fatalf("Seal operation failed with err: %v", err)
	}

	// this should cause UnsealDiskKey to fail
	pcrValue := bytes.Repeat([]byte{0xF}, sha256.Size)
	if err = tpm2.PCRExtend(rw, tpmutil.Handle(1), tpm2.AlgSHA256, pcrValue, ""); err != nil {
		t.Fatalf("Failed to extend PCR[1]: %v", err)
	}

	// this should fail and result in saving creating measurementLogUnsealFail
	_, err = UnsealDiskKey(pcrSelection)
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
	if err := SealDiskKey(log, dataToSeal, pcrSelection); err != nil {
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

func TestSaveDiskKeySealingPCRsValidPolicy(t *testing.T) {
	// Use temporary paths for testing
	testPcrPolicyFile := "/tmp/eve-tpm/test_pcr_policy_indexes.json"
	testPcrPolicyHashFile := "/tmp/eve-tpm/test_pcr_policy_indexes.hash"

	// Clean up any existing policy files
	os.Remove(testPcrPolicyFile)
	os.Remove(testPcrPolicyHashFile)
	defer func() {
		os.Remove(testPcrPolicyFile)
		os.Remove(testPcrPolicyHashFile)
	}()

	testCases := []struct {
		name          string
		policy        SealingPcrPolicyIndexes
		expectChanged bool
		expectError   bool
	}{
		{
			name: "valid policy with default PCRs",
			policy: SealingPcrPolicyIndexes{
				Pcrs: []int{0, 1, 2, 3, 4, 6, 7, 8, 9, 13, 14},
				Id:   1,
			},
			expectChanged: true,
			expectError:   false,
		},
		{
			name: "minimal policy with PCR 0 only",
			policy: SealingPcrPolicyIndexes{
				Pcrs: []int{0},
				Id:   2,
			},
			expectChanged: true,
			expectError:   false,
		},
		{
			name: "policy with PCR 0 and upper range PCRs",
			policy: SealingPcrPolicyIndexes{
				Pcrs: []int{0, 10, 11, 12, 13, 14, 15},
				Id:   3,
			},
			expectChanged: true,
			expectError:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pcrSel, changed, err := SaveDiskKeySealingPCRs(tc.policy, testPcrPolicyFile, testPcrPolicyHashFile)

			if tc.expectError && err == nil {
				t.Fatalf("Expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !tc.expectError {
				if changed != tc.expectChanged {
					t.Errorf("Expected changed=%v, got %v", tc.expectChanged, changed)
				}
				if !reflect.DeepEqual(pcrSel.PCRs, tc.policy.Pcrs) {
					t.Errorf("Expected PCRs %v, got %v", tc.policy.Pcrs, pcrSel.PCRs)
				}
				if pcrSel.Hash != tpm2.AlgSHA256 {
					t.Errorf("Expected hash algorithm SHA256, got %v", pcrSel.Hash)
				}
			}
		})
	}
}

func TestSaveDiskKeySealingPCRsInvalidPolicy(t *testing.T) {
	// Use temporary paths for testing
	testPcrPolicyFile := "/tmp/eve-tpm/test_pcr_policy_indexes.json"
	testPcrPolicyHashFile := "/tmp/eve-tpm/test_pcr_policy_indexes.hash"

	// Clean up any existing policy files
	os.Remove(testPcrPolicyFile)
	os.Remove(testPcrPolicyHashFile)
	defer func() {
		os.Remove(testPcrPolicyFile)
		os.Remove(testPcrPolicyHashFile)
	}()

	testCases := []struct {
		name   string
		policy SealingPcrPolicyIndexes
	}{
		{
			name: "empty PCR list",
			policy: SealingPcrPolicyIndexes{
				Pcrs: []int{},
				Id:   1,
			},
		},
		{
			name: "missing PCR 0",
			policy: SealingPcrPolicyIndexes{
				Pcrs: []int{1, 2, 3},
				Id:   2,
			},
		},
		{
			name: "duplicate PCR indexes",
			policy: SealingPcrPolicyIndexes{
				Pcrs: []int{0, 1, 2, 2, 3},
				Id:   3,
			},
		},
		{
			name: "negative PCR index",
			policy: SealingPcrPolicyIndexes{
				Pcrs: []int{0, -1, 2},
				Id:   4,
			},
		},
		{
			name: "PCR index out of range (>15)",
			policy: SealingPcrPolicyIndexes{
				Pcrs: []int{0, 1, 20},
				Id:   5,
			},
		},
		{
			name: "PCR 5 (volatile GPT/boot manager)",
			policy: SealingPcrPolicyIndexes{
				Pcrs: []int{0, 1, 5, 7},
				Id:   6,
			},
		},
		{
			name: "PCR 16 (debug PCR)",
			policy: SealingPcrPolicyIndexes{
				Pcrs: []int{0, 1, 16},
				Id:   7,
			},
		},
		{
			name: "PCR 17 (DTRM)",
			policy: SealingPcrPolicyIndexes{
				Pcrs: []int{0, 1, 17},
				Id:   8,
			},
		},
		{
			name: "PCR 23 (DTRM)",
			policy: SealingPcrPolicyIndexes{
				Pcrs: []int{0, 1, 23},
				Id:   9,
			},
		},
		{
			name: "too many PCRs",
			policy: SealingPcrPolicyIndexes{
				Pcrs: []int{0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 2},
				Id:   10,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := SaveDiskKeySealingPCRs(tc.policy, testPcrPolicyFile, testPcrPolicyHashFile)

			if err == nil {
				t.Fatalf("Expected error but got none")
			}
		})
	}
}

func TestSaveDiskKeySealingPCRsPolicyUnchanged(t *testing.T) {
	// Use temporary paths for testing
	testPcrPolicyFile := "/tmp/eve-tpm/test_pcr_policy_indexes.json"
	testPcrPolicyHashFile := "/tmp/eve-tpm/test_pcr_policy_indexes.hash"

	// Clean up any existing policy files
	os.Remove(testPcrPolicyFile)
	os.Remove(testPcrPolicyHashFile)
	defer func() {
		os.Remove(testPcrPolicyFile)
		os.Remove(testPcrPolicyHashFile)
	}()

	policy := SealingPcrPolicyIndexes{
		Pcrs: []int{0, 1, 2, 3, 7},
		Id:   100,
	}

	// Save policy first time
	_, changed1, err := SaveDiskKeySealingPCRs(policy, testPcrPolicyFile, testPcrPolicyHashFile)
	if err != nil {
		t.Fatalf("First save failed: %v", err)
	}
	if !changed1 {
		t.Errorf("Expected policy to be changed on first save")
	}

	// Save same policy again
	_, changed2, err := SaveDiskKeySealingPCRs(policy, testPcrPolicyFile, testPcrPolicyHashFile)
	if err != nil {
		t.Fatalf("Second save failed: %v", err)
	}
	if changed2 {
		t.Errorf("Expected policy to be unchanged on second save with same data")
	}

	// Save different policy
	policy2 := SealingPcrPolicyIndexes{
		Pcrs: []int{0, 1, 2, 3, 8}, // Changed PCR
		Id:   100,
	}
	_, changed3, err := SaveDiskKeySealingPCRs(policy2, testPcrPolicyFile, testPcrPolicyHashFile)
	if err != nil {
		t.Fatalf("Third save failed: %v", err)
	}
	if !changed3 {
		t.Errorf("Expected policy to be changed when PCRs differ")
	}
}

func TestGetDiskKeySealingPCRsDefault(t *testing.T) {
	// Use temporary paths for testing
	testPcrPolicyFile := "/tmp/eve-tpm/test_pcr_policy_indexes.json"

	// Clean up any existing policy files
	os.Remove(testPcrPolicyFile)
	defer func() {
		os.Remove(testPcrPolicyFile)
	}()

	// When no policy file exists, should return default
	pcrSel := GetDiskKeySealingPCRs(nil, testPcrPolicyFile)

	if !reflect.DeepEqual(pcrSel.PCRs, DefaultDiskKeySealingPCRs.PCRs) {
		t.Errorf("Expected default PCRs %v, got %v", DefaultDiskKeySealingPCRs.PCRs, pcrSel.PCRs)
	}
	if pcrSel.Hash != tpm2.AlgSHA256 {
		t.Errorf("Expected hash algorithm SHA256, got %v", pcrSel.Hash)
	}
}

func TestGetDiskKeySealingPCRsFromFile(t *testing.T) {
	// Use temporary paths for testing
	testPcrPolicyFile := "/tmp/eve-tpm/test_pcr_policy_indexes.json"
	testPcrPolicyHashFile := "/tmp/eve-tpm/test_pcr_policy_indexes.hash"

	// Clean up any existing policy files
	os.Remove(testPcrPolicyFile)
	os.Remove(testPcrPolicyHashFile)
	defer func() {
		os.Remove(testPcrPolicyFile)
		os.Remove(testPcrPolicyHashFile)
	}()

	// Save a custom policy
	customPolicy := SealingPcrPolicyIndexes{
		Pcrs: []int{0, 2, 4, 7, 9},
		Id:   42,
	}
	_, _, err := SaveDiskKeySealingPCRs(customPolicy, testPcrPolicyFile, testPcrPolicyHashFile)
	if err != nil {
		t.Fatalf("Failed to save custom policy: %v", err)
	}

	// Retrieve it
	pcrSel := GetDiskKeySealingPCRs(nil, testPcrPolicyFile)

	if !reflect.DeepEqual(pcrSel.PCRs, customPolicy.Pcrs) {
		t.Errorf("Expected custom PCRs %v, got %v", customPolicy.Pcrs, pcrSel.PCRs)
	}
	if pcrSel.Hash != tpm2.AlgSHA256 {
		t.Errorf("Expected hash algorithm SHA256, got %v", pcrSel.Hash)
	}
}

func TestGetDiskKeySealingPCRsCorruptedFile(t *testing.T) {
	// Use temporary paths for testing
	testPcrPolicyFile := "/tmp/eve-tpm/test_pcr_policy_indexes.json"

	// Clean up any existing policy files
	os.Remove(testPcrPolicyFile)
	defer func() {
		os.Remove(testPcrPolicyFile)
	}()

	// Write corrupted JSON
	err := os.WriteFile(testPcrPolicyFile, []byte("not valid json{{{"), 0644)
	if err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	// Should fall back to default
	pcrSel := GetDiskKeySealingPCRs(nil, testPcrPolicyFile)

	if !reflect.DeepEqual(pcrSel.PCRs, DefaultDiskKeySealingPCRs.PCRs) {
		t.Errorf("Expected default PCRs on corrupted file, got %v", pcrSel.PCRs)
	}
}
