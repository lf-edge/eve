// Copyright (c) 2020-2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// unit-tests for evetpm package
package evetpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
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

var logger = base.NewSourceLogObject(logrus.StandardLogger(), "evetpm", os.Getpid())

func TestMain(m *testing.M) {
	logger.Tracef("Setup test environment")

	// setup variables
	TpmDevicePath = SimTpmPath
	types.TpmMeasurementLogFile = "/tmp/eve-tpm/binary_bios_measurement"
	types.TpmMeasurefsEventLog = "/tmp/eve-tpm/measurefs_tpm_event_log"
	savedSealingPcrsFile = "/tmp/eve-tpm/sealingpcrs"
	measurementLogSealSuccess = "/tmp/eve-tpm/tpm_measurement_seal_success"
	measurementLogUnsealFail = "/tmp/eve-tpm/tpm_measurement_unseal_fail"

	if !SimTpmAvailable() {
		logger.Warnf("TPM is not available, skipping the test.")
		os.Exit(0)
	}

	// for some reason TPM might return RCRetry for the first
	// few operations, so we need to wait for it to become ready.
	if err := SimTpmWaitForTpmReadyState(); err != nil {
		logger.Fatalf("Failed to wait for TPM ready state: %v", err)
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
	if err := SealDiskKey(logger, dataToSeal, DefaultDiskKeySealingPCRs); err != nil {
		t.Fatalf("Seal operation failed with err: %v", err)
	}

	unsealedData, err := UnsealDiskKey(DefaultDiskKeySealingPCRs)
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
	if err := SealDiskKey(logger, dataToSeal, DefaultDiskKeySealingPCRs); err != nil {
		t.Fatalf("Seal operation failed with err: %v", err)
	}

	pcrIndexes := [3]int{1, 7, 8}
	pcrValue := bytes.Repeat([]byte{0xF}, sha256.Size)
	for _, pcr := range pcrIndexes {
		if err = tpm2.PCRExtend(rw, tpmutil.Handle(pcr), tpm2.AlgSHA256, pcrValue, ""); err != nil {
			t.Fatalf("Failed to extend PCR %d: %s", pcr, err)
		}
	}

	_, err = UnsealDiskKey(DefaultDiskKeySealingPCRs)
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

	// this should write tpm event log to measurementLogSealSuccess file
	dataToSeal := []byte("secret")
	if err := SealDiskKey(logger, dataToSeal, DefaultDiskKeySealingPCRs); err != nil {
		t.Fatalf("Seal operation failed with err: %v", err)
	}

	// this should cause UnsealDiskKey to fail
	pcrValue := bytes.Repeat([]byte{0xF}, sha256.Size)
	if err = tpm2.PCRExtend(rw, tpmutil.Handle(1), tpm2.AlgSHA256, pcrValue, ""); err != nil {
		t.Fatalf("Failed to extend PCR[1]: %v", err)
	}

	// this should fail and result in saving creating measurementLogUnsealFail
	_, err = UnsealDiskKey(DefaultDiskKeySealingPCRs)
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
	if err := SealDiskKey(logger, dataToSeal, DefaultDiskKeySealingPCRs); err != nil {
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
		policy        types.VaultKeyPolicyPCR
		expectChanged bool
		expectError   bool
	}{
		{
			name: "valid policy with default PCRs",
			policy: types.VaultKeyPolicyPCR{
				Indexes: []int{0, 1, 2, 3, 4, 6, 7, 8, 9, 13, 14},
				ID:      1,
			},
			expectChanged: true,
			expectError:   false,
		},
		{
			name: "minimal policy with PCR 0 only",
			policy: types.VaultKeyPolicyPCR{
				Indexes: []int{0},
				ID:      2,
			},
			expectChanged: true,
			expectError:   false,
		},
		{
			name: "policy with PCR 0 and upper range PCRs",
			policy: types.VaultKeyPolicyPCR{
				Indexes: []int{0, 10, 11, 12, 13, 14, 15},
				ID:      3,
			},
			expectChanged: true,
			expectError:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			changed, err := SaveDiskKeyPolicyPcr(tc.policy, testPcrPolicyFile)

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
		policy types.VaultKeyPolicyPCR
	}{
		{
			name: "empty PCR list",
			policy: types.VaultKeyPolicyPCR{
				Indexes: []int{},
				ID:      1,
			},
		},
		{
			name: "missing PCR 0",
			policy: types.VaultKeyPolicyPCR{
				Indexes: []int{1, 2, 3},
				ID:      2,
			},
		},
		{
			name: "duplicate PCR indexes",
			policy: types.VaultKeyPolicyPCR{
				Indexes: []int{0, 1, 2, 2, 3},
				ID:      3,
			},
		},
		{
			name: "negative PCR index",
			policy: types.VaultKeyPolicyPCR{
				Indexes: []int{0, -1, 2},
				ID:      4,
			},
		},
		{
			name: "PCR index out of range (>15)",
			policy: types.VaultKeyPolicyPCR{
				Indexes: []int{0, 1, 20},
				ID:      5,
			},
		},
		{
			name: "PCR 5 (volatile GPT/boot manager)",
			policy: types.VaultKeyPolicyPCR{
				Indexes: []int{0, 1, 5, 7},
				ID:      6,
			},
		},
		{
			name: "PCR 16 (debug PCR)",
			policy: types.VaultKeyPolicyPCR{
				Indexes: []int{0, 1, 16},
				ID:      7,
			},
		},
		{
			name: "PCR 17 (DTRM)",
			policy: types.VaultKeyPolicyPCR{
				Indexes: []int{0, 1, 17},
				ID:      8,
			},
		},
		{
			name: "PCR 23 (DTRM)",
			policy: types.VaultKeyPolicyPCR{
				Indexes: []int{0, 1, 23},
				ID:      9,
			},
		},
		{
			name: "too many PCRs",
			policy: types.VaultKeyPolicyPCR{
				Indexes: []int{0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 2},
				ID:      10,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SaveDiskKeyPolicyPcr(tc.policy, testPcrPolicyFile)

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

	policy := types.VaultKeyPolicyPCR{
		Indexes: []int{0, 1, 2, 3, 7},
		ID:      100,
	}

	// Save policy first time
	changed1, err := SaveDiskKeyPolicyPcr(policy, testPcrPolicyFile)
	if err != nil {
		t.Fatalf("First save failed: %v", err)
	}
	if !changed1 {
		t.Errorf("Expected policy to be changed on first save")
	}

	// Save same policy again
	changed2, err := SaveDiskKeyPolicyPcr(policy, testPcrPolicyFile)
	if err != nil {
		t.Fatalf("Second save failed: %v", err)
	}
	if changed2 {
		t.Errorf("Expected policy to be unchanged on second save with same data")
	}

	// Save different policy
	policy2 := types.VaultKeyPolicyPCR{
		Indexes: []int{0, 1, 2, 3, 8},
		ID:      100,
	}
	changed3, err := SaveDiskKeyPolicyPcr(policy2, testPcrPolicyFile)
	if err != nil {
		t.Fatalf("Third save failed: %v", err)
	}
	if !changed3 {
		t.Errorf("Expected policy to be changed when PCRs differ")
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
	customPolicy := types.VaultKeyPolicyPCR{
		Indexes: []int{0, 2, 4, 7, 9},
		ID:      42,
	}
	_, err := SaveDiskKeyPolicyPcr(customPolicy, testPcrPolicyFile)
	if err != nil {
		t.Fatalf("Failed to save custom policy: %v", err)
	}

	// Retrieve it
	pcrSel := GetDiskKeyPolicyPcrOrDefault(testPcrPolicyFile)

	if !reflect.DeepEqual(pcrSel.PCRs, customPolicy.Indexes) {
		t.Errorf("Expected custom PCRs %v, got %v", customPolicy.Indexes, pcrSel.PCRs)
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
	pcrSel := GetDiskKeyPolicyPcrOrDefault(testPcrPolicyFile)

	if !reflect.DeepEqual(pcrSel.PCRs, DefaultDiskKeySealingPCRs.PCRs) {
		t.Errorf("Expected default PCRs on corrupted file, got %v", pcrSel.PCRs)
	}
}

func TestComputePolicyPCRAuthDigest(t *testing.T) {
	fromHex := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("failed to decode hex %q: %v", s, err)
		}
		return b
	}

	pcrValues := map[int][]byte{
		0:  fromHex("5619430cb549255eb944f6956c5e7d0c11a47264b946c337ff1b9e81be44307a"),
		1:  fromHex("9d67a4555e8819f0027bf842144b11fe262e51daa024127454c535695ca6d1c8"),
		2:  fromHex("1354f05191d8f84a82bac927c4d3f2be9c45d26f54b2e7f944983fc9fa37d274"),
		3:  fromHex("5949b9fdb9a1eb56d7d3ab9246e0aabfea539d8b908d6975c68b29b20b54dc02"),
		4:  fromHex("da8be6f328d3266412d163119bedb0af36c4c623843d07158184e843edb6f6e7"),
		5:  fromHex("a1c51aa3fe4eade529ae8bfd52933ee7ed19eadb3c91e4e6837004f136f20b1f"),
		6:  fromHex("a86d0042900a791b00e873d4198a826c6db5986909ce5d1e54faa2975e38c207"),
		7:  fromHex("70a6a9ab9369798e862dcc97fa40c14b82da9b6ad55035a7377a09ca8f66517a"),
		8:  fromHex("899fc5970745180046a9cc648f9c50d2850688240deef0f3979036d06fe9d67e"),
		9:  fromHex("94630cd2cc6685797c0333873060b72a5a8396bbc94701f6e486786b72554d7d"),
		10: fromHex("0dc8541532673ef24307be91567b9a417f83466d8e39e02a32508ca611975fb4"),
		11: fromHex("5b52ccb39c4a08cd63fe4e84472de87a4555e38de3c3b3125562a0f0b1eb8ea1"),
		12: fromHex("4cb6dfa4c8ac2a6aaf752dcade4ac4bc1a714d76de42a17a07377db7be50d4b0"),
		13: fromHex("7480ecb57430813904a28f6ba239a5cdfaa77ba7f43b252dbdadf3304d939182"),
		14: fromHex("12aeb9ea2640c6ee70637dc73b1a4720546aed216103d5456cbd14438e6ea683"),
		15: fromHex("7ca6ece90c02b04cc11508f204558a8b2b171271cdf8c15ffeb0ea17fa8b64c0"),
		16: fromHex("d085442c11a3d1eff014d56859140f9ff9f4a609d33bdaf72fd00a5593b4b573"),
		17: bytes.Repeat([]byte{0xff}, 32),
		18: bytes.Repeat([]byte{0xff}, 32),
		19: bytes.Repeat([]byte{0xff}, 32),
		20: bytes.Repeat([]byte{0xff}, 32),
		21: bytes.Repeat([]byte{0xff}, 32),
		22: bytes.Repeat([]byte{0xff}, 32),
		23: bytes.Repeat([]byte{0x00}, 32),
	}

	scenarios := []struct {
		name           string
		indices        []int
		expectedDigest string
	}{
		{
			name:           "Scenario 1: PCRs [0]",
			indices:        []int{0},
			expectedDigest: "924ea886222d06270b639b0b1f3a034dba58f7f4bc9d2e110391832d524dcaf1",
		},
		{
			name:           "Scenario 2: PCRs [7]",
			indices:        []int{7},
			expectedDigest: "883510a0211286f571c65e26e884aa786f3427a1a6009cb67c16be094bdb71d9",
		},
		{
			name:           "Scenario 3: PCRs [0 7]",
			indices:        []int{0, 7},
			expectedDigest: "8c07b5510a2444e166e3f39706a2156f50e788250dde71f46c50ed1dd4e080a1",
		},
		{
			name:           "Scenario 4: PCRs [0 7 14]",
			indices:        []int{0, 7, 14},
			expectedDigest: "1461fd66a64b5bf22ba94477072fb6a3f1635aa7c1447bdda53ff892c50b9d7f",
		},
		{
			name:           "Scenario 5: PCRs [1 2 3 4 5]",
			indices:        []int{1, 2, 3, 4, 5},
			expectedDigest: "fad57978340c84625fabf9387e6701bba92f13c8e8827fe6b346d18d1c3cb90d",
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			computed, err := computePolicyPCRAuthDigest(pcrValues, sc.indices)
			if err != nil {
				t.Fatalf("computePolicyPCRAuthDigest failed: %v", err)
			}

			computedHex := hex.EncodeToString(computed)
			if computedHex != sc.expectedDigest {
				t.Errorf("Mismatch in digest:\nWant: %s\nGot : %s", sc.expectedDigest, computedHex)
			}
		})
	}
}
