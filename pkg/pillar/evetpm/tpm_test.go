// Copyright (c) 2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// unit-tests for evetpm

package evetpm

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	tpmea "github.com/lf-edge/eve-tpmea"
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
	unsealedData, err := UnsealDiskKey(log, DiskKeySealingPCRs)
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

	_, err = UnsealDiskKey(log, DiskKeySealingPCRs)
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
	_, err = UnsealDiskKey(log, DiskKeySealingPCRs)
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

func readPCRs(pcrs []int) ([]tpmea.PCR, error) {
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		return nil, err
	}
	defer rw.Close()

	list := make([]tpmea.PCR, 0)
	for _, pcr := range pcrs {
		val, _ := tpm2.ReadPCR(rw, pcr, tpm2.AlgSHA256)
		list = append(list, tpmea.PCR{Index: pcr, Digest: val})
	}

	return list, nil
}

func TestEnhancedAuthConfigReadWrite(t *testing.T) {
	_, err := os.Stat(TpmDevicePath)
	if err != nil {
		t.Skip("TPM is not available, skipping the test.")
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	authorizationDigest, err := tpmea.GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// create a policy using some of the PCRs
	pcrs, err := readPCRs(DiskKeySealingPCRs.PCRs)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}
	pcrsList := tpmea.PCRList{Algo: tpmea.AlgoSHA256, Pcrs: pcrs}

	// sign the policy
	policy, policySig, err := tpmea.GenerateSignedPolicy(key, pcrsList, tpmea.RBP{})
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	var config EnhancedAuthConfig
	config.AuthDigest = authorizationDigest
	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	config.AuthPublicKey = pemEncodedPub

	config.Policy = make([]EnhancedAuthPolicy, 0)
	config.Policy = append(config.Policy, EnhancedAuthPolicy{
		Policy:    policy,
		PolicySig: *policySig})

	content, _ := json.Marshal(config)

	// marshal and dump it to a file
	fileutils.WriteRename("/tmp/tpm_policy.json", content)
	defer os.Remove("/tmp/tpm_policy.json")

	// read the config again from a file
	readConfig, err := readEnhancedAuthConfig("/tmp/tpm_policy.json")
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if !bytes.Equal(readConfig.AuthDigest, config.AuthDigest) {
		t.Fatalf("Expected read AuthDigest to be equal to config AuthDigest")
	}

	if !bytes.Equal(readConfig.AuthPublicKey, pemEncodedPub) {
		t.Fatalf("Expected read AuthPublicKey to be equal to config AuthPublicKey")
	}

	if len(readConfig.Policy) != len(config.Policy) {
		t.Fatalf("Expected len of read Policy to be equal to len of config Policy")
	}

	// json doesn't guarantee order, but this should be fine
	for i := 0; i < len(readConfig.Policy); i++ {
		if !bytes.Equal(readConfig.Policy[i].Policy, config.Policy[i].Policy) {
			t.Fatalf("Expected read Policy to be equal to config Policy")
		}
	}

	for i := 0; i < len(readConfig.Policy); i++ {
		if !bytes.Equal(readConfig.Policy[i].PolicySig.RSASignature, config.Policy[i].PolicySig.RSASignature) {
			t.Fatalf("Expected read RSASignature to be equal to config RSASignature")
		}

		if !bytes.Equal(readConfig.Policy[i].PolicySig.ECCSignatureR, config.Policy[i].PolicySig.ECCSignatureR) {
			t.Fatalf("Expected read ECCSignatureR to be equal to config ECCSignatureR")
		}

		if !bytes.Equal(readConfig.Policy[i].PolicySig.ECCSignatureS, config.Policy[i].PolicySig.ECCSignatureS) {
			t.Fatalf("Expected read ECCSignatureS to be equal to config ECCSignatureS")
		}
	}
}

func TestSealUnsealWithEnhancedAuth(t *testing.T) {
	_, err := os.Stat(TpmDevicePath)
	if err != nil {
		t.Skip("TPM is not available, skipping the test.")
	}

	configDir := "/tmp/tpmpolicy"
	configFile := filepath.Join(configDir, "tpm_policy.json")
	secretTpmKey := []byte("THIS IS THE SECRET")
	os.MkdirAll(configDir, 0755)
	defer os.RemoveAll(configDir)

	// gen a random key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)

	// create a monotonic counter in TPM
	_, err = tpmea.DefineMonotonicCounter(TpmPolicyCounterIndex)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// generate the authorization digest
	authorizationDigest, err := tpmea.GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// create a policy using static list of PCRs and rbp value
	pcrs, err := readPCRs(DiskKeySealingPCRs.PCRs)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}
	pcrsList := tpmea.PCRList{Algo: tpmea.AlgoSHA256, Pcrs: pcrs}
	rbp := tpmea.RBP{Counter: TpmPolicyCounterIndex, Check: RollbackCounter}

	// sign the policy
	policy, policySig, err := tpmea.GenerateSignedPolicy(key, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// marshal and dump the tpm policy config to a file
	var config EnhancedAuthConfig
	config.AuthDigest = authorizationDigest
	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	config.AuthPublicKey = pemEncodedPub
	config.Policy = make([]EnhancedAuthPolicy, 0)
	config.Policy = append(config.Policy, EnhancedAuthPolicy{
		Policy:    policy,
		PolicySig: *policySig})
	content, _ := json.Marshal(config)
	fileutils.WriteRename(configFile, content)

	// seal a secret
	err = SealDiskKeyWithEnhancedAuth(log, configFile, secretTpmKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// find and load the current policy
	path, err := FindCurrentTpmPolicy(configDir)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// unseal the secret
	secret, err := UnsealDiskKeyWithEnhancedAuth(log, path)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if !bytes.Equal(secret, secretTpmKey) {
		t.Fatalf("Expected secret to be \"%v\", got \"%v\"", secretTpmKey, secret)
	}

	// extend a PCR make the previous policy invalid
	rw, err := tpm2.OpenTPM(TpmDevicePath)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}
	defer rw.Close()

	pcrValue := bytes.Repeat([]byte{0xF}, sha256.Size)
	if err = tpm2.PCRExtend(rw, tpmutil.Handle(0), tpm2.AlgSHA256, pcrValue, ""); err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// try to unseal the secret again, this should fail
	_, err = UnsealDiskKeyWithEnhancedAuth(log, path)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}

	// update the policy with a new set of PCR values
	pcrs, err = readPCRs(DiskKeySealingPCRs.PCRs)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}
	pcrsList = tpmea.PCRList{Algo: tpmea.AlgoSHA256, Pcrs: pcrs}
	rbp = tpmea.RBP{Counter: TpmPolicyCounterIndex, Check: RollbackCounter}

	// sign the new policy
	policy, policySig, err = tpmea.GenerateSignedPolicy(key, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	config.Policy = append(config.Policy, EnhancedAuthPolicy{
		Policy:    policy,
		PolicySig: *policySig})
	content, _ = json.Marshal(config)
	fileutils.WriteRename(configFile, content)

	// try to unseal again, this should succeed
	secret, err = UnsealDiskKeyWithEnhancedAuth(log, path)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if !bytes.Equal(secret, secretTpmKey) {
		t.Fatalf("Expected secret to be \"%v\", got \"%v\"", secretTpmKey, secret)
	}
}

func TestEnhancedAuthKeyRotation(t *testing.T) {
	_, err := os.Stat(TpmDevicePath)
	if err != nil {
		t.Skip("TPM is not available, skipping the test.")
	}

	configDir := "/tmp/tpmpolicy"
	configFileOld := filepath.Join(configDir, "tpm_policy_old.json")
	configFileNew := filepath.Join(configDir, "tpm_policy_new.json")
	secretTpmKey := []byte("THIS IS THE SECRET")
	os.MkdirAll(configDir, 0755)
	defer os.RemoveAll(configDir)

	// gen a random key
	key, _ := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)

	// create a monotonic counter in TPM
	_, err = tpmea.DefineMonotonicCounter(TpmPolicyCounterIndex)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// generate the authorization digest
	authorizationDigest, err := tpmea.GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// create a policy using static list of PCRs and rbp value
	pcrs, err := readPCRs(DiskKeySealingPCRs.PCRs)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}
	pcrsList := tpmea.PCRList{Algo: tpmea.AlgoSHA256, Pcrs: pcrs}
	rbp := tpmea.RBP{Counter: TpmPolicyCounterIndex, Check: RollbackCounter}

	// sign the policy
	policy, policySig, err := tpmea.GenerateSignedPolicy(key, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// marshal and dump the tpm policy config to a file
	var oldConfig EnhancedAuthConfig
	oldConfig.AuthDigest = authorizationDigest
	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	oldConfig.AuthPublicKey = pemEncodedPub
	oldConfig.Policy = make([]EnhancedAuthPolicy, 0)
	oldConfig.Policy = append(oldConfig.Policy, EnhancedAuthPolicy{
		Policy:    policy,
		PolicySig: *policySig})
	content, _ := json.Marshal(oldConfig)
	fileutils.WriteRename(configFileOld, content)

	// seal a secret
	err = SealDiskKeyWithEnhancedAuth(log, configFileOld, secretTpmKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// gen another random key
	key, _ = ecdsa.GenerateKey(elliptic.P256(), crand.Reader)

	// generate a new authorization digest
	authorizationDigest, err = tpmea.GenerateAuthDigest(&key.PublicKey)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// sign the policy using the new key
	policy, policySig, err = tpmea.GenerateSignedPolicy(key, pcrsList, rbp)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// marshal and dump the new tpm policy config to a file
	var newConfig EnhancedAuthConfig
	newConfig.AuthDigest = authorizationDigest
	x509EncodedPub, _ = x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemEncodedPub = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	newConfig.AuthPublicKey = pemEncodedPub
	newConfig.Policy = make([]EnhancedAuthPolicy, 0)
	newConfig.Policy = append(newConfig.Policy, EnhancedAuthPolicy{
		Policy:    policy,
		PolicySig: *policySig})
	content, _ = json.Marshal(newConfig)
	fileutils.WriteRename(configFileNew, content)

	// rotate the key (auth digest)
	err = RotateEnhancedAuthPublicKey(log, configFileOld, configFileNew)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	// find and load the current policy, this should be the new policy
	path, err := FindCurrentTpmPolicy(configDir)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if path != configFileNew {
		t.Fatalf("Expected path to be \"%v\", got \"%v\"", configFileNew, path)
	}

	// unseal the secret
	secret, err := UnsealDiskKeyWithEnhancedAuth(log, path)
	if err != nil {
		t.Fatalf("Expected no error, got  \"%v\"", err)
	}

	if !bytes.Equal(secret, secretTpmKey) {
		t.Fatalf("Expected secret to be \"%v\", got \"%v\"", secretTpmKey, secret)
	}
}
